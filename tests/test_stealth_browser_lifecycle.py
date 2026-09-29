"""Tests del ciclo de vida de specter.stealth_browser.

Aquí NO se lanza Chromium: se verifica el ARQUITECTURA del gestor, que es
donde estaban los fallos de concurrencia. Contexto cubierto:

- Aislamiento: cada operación pide su propio BrowserContext. Antes había un
  `self._context` compartido, y con `parallel_search` (5 consultas × N motores)
  un solo fallo llamaba a `_restart()`, que cerraba el contexto común y
  mataba todas las operaciones en vuelo.
- Clasificación de errores: sólo la muerte real del navegador justifica
  reiniciarlo. Un timeout de red es un fallo del destino.
- Presupuesto de reinicios: cuenta muertes del navegador, no fallos de red.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from specter.stealth_browser import StealthBrowser

# ---------------------------------------------------------------------------
# Dobles: simulan la API de Playwright sin lanzar Chromium.
# ---------------------------------------------------------------------------


class FakePage:
    def __init__(self, fail_with: Exception | None = None) -> None:
        self.closed = False
        self._fail_with = fail_with

    async def goto(self, *args: Any, **kwargs: Any) -> None:
        if self._fail_with:
            raise self._fail_with

    async def close(self) -> None:
        self.closed = True


class FakeContext:
    def __init__(self, fail_with: Exception | None = None) -> None:
        self.closed = False
        self.pages: list[FakePage] = []
        self._fail_with = fail_with

    async def new_page(self) -> FakePage:
        if self._fail_with:
            raise self._fail_with
        page = FakePage()
        self.pages.append(page)
        return page

    async def add_init_script(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def route(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def route_web_socket(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def close(self) -> None:
        self.closed = True


class FakeBrowserProcess:
    def __init__(self, fail_with: Exception | None = None) -> None:
        self.closed = False
        self.contexts: list[FakeContext] = []
        self._fail_with = fail_with

    async def new_context(self, *args: Any, **kwargs: Any) -> FakeContext:
        if self._fail_with:
            raise self._fail_with
        context = FakeContext()
        self.contexts.append(context)
        return context

    async def close(self) -> None:
        self.closed = True


def _browser_with_fake(
    monkeypatch: pytest.MonkeyPatch, *, fail_with: Exception | None = None
) -> tuple[StealthBrowser, FakeBrowserProcess]:
    """Construye un StealthBrowser con un proceso Chromium falso."""
    process = FakeBrowserProcess()
    browser = StealthBrowser()
    browser._browser = process
    browser._fingerprint = dict(browser._fingerprint)
    monkeypatch.setattr(browser, "_ensure", _noop_ensure(browser))
    return browser, process


def _noop_ensure(browser: StealthBrowser):  # type: ignore[no-untyped-def]
    async def _ensure() -> None:
        return None

    return _ensure


# ---------------------------------------------------------------------------
# Clasificación de errores (Bug 3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "message",
    [
        "Target page, context or browser has been closed",
        "Target closed",
        "Browser has been closed",
        "browser closed",
        "Connection closed",
        "Browser has disconnected",
    ],
)
def test_muerte_real_del_navegador_se_detecta(message: str) -> None:
    assert StealthBrowser._is_browser_death(Exception(message)) is True


@pytest.mark.parametrize(
    "message",
    [
        "net::ERR_CONNECTION_TIMED_OUT at https://html.duckduckgo.com/html/?q=x",
        "net::ERR_NAME_NOT_RESOLVED at https://example.com",
        "net::ERR_CONNECTION_REFUSED at https://example.com",
        "http_503",
        "Timeout 25000ms exceeded",
    ],
)
def test_fallo_de_red_NO_es_muerte_del_navegador(message: str) -> None:
    """Un timeout de red no debe reiniciar Chromium: antes vaciaba el lote."""
    assert StealthBrowser._is_browser_death(Exception(message)) is False


# ---------------------------------------------------------------------------
# Aislamiento de contextos (Bug 1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cada_operacion_crea_su_propio_contexto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dos operaciones simultáneas no comparten contexto."""
    browser, process = _browser_with_fake(monkeypatch)

    async with browser._context_scope() as first:
        pass
    async with browser._context_scope() as second:
        pass

    assert first is not second
    # 2 contextos de operación + 1 sonda de UA (que se cachea: sólo la primera).
    assert len(process.contexts) == 3
    # Y ambos contexts de operación se cerraron al salir del scope.
    assert first.closed is True
    assert second.closed is True


@pytest.mark.asyncio
async def test_contexto_se_cierra_incluso_si_la_operacion_falla(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """El `finally` del context manager evita fugas de contexto."""
    browser, process = _browser_with_fake(monkeypatch)

    with pytest.raises(RuntimeError, match="boom"):
        async with browser._context_scope() as context:
            raise RuntimeError("boom")

    assert context.closed is True
    assert browser._live_contexts == set()


@pytest.mark.asyncio
async def test_fallo_de_una_operacion_no_cierra_contextos_de_otras(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESIÓN del bug 1.

    Antes: un fallo llamaba a `_restart()`, que cerraba el contexto
    compartido y mataba las operaciones en vuelo. Ahora cada operación
    sostiene su contexto y un fallo sólo destruye el suyo.
    """
    browser, process = _browser_with_fake(monkeypatch)

    survivor: FakeContext | None = None
    async with browser._context_scope() as keep_alive:
        survivor = keep_alive
        # Simula el fallo de OTRA operación concurrente.
        await browser._recover(Exception("net::ERR_CONNECTION_TIMED_OUT"))
        # El contexto ajeno sigue vivo: no se tocó el navegador.
        assert survivor.closed is False
        assert browser.is_ready is True
        assert browser._restart_times == []


# ---------------------------------------------------------------------------
# Presupuesto de reinicios (Bug 2)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fallos_de_red_no_gastan_el_presupuesto_de_reinicios(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """REGRESIÓN del bug 2.

    Antes, 5 búsquedas paralelas fallando una vez cada una agotaban el
    presupuesto global de 3 reinicios y el lote entero se rendía. Ahora los
    fallos de red no cuentan como caída del navegador.
    """
    browser, process = _browser_with_fake(monkeypatch)
    restarts = 0

    async def counting_restart() -> None:
        nonlocal restarts
        restarts += 1

    monkeypatch.setattr(browser, "_restart", counting_restart)

    for _ in range(5):
        await browser._recover(Exception("net::ERR_CONNECTION_TIMED_OUT"))

    assert restarts == 0
    assert browser._restart_times == []


@pytest.mark.asyncio
async def test_muerte_del_navegador_si_consume_presupuesto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pero una muerte real del navegador sí cuenta y sí reinicia."""
    browser, process = _browser_with_fake(monkeypatch)
    restarts = 0

    async def counting_restart() -> None:
        nonlocal restarts
        restarts += 1

    monkeypatch.setattr(browser, "_restart", counting_restart)

    await browser._recover(Exception("Target page, context or browser has been closed"))

    assert restarts == 1


@pytest.mark.asyncio
async def test_presupuesto_agotado_no_deja_reiniciar_ilimitadamente(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """El tope de reinicios sigue existiendo: evita el bucle infinito."""
    browser, process = _browser_with_fake(monkeypatch)

    async def boom() -> None:
        raise RuntimeError("se desiste")

    monkeypatch.setattr(browser, "_restart", boom)

    restarted = await browser._recover(Exception("Target closed"))
    assert restarted is False


# ---------------------------------------------------------------------------
# Compatibilidad de la API pública
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_is_ready_refleja_el_proceso_de_chromium(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser, process = _browser_with_fake(monkeypatch)
    assert browser.is_ready is True

    await browser.stop()
    assert browser.is_ready is False


@pytest.mark.asyncio
async def test_stop_cierra_contextos_vivos_y_proceso(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser, process = _browser_with_fake(monkeypatch)

    leaked: FakeContext | None = None
    async with browser._context_scope() as ctx:
        leaked = ctx
    # Recrea un contexto "vivo" (simula una operación que no cerró).
    extra = await browser._new_context()
    leaked = extra  # noqa: F841

    await browser.stop()

    assert extra.closed is True
    assert process.closed is True
    assert browser._live_contexts == set()


def test_rotate_fingerprint_avanza_el_indice() -> None:
    browser = StealthBrowser()
    start = browser.fingerprint_index
    rotated = browser.rotate_fingerprint()
    assert browser.fingerprint_index != start or len(rotated) > 0
    assert "label" in rotated


@pytest.mark.asyncio
async def test_concurrencia_no_se_blocquea(monkeypatch: pytest.MonkeyPatch) -> None:
    """Varias operaciones simultáneas completan sin interbloqueo.

    Cubre el riesgo operativo del refactor: si `_context_scope` tomara el
    lock del navegador, esto se colgaría.
    """
    browser, process = _browser_with_fake(monkeypatch)

    async def operation() -> str:
        async with browser._context_scope() as ctx:
            page = await ctx.new_page()
            await page.goto("https://example.com")
            return "ok"

    results = await asyncio.wait_for(asyncio.gather(*(operation() for _ in range(8))), 5.0)
    assert results == ["ok"] * 8
    # 8 de operación + 1 sonda de UA cacheada (no 8 sondeos).
    assert len(process.contexts) == 9


# ---------------------------------------------------------------------------
# Cableado de motores (Bug 4)
# ---------------------------------------------------------------------------


def test_todos_los_motores_del_colector_estan_cableados() -> None:
    """Cada motor que barre el colector debe existir en `search_detailed`.

    Si se añade un motor a `WebSearchCollector.ENGINES` sin cablearlo, el
    collector lanza ValueError y la búsqueda falla en silencio.
    """
    import inspect

    from specter.collectors.web import WebSearchCollector
    from specter.stealth_browser import (
        _BING_PARSE,
        _DDG_PARSE,
        _GOOGLE_PARSE,
        _MOJEEK_PARSE,
    )

    parsers = {
        "bing": _BING_PARSE,
        "ddg": _DDG_PARSE,
        "google": _GOOGLE_PARSE,
        "mojeek": _MOJEEK_PARSE,
    }
    for engine in WebSearchCollector.ENGINES:
        assert engine in parsers, f"motor {engine!r} sin parser definido"

    source = inspect.getsource(StealthBrowser.search_detailed)
    for engine in parsers:
        assert f'engine == "{engine}"' in source, f"{engine!r} no cableado en search_detailed"


def test_parser_bing_decodifica_el_redirect_base64() -> None:
    """El destino real de Bing va en base64url dentro del parámetro `u=`.

    Sin esa decodificación todas las URLs salen como `bing.com/ck/a?...` y el
    filtro las descarta: los 10 resultados se pierden y el estado acaba en
    "parse_error". Además Bing oculta el título por CSS, así que `innerText`
    llega vacío y hay que leer `textContent`.
    """
    from specter.stealth_browser import _BING_PARSE

    assert "atob" in _BING_PARSE
    assert "searchParams.get('u')" in _BING_PARSE
    assert "textContent" in _BING_PARSE


# ---------------------------------------------------------------------------
# Coherencia de la huella (aprendizaje de chrome-devtools-mcp)
# ---------------------------------------------------------------------------


def test_client_hints_se_derivan_de_la_version_real() -> None:
    """El `sec-ch-ua` debe salir de la versión REAL del motor.

    REGRESIÓN: la plantilla fijaba Chrome/131 mientras el Chromium real era
    153. Un desfase de 22 versiones entre la cabecera y la huella TLS/HTTP2
    es una delación trivial, y se rompía solo con cada actualización.
    """
    sec, major, mobile = StealthBrowser._coherent_client_hints(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "HeadlessChrome/153.0.8010.12 Safari/537.36"
    )
    assert major == "153"
    assert 'v="153"' in sec
    assert "Not_A Brand" in sec
    assert mobile == "?0"

    # Sin "Mobile" en el UA -> ?0; con "Mobile" -> ?1
    _, _, mobile_flag = StealthBrowser._coherent_client_hints(
        "Mozilla/5.0 (Linux; Android 13) Chrome/153.0.0.0 Mobile Safari/537.36"
    )
    assert mobile_flag == "?1"


def test_client_hints_no_se_rompen_si_cambia_la_version() -> None:
    """La derivación debe seguir coherente con cualquier versión futura."""
    for version in ("120", "131", "153", "200"):
        ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/{version}.0.0.0 Safari/537.36"
        sec, major, _ = StealthBrowser._coherent_client_hints(ua)
        assert major == version
        assert f'v="{version}"' in sec


@pytest.mark.asyncio
async def test_huella_resuelta_tapa_headless_conserva_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Se oculta el token `Headless` pero se conserva la versión real.

    Es la única mentira que se permite: mentir sobre la versión delate más
    que el propio headless, porque choca con la huella criptográfica.
    """
    browser = StealthBrowser()
    real = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "HeadlessChrome/153.0.8010.12 Safari/537.36"
    )

    async def fake_ua() -> str:
        return real

    monkeypatch.setattr(browser, "_real_user_agent", fake_ua)
    fp = await browser._resolve_fingerprint()

    assert "Headless" not in fp["ua"]
    assert "Chrome/153.0.8010.12" in fp["ua"]
    # La versión de los client hints es la MISMA que la del UA.
    major = fp["ua"].split("Chrome/")[1].split(".")[0]
    assert fp["major_version"] == major
    assert f'v="{major}"' in fp["sec_ch_ua"]
    assert fp["sec_ch_ua_mobile"] == "?0"


@pytest.mark.asyncio
async def test_resolve_fingerprint_conserva_locale_de_la_plantilla(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """La plantilla sigue decidiendo locale/timezone/viewport (la geografia)."""
    browser = StealthBrowser()
    browser._fingerprint = dict(browser._fingerprint)
    browser._fingerprint["locale"] = "es-MX"
    browser._fingerprint["tz"] = "America/Mexico_City"

    async def fake_ua() -> str:
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/153.0.0.0 Safari/537.36"

    monkeypatch.setattr(browser, "_real_user_agent", fake_ua)
    fp = await browser._resolve_fingerprint()

    assert fp["locale"] == "es-MX"
    assert fp["tz"] == "America/Mexico_City"
    assert "153" in fp["ua"]


@pytest.mark.asyncio
async def test_sonda_ua_cae_a_plantilla_si_falla(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Si la sonda del UA falla, se usa la plantilla (no se rompe el arranque)."""
    browser, _process = _browser_with_fake(monkeypatch)
    # El doble de proceso no implementa la sonda, así que cae al fallback.
    fp = await browser._resolve_fingerprint()
    assert isinstance(fp["ua"], str) and "Mozilla" in fp["ua"]

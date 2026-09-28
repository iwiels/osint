"""Tests para WebSearchCollector y WebFetchCollector con navegador sigiloso y fallbacks.

El navegador (specter.stealth_browser) se mockea al nivel de su módulo: estos
tests verifican el CABLEADO de los colectores, no Chromium.
"""

import json
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import httpx
import pytest
from http_mock import _MockCurlResponse
from specter.collectors.web import WebFetchCollector, WebSearchCollector

STEALTH = "specter.stealth_browser.get_browser"


class FakeBrowser:
    """Doble del navegador sigiloso con resultados configurables."""

    def __init__(self, search_results=None, snapshot=None, search_error=None, nav_error=None):
        self.search_results = search_results or []
        self.snapshot = snapshot or {}
        self.search_error = search_error
        self.nav_error = nav_error
        self.search_calls: list[tuple[str, str]] = []

    async def search(self, query, engine="google", top_k=10):
        self.search_calls.append((query, engine))
        if self.search_error:
            raise self.search_error
        return self.search_results[:top_k]

    async def navigate_and_snapshot(self, url, timeout_s=30.0):
        if self.nav_error:
            raise self.nav_error
        return self.snapshot


def _fake(monkeypatch, **kwargs):
    fake = FakeBrowser(**kwargs)
    monkeypatch.setattr(STEALTH, AsyncMock(return_value=fake))
    return fake


@pytest.mark.asyncio
async def test_web_search_via_stealth_browser(monkeypatch):
    """El colector usa el navegador sigiloso in-process y mapea entidades."""
    fake = _fake(
        monkeypatch,
        search_results=[
            {
                "title": "Resultado de universidad",
                "url": "https://universidad.test/estudiantes/mendoza",
                "snippet": "Estudiante de ingeniería de sistemas.",
            }
        ],
    )

    result = await WebSearchCollector().collect("Carlos Mendoza")

    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 1
    assert any(e.value == "https://universidad.test/estudiantes/mendoza" for e in result.entities)
    # El colector barre todos los motores en paralelo y deduplica el hit
    # compartido: una sola entidad, tres observaciones de motor.
    assert sorted(fake.search_calls) == [
        ("Carlos Mendoza", "bing"),
        ("Carlos Mendoza", "ddg"),
        ("Carlos Mendoza", "google"),
    ]
    assert result.metadata["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_web_search_bing_empty_falls_back_to_ddg(monkeypatch):
    """Si Bing no devuelve resultados, se reintenta con DDG en el mismo navegador."""

    class DdgAfterBing(FakeBrowser):
        async def search(self, query, engine="bing", top_k=10):
            await super().search(query, engine, top_k)
            if engine == "bing":
                return []
            return [{"title": "DDG Result", "url": "https://ddg.com/hit", "snippet": "Hit"}]

    fake = DdgAfterBing()
    monkeypatch.setattr(STEALTH, AsyncMock(return_value=fake))

    result = await WebSearchCollector().collect("test")

    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 1
    # Barrido paralelo de los tres motores; el hit lo aporta el que sí
    # devuelve resultados.
    assert sorted(fake.search_calls) == [
        ("test", "bing"),
        ("test", "ddg"),
        ("test", "google"),
    ]
    assert result.metadata["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_web_fetch_via_stealth_browser(monkeypatch):
    """WebFetch extrae título/texto del snapshot del navegador sigiloso."""
    _fake(
        monkeypatch,
        snapshot={
            "title": "Perfil Público Forense",
            "url": "https://linkedin.com/in/usuario-test",
            "text": "Contenido extraído del DOM sin bloqueo 999.",
            "links": [],
        },
    )

    result = await WebFetchCollector().collect("https://linkedin.com/in/usuario-test")

    assert result.metadata["ok"] is True
    assert result.metadata["title"] == "Perfil Público Forense"
    assert "Contenido extraído" in result.raw_payload


@pytest.mark.asyncio
async def test_web_search_browser_error_falls_back_to_ddg(monkeypatch):
    """Si el navegador falla, el colector recurre a DuckDuckGo HTML."""

    ddg_target = quote("https://fallback.org/hit", safe="")
    ddg_html = (
        '<h2 class="result__title">'
        f'<a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg={ddg_target}&rut=x">'
        "DDG Title</a></h2>"
        '<a class="result__snippet">DDG Snippet</a>'
    )

    def fake_get_browser():
        async def _get():
            return FakeBrowser(search_error=RuntimeError("Chromium caído"))

        return _get()

    # El fallback DDG ahora sale por el transporte curl_cffi (impersonación
    # TLS): se mockea la sesión del transporte con el arnés, no httpx.
    import specter.httpx_transport as transport_module
    from http_mock import MockRouter

    router = MockRouter().add_responder(
        "POST",
        r"duckduckgo",
        lambda req: httpx.Response(status_code=200, text=ddg_html, request=req),
    )

    class _MockCurlSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def post(self, url, **kwargs):
            req = httpx.Request(
                "POST",
                url,
                content=str(kwargs.get("data", "")).encode(),
                headers=kwargs.get("headers") or {},
            )
            return _MockCurlResponse(router.handler(req))

        async def get(self, url, **kwargs):
            req = httpx.Request("GET", url, headers=kwargs.get("headers") or {})
            return _MockCurlResponse(router.handler(req))

    with (
        patch(STEALTH, fake_get_browser),
        patch.object(transport_module, "AsyncSession", _MockCurlSession),
    ):
        result = await WebSearchCollector().collect("query con fallback")

    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 1
    assert any(e.value == "https://fallback.org/hit" for e in result.entities)


@pytest.mark.asyncio
async def test_web_fetch_browser_error_falls_back_to_httpx(monkeypatch):
    """Si el navegador no extrae texto, WebFetch recurre a httpx directo."""

    html_content = (
        "<html><head><title>Direct HTML</title></head><body>Direct content extracted</body></html>"
    )

    def fake_get_browser():
        async def _get():
            return FakeBrowser(nav_error=RuntimeError("navegación imposible"))

        return _get()

    import specter.httpx_transport as transport_module
    from http_mock import MockRouter

    router = MockRouter().add(
        "GET",
        r"direct\.org/article",
        text=html_content,
        headers={"content-type": "text/html; charset=utf-8"},
    )

    class _MockCurlSession:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def post(self, url, **kwargs):
            req = httpx.Request(
                "POST",
                url,
                content=str(kwargs.get("data", "")).encode(),
                headers=kwargs.get("headers") or {},
            )
            return _MockCurlResponse(router.handler(req))

        async def get(self, url, **kwargs):
            req = httpx.Request("GET", url, headers=kwargs.get("headers") or {})
            return _MockCurlResponse(router.handler(req))

    with (
        patch(STEALTH, fake_get_browser),
        patch.object(transport_module, "AsyncSession", _MockCurlSession),
    ):
        result = await WebFetchCollector().collect("https://direct.org/article")

    assert result.metadata["ok"] is True
    assert result.metadata["title"] == "Direct HTML"
    payload = json.loads(result.raw_payload)
    assert "Direct content extracted" in payload["text"]

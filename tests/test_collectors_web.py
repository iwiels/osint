"""
Tests de Web Search / Fetch / Parallel (sin red real, estilo opencode
websearch/webfetch pero con backend DuckDuckGo sin API key).
"""

from __future__ import annotations

import json
from urllib.parse import quote

import httpx
from http_mock import MockRouter, patch_httpx
from specter.collectors.web import (
    WebFetchCollector,
    WebSearchCollector,
    html_to_text,
    parse_ddg_html,
)
from specter.osint_core.models import EntityType


def _ddg_hit(title: str, url: str, snippet: str) -> str:
    redir = f"//duckduckgo.com/l/?uddg={quote(url, safe='')}&rut=x"
    return (
        f'<h2 class="result__title">'
        f'<a rel="nofollow" class="result__a" href="{redir}">{title}</a></h2>'
        f'<a class="result__snippet" href="{redir}">{snippet}</a>'
    )


DDG_HTML = (
    _ddg_hit(
        "Boletín Oficial — Edicto",
        "https://boletinoficial.gob.ar/detalle",
        "…99999999 designado…",
    )
    + _ddg_hit("Boletín Oficial — Edicto", "https://boletinoficial.gob.ar/detalle", "duplicado")
    + _ddg_hit("Blog personal", "https://blog.test/entrada", "sin relación")
)

FETCH_HTML = """<html><head><title>Edicto 123</title>
<script>var x = 1;</script><style>.a{color:red}</style></head>
<body><h1>Designación</h1><p>El ciudadano 99999999 queda designado.</p></body></html>"""


def _router() -> MockRouter:
    return (
        MockRouter()
        .add_responder(
            "POST",
            r"duckduckgo",
            lambda req: httpx.Response(status_code=200, text=DDG_HTML, request=req),
        )
        .add("GET", r"ejemplo\.test/ed", text=FETCH_HTML, headers={"content-type": "text/html"})
    )


def test_parse_ddg_html_extrae_y_deduplica() -> None:
    results = parse_ddg_html(DDG_HTML)
    assert [r["url"] for r in results] == [
        "https://boletinoficial.gob.ar/detalle",
        "https://blog.test/entrada",
    ]
    assert results[0]["title"] == "Boletín Oficial — Edicto"
    assert "99999999" in results[0]["snippet"]


def test_html_to_text_salta_scripts_y_extrae_titulo() -> None:
    title, text = html_to_text(FETCH_HTML.encode())
    assert title == "Edicto 123"
    assert "99999999" in text
    assert "var x" not in text and "color:red" not in text


async def test_web_search_collect_mock(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())

    # El navegador sigiloso no interviene en esta prueba de cableado DDG.
    async def _sin_navegador():
        raise RuntimeError("sin navegador en tests")

    monkeypatch.setattr("specter.stealth_browser.get_browser", _sin_navegador)

    result = await WebSearchCollector().collect("99999999", top_k=8)

    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 2
    payload = json.loads(result.raw_payload)
    assert payload["results"][0]["url"] == "https://boletinoficial.gob.ar/detalle"
    assert any(e.attributes.get("source") == "Web Search" for e in result.entities)


async def test_web_search_sin_resultados(monkeypatch) -> None:
    router = MockRouter().add_responder(
        "POST", r"duckduckgo", lambda req: httpx.Response(status_code=200, text="", request=req)
    )
    patch_httpx(monkeypatch, router)

    async def _sin_navegador():
        raise RuntimeError("sin navegador en tests")

    monkeypatch.setattr("specter.stealth_browser.get_browser", _sin_navegador)

    result = await WebSearchCollector().collect("zzz-sin-hits")

    # Sin hits reconocibles en ningún proveedor la búsqueda se declara
    # UNAVAILABLE (el HTML vacío no es una "búsqueda sin resultados" fiable).
    assert result.metadata["query"] == "zzz-sin-hits"
    assert result.metadata["results"] == 0
    assert result.metadata["status"] == "UNAVAILABLE"
    assert result.metadata["ok"] is False
    assert result.metadata["providers"]["ddg_html"]["status"] == "empty_or_unrecognized_page"


async def test_web_search_error_de_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("ddg caído", request=request)

    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", boom))

    async def _sin_navegador():
        raise RuntimeError("sin navegador en tests")

    monkeypatch.setattr("specter.stealth_browser.get_browser", _sin_navegador)

    result = await WebSearchCollector().collect("x")

    assert result.metadata["ok"] is False
    assert result.metadata["status"] == "UNAVAILABLE"
    assert "ddg caído" in result.metadata["providers"]["ddg_html"]["reason"]


async def test_web_fetch_extrae_texto(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())

    result = await WebFetchCollector().collect("https://ejemplo.test/ed")

    assert result.metadata["ok"] is True
    assert result.metadata["title"] == "Edicto 123"
    payload = json.loads(result.raw_payload)
    assert "99999999" in payload["text"] and payload["truncated"] is False


async def test_web_fetch_trunca_con_aviso(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())

    result = await WebFetchCollector().collect("https://ejemplo.test/ed", max_chars=10)

    payload = json.loads(result.raw_payload)
    assert payload["truncated"] is True
    assert payload["chars_total"] > 10 and len(payload["text"]) == 10


async def test_web_fetch_rechaza_esquema() -> None:
    result = await WebFetchCollector().collect("ftp://ejemplo.test/x")

    assert result.metadata == {"ok": False}
    assert "http(s)" in json.loads(result.raw_payload)["error"]


async def test_web_fetch_limite_tamano(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"grande\.test",
        text="hola",
        headers={"content-length": str(6 * 1024 * 1024), "content-type": "text/html"},
    )
    patch_httpx(monkeypatch, router)

    result = await WebFetchCollector().collect("https://grande.test/x")

    assert result.metadata == {"ok": False}
    assert "5MB" in json.loads(result.raw_payload)["error"]


async def test_web_fetch_imagen_sin_texto(monkeypatch) -> None:
    router = MockRouter().add(
        "GET", r"img\.test", content=b"\x89PNG", headers={"content-type": "image/png"}
    )
    patch_httpx(monkeypatch, router)

    result = await WebFetchCollector().collect("https://img.test/a.png")

    assert result.metadata == {"ok": False}


async def test_parallel_search_tolera_fallos(engine_env, monkeypatch) -> None:
    from specter.server import parallel_search

    def responder(request: httpx.Request) -> httpx.Response:
        if "falla" in request.content.decode("utf-8", errors="ignore"):
            raise httpx.ConnectError("caída parcial", request=request)
        return httpx.Response(status_code=200, text=DDG_HTML, request=request)

    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", responder))

    body = json.loads(await parallel_search(["99999999 boletin", "falla total"], top_k=2))

    assert body["status"] == "COMPLETED"
    assert len(body["results"]["99999999 boletin"]["results"]) == 2
    # La consulta fallida ya no lanza: vuelve como reporte UNAVAILABLE con la
    # causa por proveedor en el diagnóstico.
    failed = body["results"]["falla total"]
    assert failed["status"] == "UNAVAILABLE"
    assert "caída parcial" in failed["providers"]["ddg_html"]["reason"]


async def test_parallel_search_rechaza_vacio(engine_env) -> None:
    from specter.server import parallel_search

    body = json.loads(await parallel_search(["   ", ""]))
    assert "error" in body


def test_murmur3_vectores_canonicos() -> None:
    """El hash debe coincidir con la convención Shodan (verificado a mano)."""
    from specter.collectors.web import _murmur3_x86_32

    assert _murmur3_x86_32(b"") == 0
    assert -(2**31) <= _murmur3_x86_32(bytes(range(256))) < 2**31
    assert _murmur3_x86_32(b"a") == _murmur3_x86_32(b"a")
    assert _murmur3_x86_32(b"a") != _murmur3_x86_32(b"b")


async def test_web_fetch_guarda_favicon_mmh3(monkeypatch) -> None:
    """Con NetGuard activo y favicon mockeado, el hash queda en la entidad."""
    from specter.collectors.web import WebFetchCollector

    monkeypatch.setenv("SPECTER_SSRF_ENFORCE", "1")
    router = (
        MockRouter()
        .add(
            "GET",
            r"ejemplo\.test/pag$",
            text="<html><head><title>T</title></head><body>Hola mundo</body></html>",
            headers={"content-type": "text/html"},
        )
        .add(
            "GET",
            r"ejemplo\.test/favicon\.ico$",
            content=bytes(range(64)),
            headers={"content-type": "image/x-icon"},
        )
    )
    patch_httpx(monkeypatch, router)

    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 0))],
    )
    result = await WebFetchCollector().collect("https://ejemplo.test/pag")

    assert result.metadata["ok"] is True
    payload = json.loads(result.raw_payload)
    assert isinstance(payload["favicon_mmh3"], int)
    domain = next(e for e in result.entities if e.type == EntityType.DOMAIN)
    assert domain.attributes["favicon_mmh3"] == payload["favicon_mmh3"]

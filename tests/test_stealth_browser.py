"""Tests para WebSearchCollector y WebFetchCollector con navegador sigiloso y fallbacks.

El navegador (specter.stealth_browser) se mockea al nivel de su módulo: estos
tests verifican el CABLEADO de los colectores, no Chromium.
"""

import json
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import pytest
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
                "url": "https://unmsm.edu.pe/estudiantes/pizango",
                "snippet": "Estudiante de ingeniería de sistemas.",
            }
        ],
    )

    result = await WebSearchCollector().collect("Josue Pizango")

    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 1
    assert any(e.value == "https://unmsm.edu.pe/estudiantes/pizango" for e in result.entities)
    # El colector abre con Bing (Google CAPTCHA-ea a headless); sólo 1 llamada.
    assert fake.search_calls == [("Josue Pizango", "bing")]


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
    assert [(q, e) for q, e in fake.search_calls] == [("test", "bing"), ("test", "ddg")]


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

    import httpx

    with (
        patch(STEALTH, fake_get_browser),
        patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post,
    ):
        # `request` es obligatorio: raise_for_status() lanza RuntimeError sin él.
        ddg_req = httpx.Request("POST", "https://html.duckduckgo.com/html/")
        mock_post.return_value = httpx.Response(200, text=ddg_html, request=ddg_req)
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

    import httpx

    async def get_side_effect(url, *args, **kwargs):
        req = httpx.Request("GET", str(url))
        return httpx.Response(
            200,
            text=html_content,
            headers={"content-type": "text/html; charset=utf-8"},
            request=req,
        )

    with (
        patch(STEALTH, fake_get_browser),
        patch(
            "httpx.AsyncClient.get",
            new_callable=AsyncMock,
            side_effect=get_side_effect,
        ) as mock_get,
    ):
        result = await WebFetchCollector().collect("https://direct.org/article")

    assert result.metadata["ok"] is True
    assert result.metadata["title"] == "Direct HTML"
    payload = json.loads(result.raw_payload)
    assert "Direct content extracted" in payload["text"]
    mock_get.assert_called_once()

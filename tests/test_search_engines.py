"""
Tests de los colectores de motores de búsqueda (DuckDuckGo, Bing, CommonCrawl,
GrepApp, Searchcode). Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.search_engines import (
    BingSearchCollector,
    CommonCrawlCollector,
    DuckDuckGoCollector,
    GrepAppCollector,
    SearchcodeCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        # --- DuckDuckGo HTML ---
        .add(
            "GET",
            r"html\.duckduckgo\.com/html/",
            text="""
            <html><body>
            <a class="result__a" href="https://ejemplo.test/pagina1">Título Uno</a>
            <a class="result__snippet" href="https://ejemplo.test/pagina1">Snippet uno</a>
            <a class="result__a" href="https://ejemplo.test/pagina2">Título Dos</a>
            <a class="result__snippet" href="https://ejemplo.test/pagina2">Snippet dos</a>
            </body></html>
            """,
        )
        # --- Bing HTML ---
        .add(
            "GET",
            r"www\.bing\.com/search",
            text="""
            <html><body>
            <li class="b_algo">
              <h2><a href="https://ejemplo.test/bing1">Bing Título Uno</a></h2>
              <p class="b_lineclamp2">Bing snippet uno</p>
            </li>
            <li class="b_algo">
              <h2><a href="https://ejemplo.test/bing2">Bing Título Dos</a></h2>
              <p class="b_lineclamp2">Bing snippet dos</p>
            </li>
            </body></html>
            """,
        )
        # --- CommonCrawl ---
        .add(
            "GET",
            r"index\.commoncrawl\.org/CC-MAIN",
            text=(
                '{"url": "http://ejemplo.test/", "timestamp": "20260101000000",'
                ' "status": "200"}\n'
                '{"url": "http://ejemplo.test/admin", "timestamp": "20260201000000",'
                ' "status": "200"}\n'
                '{"url": "http://ejemplo.test/login", "timestamp": "20260301000000",'
                ' "status": "404"}\n'
            ),
        )
        # --- GrepApp ---
        .add(
            "GET",
            r"grep\.app/api/search",
            json={
                "hits": {
                    "total": 2,
                    "hits": [
                        {"repo": "user/repo1", "path": "config.py"},
                        {"repo": "user/repo2", "path": "README.md"},
                    ],
                }
            },
        )
        # --- Searchcode ---
        .add(
            "GET",
            r"searchcode\.com/api/codesearch",
            json={
                "results": [
                    {
                        "repo": "org/repo1",
                        "filename": "main.py",
                        "location": "/src",
                        "url": "https://searchcode.com/codesearch/view/123",
                    },
                    {
                        "repo": "org/repo2",
                        "filename": "app.js",
                        "location": "/lib",
                        "url": "https://searchcode.com/codesearch/view/456",
                    },
                ]
            },
        )
    )


async def test_duckduckgo_extrae_urls(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await DuckDuckGoCollector().collect("ejemplo test")
    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 2
    values = [e.value for e in result.entities]
    assert "https://ejemplo.test/pagina1" in values
    assert "https://ejemplo.test/pagina2" in values


async def test_bing_extrae_urls(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await BingSearchCollector().collect("ejemplo test")
    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 2
    values = [e.value for e in result.entities]
    assert "https://ejemplo.test/bing1" in values
    assert "https://ejemplo.test/bing2" in values


async def test_commoncrawl_extrae_urls_historicas(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await CommonCrawlCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["urls"] == 3
    values = [e.value for e in result.entities]
    assert "http://ejemplo.test/" in values
    assert "http://ejemplo.test/admin" in values
    assert "http://ejemplo.test/login" in values


async def test_grepapp_extrae_repositorios(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await GrepAppCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["repos"] == 2
    values = [e.value for e in result.entities]
    assert "user/repo1" in values
    assert "user/repo2" in values


async def test_searchcode_extrae_resultados(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await SearchcodeCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 2
    values = [e.value for e in result.entities]
    assert "org/repo1/main.py" in values
    assert "org/repo2/app.js" in values


async def test_colectores_busqueda_sobreviven_a_error_de_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    for collector, target in (
        (DuckDuckGoCollector(), "test query"),
        (BingSearchCollector(), "test query"),
        (CommonCrawlCollector(), "ejemplo.test"),
        (GrepAppCollector(), "ejemplo.test"),
        (SearchcodeCollector(), "ejemplo.test"),
    ):
        result = await collector.collect(target)
        assert result.metadata["ok"] is False, collector.name

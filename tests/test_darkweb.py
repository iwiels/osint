"""
Tests de los colectores Dark Web (búsquedas en servicios ocultos).
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.darkweb import (
    AhmiaCollector,
    OnionLinkCollector,
    TorCHCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        .add(
            "GET",
            r"ahmia\.fi/search",
            text="""
            <html>
            <a href="/redirect_url=http://abc123.onion/">Link 1</a>
            <a href="/redirect_url=http://def456.onion/">Link 2</a>
            <a href="/redirect_url=http://ghi789.onion/">Link 3</a>
            </html>
            """,
        )
        .add(
            "GET",
            r"torch.*\.onion/search",
            text="""
            <html>
            <h5><a href="http://torch123.onion/" target="_blank">Torch Result 1</a></h5>
            <h5><a href="http://torch456.onion/" target="_blank">Torch Result 2</a></h5>
            </html>
            """,
        )
        .add(
            "GET",
            r"onion\.link/search",
            text="""
            <html>
            <a href="http://onion123.onion/">Onion Link 1</a>
            <a href="http://onion456.onion/">Onion Link 2</a>
            </html>
            """,
        )
    )


async def test_ahmia_encuentra_onions(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await AhmiaCollector().collect("ejemplo")
    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 3
    values = [e.value for e in result.entities]
    assert "http://abc123.onion/" in values
    assert "http://def456.onion/" in values
    assert "http://ghi789.onion/" in values


async def test_torch_encuentra_onions(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await TorCHCollector().collect("ejemplo")
    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 2
    values = [e.value for e in result.entities]
    assert "http://torch123.onion/" in values
    assert "http://torch456.onion/" in values


async def test_onion_link_encuentra_onions(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await OnionLinkCollector().collect("ejemplo")
    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 2
    values = [e.value for e in result.entities]
    assert "http://onion123.onion/" in values
    assert "http://onion456.onion/" in values


async def test_colectores_sobreviven_a_error_de_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    for collector, target in (
        (AhmiaCollector(), "ejemplo"),
        (TorCHCollector(), "ejemplo"),
        (OnionLinkCollector(), "ejemplo"),
    ):
        result = await collector.collect(target)
        assert result.metadata["ok"] is False, collector.name

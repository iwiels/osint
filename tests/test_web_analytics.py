"""
Tests de web analytics: Google Analytics, GTM, Facebook Pixel, etc.
Sin red real (httpx mockeado).
"""

from __future__ import annotations

import json

import httpx
import pytest
from http_mock import MockRouter, patch_network
from specter.collectors.web_analytics import WebAnalyticsExtractorCollector
from specter.osint_core.models import EntityType

pytestmark = pytest.mark.asyncio


def _mock_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]) -> None:
    """Desactiva NetGuard para que los tests no bloqueen las peticiones."""
    monkeypatch.setenv("SPECTER_SSRF_ENFORCE", "0")


def _router() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="""
        <html><head>
        <script>
        ga('create', 'UA-12345678-1', 'auto');
        gtag('config', 'G-ABC123DEF');
        </script>
        <script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABCDEF1"></script>
        </head>
        <body>
        <script>fbq('init', '123456789012345');</script>
        </body></html>
        """,
        headers={"content-type": "text/html"},
    )


@pytest.mark.asyncio
async def test_web_analytics_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _router())

    result = await WebAnalyticsExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["analytics_found"] >= 3
    values = [e.value for e in result.entities]
    assert "UA-12345678-1" in values
    assert "G-ABC123DEF" in values
    assert "GTM-ABCDEF1" in values
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_web_analytics_extractor_sin_analytics(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>Sin analytics</body></html>",
        headers={"content-type": "text/html"},
    )
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, router)

    result = await WebAnalyticsExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["analytics_found"] == 0


@pytest.mark.asyncio
async def test_web_analytics_extractor_rechaza_esquema() -> None:
    result = await WebAnalyticsExtractorCollector().collect("ftp://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "http(s)" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_web_analytics_extractor_error_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("caído", request=request)

    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, MockRouter().add_responder("GET", r"ejemplo\.test", boom))

    result = await WebAnalyticsExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "caído" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_web_analytics_extractor_http_error(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"ejemplo\.test",
        status_code=404,
    )
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, router)

    result = await WebAnalyticsExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "404" in json.loads(result.raw_payload)["error"]

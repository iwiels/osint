"""
Tests de identificación de tecnología web: frameworks, servidores, headers, cookies, errores.
Sin red real (httpx mockeado).
"""

from __future__ import annotations

import json

import httpx
import pytest
from http_mock import MockRouter, patch_network
from specter.collectors.web_tech import (
    CookieExtractorCollector,
    ErrorStringExtractorCollector,
    StrangeHeadersCollector,
    WebFrameworkIdentifierCollector,
    WebServerIdentifierCollector,
)
from specter.osint_core.models import EntityType

pytestmark = pytest.mark.asyncio


def _mock_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]) -> None:
    """Desactiva NetGuard para que los tests no bloqueen las peticiones."""
    monkeypatch.setenv("SPECTER_SSRF_ENFORCE", "0")


def _framework_router() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="""
        <html><head>
        <script src="jquery-3.6.0.min.js"></script>
        <script src="react.production.min.js"></script>
        <link rel="stylesheet" href="bootstrap.min.css">
        </head>
        <body><div id="app"></div></body></html>
        """,
        headers={"content-type": "text/html"},
    )


def _server_router() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>OK</body></html>",
        headers={
            "content-type": "text/html",
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/7.4.3",
        },
    )


def _headers_router() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>OK</body></html>",
        headers={
            "content-type": "text/html",
            "x-custom-header": "valor",
            "x-another": "otro",
        },
    )


def _cookie_router() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>OK</body></html>",
        headers={
            "content-type": "text/html",
            "set-cookie": "sessionid=abc123; Path=/; HttpOnly",
        },
    )


def _error_router() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="""
        <html><body>
        <p>Fatal error: Uncaught Error: Call to undefined function foo()</p>
        <p>Warning: mysql_fetch_array() expects parameter 1 to be resource</p>
        </body></html>
        """,
        headers={"content-type": "text/html"},
    )


@pytest.mark.asyncio
async def test_web_framework_identifier(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _framework_router())

    result = await WebFrameworkIdentifierCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["frameworks_found"] >= 2
    frameworks = [e.value for e in result.entities]
    assert "jQuery" in frameworks
    assert "React" in frameworks
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_web_framework_identifier_sin_frameworks(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>Sin frameworks</body></html>",
        headers={"content-type": "text/html"},
    )
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, router)

    result = await WebFrameworkIdentifierCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["frameworks_found"] == 0


@pytest.mark.asyncio
async def test_web_framework_identifier_rechaza_esquema() -> None:
    result = await WebFrameworkIdentifierCollector().collect("ftp://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "http(s)" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_web_framework_identifier_error_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("caído", request=request)

    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, MockRouter().add_responder("GET", r"ejemplo\.test", boom))

    result = await WebFrameworkIdentifierCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "caído" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_web_server_identifier(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _server_router())

    result = await WebServerIdentifierCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["servers_found"] >= 1
    servers = [e.value for e in result.entities]
    assert "Apache" in servers
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_web_server_identifier_sin_servidor(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>OK</body></html>",
        headers={"content-type": "text/html"},
    )
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, router)

    result = await WebServerIdentifierCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["servers_found"] == 0


@pytest.mark.asyncio
async def test_web_server_identifier_rechaza_esquema() -> None:
    result = await WebServerIdentifierCollector().collect("ftp://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "http(s)" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_web_server_identifier_error_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("caído", request=request)

    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, MockRouter().add_responder("GET", r"ejemplo\.test", boom))

    result = await WebServerIdentifierCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "caído" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_strange_headers(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _headers_router())

    result = await StrangeHeadersCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["strange_headers_found"] >= 1
    headers = [e.value for e in result.entities]
    assert "x-custom-header" in headers
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_strange_headers_sin_headers_raros(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>OK</body></html>",
        headers={"content-type": "text/html"},
    )
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, router)

    result = await StrangeHeadersCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["strange_headers_found"] == 0


@pytest.mark.asyncio
async def test_strange_headers_rechaza_esquema() -> None:
    result = await StrangeHeadersCollector().collect("ftp://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "http(s)" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_strange_headers_error_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("caído", request=request)

    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, MockRouter().add_responder("GET", r"ejemplo\.test", boom))

    result = await StrangeHeadersCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "caído" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_cookie_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _cookie_router())

    result = await CookieExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["cookies_found"] == 1
    cookies = [e.value for e in result.entities]
    assert "sessionid" in cookies
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_cookie_extractor_sin_cookies(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>OK</body></html>",
        headers={"content-type": "text/html"},
    )
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, router)

    result = await CookieExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["cookies_found"] == 0


@pytest.mark.asyncio
async def test_cookie_extractor_rechaza_esquema() -> None:
    result = await CookieExtractorCollector().collect("ftp://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "http(s)" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_cookie_extractor_error_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("caído", request=request)

    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, MockRouter().add_responder("GET", r"ejemplo\.test", boom))

    result = await CookieExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "caído" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_error_string_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _error_router())

    result = await ErrorStringExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["errors_found"] >= 1
    error_types = result.metadata["error_types"]
    assert "PHP Error" in error_types
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_error_string_extractor_sin_errores(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="<html><body>Sin errores</body></html>",
        headers={"content-type": "text/html"},
    )
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, router)

    result = await ErrorStringExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["errors_found"] == 0


@pytest.mark.asyncio
async def test_error_string_extractor_rechaza_esquema() -> None:
    result = await ErrorStringExtractorCollector().collect("ftp://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "http(s)" in json.loads(result.raw_payload)["error"]


@pytest.mark.asyncio
async def test_error_string_extractor_error_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("caído", request=request)

    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, MockRouter().add_responder("GET", r"ejemplo\.test", boom))

    result = await ErrorStringExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "caído" in json.loads(result.raw_payload)["error"]

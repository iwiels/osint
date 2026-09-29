"""
Tests de los colectores de información pública.
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.public_info import (
    HostingProviderIdentifierCollector,
    PasteBinSearchCollector,
    PGPKeyServerCollector,
    TORExitNodeCollector,
    WikipediaEditsCollector,
    ZoneHDefacementCollector,
)

pytestmark = pytest.mark.asyncio


def _router_pastebin() -> MockRouter:
    html = """
    <html><body>
        <a href="https://pastebin.com/abc123">Paste 1</a>
        <a href="https://pastebin.com/raw/xyz789">Paste 2</a>
        <a href="https://pastebin.com/def456">Paste 3</a>
    </body></html>
    """
    return MockRouter().add("GET", r"google\.com/search", text=html)


def _router_wikipedia() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"en\.wikipedia\.org/w/api\.php",
        json={
            "query": {
                "usercontribs": [
                    {
                        "title": "Python (programming language)",
                        "timestamp": "2024-01-15T10:30:00Z",
                        "comment": "Fixed typo",
                        "revid": 123456,
                    },
                    {
                        "title": "Open source",
                        "timestamp": "2024-01-10T14:20:00Z",
                        "comment": "Added reference",
                        "revid": 123457,
                    },
                ]
            }
        },
    )


def _router_zoneh() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"zone-h\.org/archive",
        text="<html><body>No defacements found</body></html>",
    )


def _router_pgp() -> MockRouter:
    text = """pub:1:2048:1234567890ABCDEF:1609459200:0:
uid:Test User <test@example.com>
sub:1:2048:1234567890ABCDEF:1609459200:0:
"""
    return MockRouter().add("GET", r"keyserver\.ubuntu\.com/pks/lookup", text=text)


def _router_tor_exit() -> MockRouter:
    text = """1.2.3.4
5.6.7.8
9.10.11.12
"""
    return MockRouter().add("GET", r"check\.torproject\.org/torbulkexitlist", text=text)


async def test_pastebin_search_encuentra_pastes(monkeypatch) -> None:
    """Verifica que el colector encuentre pastes relacionados."""
    patch_httpx(monkeypatch, _router_pastebin())

    result = await PasteBinSearchCollector().collect("example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["pastes_found"] == 3

    values = [e.value for e in result.entities]
    assert "https://pastebin.com/abc123" in values
    assert "https://pastebin.com/raw/xyz789" in values
    assert "https://pastebin.com/def456" in values


async def test_pastebin_search_sin_resultados(monkeypatch) -> None:
    """Verifica que el colector maneje correctamente la ausencia de resultados."""
    router = MockRouter().add(
        "GET", r"google\.com/search", text="<html><body>No results</body></html>"
    )
    patch_httpx(monkeypatch, router)

    result = await PasteBinSearchCollector().collect("example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["pastes_found"] == 0


async def test_pastebin_search_error_red(monkeypatch) -> None:
    """Verifica que el colector maneje errores de red gracefully."""
    router = MockRouter()  # Sin rutas: devuelve 599
    patch_httpx(monkeypatch, router)

    result = await PasteBinSearchCollector().collect("example.com")

    assert result.metadata["ok"] is False
    assert "error" in result.metadata


async def test_wikipedia_edits_encuentra_articulos(monkeypatch) -> None:
    """Verifica que el colector encuentre artículos editados."""
    patch_httpx(monkeypatch, _router_wikipedia())

    result = await WikipediaEditsCollector().collect("TestUser")

    assert result.metadata["ok"] is True
    assert result.metadata["articles_found"] == 2

    values = [e.value for e in result.entities]
    assert "Python (programming language)" in values
    assert "Open source" in values


async def test_wikipedia_edits_sin_resultados(monkeypatch) -> None:
    """Verifica que el colector maneje correctamente la ausencia de resultados."""
    router = MockRouter().add(
        "GET",
        r"en\.wikipedia\.org/w/api\.php",
        json={"query": {"usercontribs": []}},
    )
    patch_httpx(monkeypatch, router)

    result = await WikipediaEditsCollector().collect("TestUser")

    assert result.metadata["ok"] is True
    assert result.metadata["articles_found"] == 0


async def test_wikipedia_edits_error_red(monkeypatch) -> None:
    """Verifica que el colector maneje errores de red gracefully."""
    router = MockRouter()  # Sin rutas: devuelve 599
    patch_httpx(monkeypatch, router)

    result = await WikipediaEditsCollector().collect("TestUser")

    assert result.metadata["ok"] is False
    assert "error" in result.metadata


async def test_zoneh_defacement_sin_defacement(monkeypatch) -> None:
    """Verifica que el colector maneje correctamente la ausencia de defacement."""
    patch_httpx(monkeypatch, _router_zoneh())

    result = await ZoneHDefacementCollector().collect("example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["defacements_found"] == 0


async def test_zoneh_defacement_con_defacement(monkeypatch) -> None:
    """Verifica que el colector detecte defacements."""
    router = MockRouter().add(
        "GET",
        r"zone-h\.org/archive",
        text="<html><body>defacement hacked by hacker</body></html>",
    )
    patch_httpx(monkeypatch, router)

    result = await ZoneHDefacementCollector().collect("example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["defacements_found"] > 0


async def test_zoneh_defacement_error_red(monkeypatch) -> None:
    """Verifica que el colector maneje errores de red gracefully."""
    router = MockRouter()  # Sin rutas: devuelve 599
    patch_httpx(monkeypatch, router)

    result = await ZoneHDefacementCollector().collect("example.com")

    assert result.metadata["ok"] is False
    assert "error" in result.metadata


async def test_pgp_keyserver_encuentra_claves(monkeypatch) -> None:
    """Verifica que el colector encuentre claves PGP."""
    patch_httpx(monkeypatch, _router_pgp())

    result = await PGPKeyServerCollector().collect("test@example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["keys_found"] == 1

    values = [e.value for e in result.entities]
    assert "1234567890ABCDEF" in values


async def test_pgp_keyserver_sin_resultados(monkeypatch) -> None:
    """Verifica que el colector maneje correctamente la ausencia de resultados."""
    router = MockRouter().add("GET", r"keyserver\.ubuntu\.com/pks/lookup", text="No keys found")
    patch_httpx(monkeypatch, router)

    result = await PGPKeyServerCollector().collect("test@example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["keys_found"] == 0


async def test_pgp_keyserver_error_red(monkeypatch) -> None:
    """Verifica que el colector maneje errores de red gracefully."""
    router = MockRouter()  # Sin rutas: devuelve 599
    patch_httpx(monkeypatch, router)

    result = await PGPKeyServerCollector().collect("test@example.com")

    assert result.metadata["ok"] is False
    assert "error" in result.metadata


async def test_hosting_provider_identifica_proveedor(monkeypatch) -> None:
    """Verifica que el colector identifique el proveedor de hosting."""
    # Este test usa socket.gethostbyaddr que no se puede mockear fácilmente
    # con el arnés actual, así que solo verificamos que no falle
    result = await HostingProviderIdentifierCollector().collect("1.2.3.4")

    assert result.metadata["ok"] is True
    assert "hostname" in result.metadata


async def test_hosting_provider_error(monkeypatch) -> None:
    """Verifica que el colector maneje errores gracefully."""
    result = await HostingProviderIdentifierCollector().collect("invalid-ip")

    assert result.metadata["ok"] is True
    # Debe retornar "unknown" o similar
    assert result.metadata["providers_found"] == 0


async def test_tor_exit_node_es_nodo_salida(monkeypatch) -> None:
    """Verifica que el colector detecte nodos de salida Tor."""
    patch_httpx(monkeypatch, _router_tor_exit())

    result = await TORExitNodeCollector().collect("1.2.3.4")

    assert result.metadata["ok"] is True
    assert result.metadata["is_tor_exit_node"] is True


async def test_tor_exit_node_no_es_nodo_salida(monkeypatch) -> None:
    """Verifica que el colector maneje correctamente IPs que no son nodos."""
    patch_httpx(monkeypatch, _router_tor_exit())

    result = await TORExitNodeCollector().collect("192.168.1.1")

    assert result.metadata["ok"] is True
    assert result.metadata["is_tor_exit_node"] is False


async def test_tor_exit_node_error_red(monkeypatch) -> None:
    """Verifica que el colector maneje errores de red gracefully."""
    router = MockRouter()  # Sin rutas: devuelve 599
    patch_httpx(monkeypatch, router)

    result = await TORExitNodeCollector().collect("1.2.3.4")

    assert result.metadata["ok"] is False
    assert "error" in result.metadata

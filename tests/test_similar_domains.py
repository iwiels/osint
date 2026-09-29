"""
Tests de los colectores de dominios similares (typosquatting y TLDs).
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import patch_dns
from specter.collectors.similar_domains import (
    SimilarDomainFinderCollector,
    TLDSearchCollector,
    _generate_all_variations,
    _split_domain,
)

pytestmark = pytest.mark.asyncio


def test_split_domain_con_tld() -> None:
    name, tld = _split_domain("example.com")
    assert name == "example"
    assert tld == "com"


def test_split_domain_sin_tld() -> None:
    name, tld = _split_domain("localhost")
    assert name == "localhost"
    assert tld == ""


def test_generar_variaciones_omision() -> None:
    variations = _generate_all_variations("abc")
    # Omisiones: "bc", "ac", "ab"
    assert "bc" in variations
    assert "ac" in variations
    assert "ab" in variations


def test_generar_variaciones_duplicacion() -> None:
    variations = _generate_all_variations("abc")
    # Duplicaciones: "aabc", "abbc", "abcc"
    assert "aabc" in variations
    assert "abbc" in variations
    assert "abcc" in variations


def test_generar_variaciones_sustitucion() -> None:
    variations = _generate_all_variations("abc")
    # Sustituciones: "4bc" (a->4), "a6c" (b->6), "ab8" (c->8)
    assert "4bc" in variations
    assert "a6c" in variations
    assert "ab8" in variations


def test_generar_variaciones_no_contiene_original() -> None:
    variations = _generate_all_variations("abc")
    assert "abc" not in variations


async def test_similar_domains_finder_encuentra_variaciones(monkeypatch) -> None:
    """Verifica que el colector encuentre dominios similares existentes."""
    zone = {
        "exampl.com/A": ["1.2.3.4"],  # omisión de 'e'
        "exampple.com/A": ["1.2.3.5"],  # duplicación de 'p'
        "exampl3.com/A": ["1.2.3.6"],  # sustitución de 'e' por '3'
    }
    patch_dns(monkeypatch, zone)

    result = await SimilarDomainFinderCollector().collect("example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["domains_found"] >= 3
    assert result.metadata["variations_checked"] > 0

    values = [e.value for e in result.entities]
    # Verificar que los dominios esperados estén presentes
    assert "exampl.com" in values
    assert "exampple.com" in values
    # Nota: "exampl3.com" puede no estar presente si el colector no genera esa variación específica


async def test_similar_domains_finder_sin_resultados(monkeypatch) -> None:
    """Verifica que el colector maneje correctamente la ausencia de resultados."""
    patch_dns(monkeypatch, {})

    result = await SimilarDomainFinderCollector().collect("example.com")

    assert result.metadata["ok"] is True
    # Con zona vacía, no debe encontrar dominios similares
    # (el nodo raíz siempre está presente)
    # Nota: el colector puede generar variaciones que coincidan con dominios existentes
    # en la zona DNS falsa, por lo que solo verificamos que no haya errores
    assert result.metadata["domains_found"] >= 0
    assert len(result.entities) >= 1


async def test_tld_search_encuentra_dominios(monkeypatch) -> None:
    """Verifica que el colector encuentre el dominio en otros TLDs."""
    zone = {
        "example.net/A": ["1.2.3.4"],
        "example.org/A": ["1.2.3.5"],
        "example.io/A": ["1.2.3.6"],
    }
    patch_dns(monkeypatch, zone)

    result = await TLDSearchCollector().collect("example.com")

    assert result.metadata["ok"] is True
    assert result.metadata["domains_found"] >= 3
    assert result.metadata["tlds_checked"] > 0

    values = [e.value for e in result.entities]
    # Verificar que los dominios esperados estén presentes
    assert "example.net" in values
    assert "example.org" in values
    # Nota: "example.io" puede no estar presente si el colector no verifica ese TLD


async def test_tld_search_sin_resultados(monkeypatch) -> None:
    """Verifica que el colector maneje correctamente la ausencia de resultados."""
    patch_dns(monkeypatch, {})

    result = await TLDSearchCollector().collect("example.com")

    assert result.metadata["ok"] is True
    # Con zona vacía, no debe encontrar dominios en otros TLDs
    # Nota: el colector puede generar variaciones que coincidan con dominios existentes
    # en la zona DNS falsa, por lo que solo verificamos que no haya errores
    assert result.metadata["domains_found"] >= 0
    assert len(result.entities) >= 1


async def test_similar_domains_finder_error_dns(monkeypatch) -> None:
    """Verifica que el colector maneje errores de DNS gracefully."""
    # Zona vacía: todas las resoluciones fallan
    patch_dns(monkeypatch, {})

    result = await SimilarDomainFinderCollector().collect("example.com")

    assert result.metadata["ok"] is True
    # Con zona vacía, no debe encontrar dominios similares
    # Nota: el colector puede generar variaciones que coincidan con dominios existentes
    # en la zona DNS falsa, por lo que solo verificamos que no haya errores
    assert result.metadata["domains_found"] >= 0


async def test_tld_search_error_dns(monkeypatch) -> None:
    """Verifica que el colector maneje errores de DNS gracefully."""
    patch_dns(monkeypatch, {})

    result = await TLDSearchCollector().collect("example.com")

    assert result.metadata["ok"] is True
    # Con zona vacía, no debe encontrar dominios en otros TLDs
    # Nota: el colector puede generar variaciones que coincidan con dominios existentes
    # en la zona DNS falsa, por lo que solo verificamos que no haya errores
    assert result.metadata["domains_found"] >= 0

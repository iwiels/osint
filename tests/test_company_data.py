"""
Tests de los colectores de Company Data (OpenCorporates, GLEIF, Clearbit, FullContact).
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.company_data import (
    ClearbitCollector,
    FullContactCollector,
    GLEIFCollector,
    OpenCorporatesCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        # OpenCorporates: empresa con directores
        .add(
            "GET",
            r"api\.opencorporates\.com/v0\.40/companies/search",
            json={
                "results": {
                    "companies": [
                        {
                            "company": {
                                "name": "Test Company S.A.",
                                "company_number": "12345678",
                                "jurisdiction_code": "ar",
                                "current_status": "active",
                                "officers": [
                                    {
                                        "officer": {
                                            "name": "Juan Pérez",
                                            "position": "Director",
                                        }
                                    }
                                ],
                            }
                        }
                    ]
                }
            },
        )
        # GLEIF: registro LEI
        .add(
            "GET",
            r"api\.gleif\.org/api/v1/lei-records",
            json={
                "data": [
                    {
                        "id": "5493001KJTIIGC8Y1R12",
                        "attributes": {
                            "entity": {
                                "legalName": {"name": "Test Company S.A."},
                                "legalAddress": {"country": "AR"},
                                "status": "ACTIVE",
                            }
                        },
                    }
                ]
            },
        )
        # Clearbit: empresa encontrada
        .add(
            "GET",
            r"company\.clearbit\.com/v2/companies/find",
            json={
                "name": "Test Company",
                "sector": "Technology",
                "industry": "Software",
                "metrics": {"employees": 100},
                "location": "Buenos Aires, Argentina",
                "tech": ["Python", "JavaScript"],
            },
        )
        # FullContact: empresa encontrada
        .add(
            "POST",
            r"api\.fullcontact\.com/v3/company\.enrich",
            json={
                "name": "Test Company",
                "sector": "Technology",
                "industry": "Software",
                "employees": 100,
                "location": "Buenos Aires, Argentina",
            },
        )
    )


async def test_opencorporates_encuentra_empresa(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await OpenCorporatesCollector().collect("Test Company")
    assert result.metadata["ok"] is True
    assert result.metadata["companies_found"] >= 1
    org_names = [e.value for e in result.entities if e.type.value == "ORGANIZATION"]
    assert "Test Company S.A." in org_names


async def test_opencorporates_encuentra_directores(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await OpenCorporatesCollector().collect("Test Company")
    assert result.metadata["ok"] is True
    # Verificar que hay relaciones de directores
    assert len(result.relations) >= 1


async def test_gleif_encuentra_registro(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await GLEIFCollector().collect("Test Company")
    assert result.metadata["ok"] is True
    assert result.metadata["records_found"] >= 1
    org_names = [e.value for e in result.entities if e.type.value == "ORGANIZATION"]
    assert "Test Company S.A." in org_names


async def test_clearbit_requiere_key(monkeypatch) -> None:
    """Verifica que Clearbit requiere API key."""
    patch_httpx(monkeypatch, _router())
    result = await ClearbitCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_key"] == "clearbit_api_key"


async def test_fullcontact_requiere_key(monkeypatch) -> None:
    """Verifica que FullContact requiere API key."""
    patch_httpx(monkeypatch, _router())
    result = await FullContactCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_key"] == "fullcontact_api_key"


async def test_opencorporates_maneja_error_red(monkeypatch) -> None:
    """Verifica que un error de red no rompe el colector."""
    router = MockRouter()  # Sin rutas = 599
    patch_httpx(monkeypatch, router)
    result = await OpenCorporatesCollector().collect("error")
    assert result.metadata["ok"] is False


async def test_gleif_maneja_error_red(monkeypatch) -> None:
    """Verifica que un error de red no rompe el colector."""
    router = MockRouter()  # Sin rutas = 599
    patch_httpx(monkeypatch, router)
    result = await GLEIFCollector().collect("error")
    assert result.metadata["ok"] is False

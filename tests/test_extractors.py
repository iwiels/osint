"""
Tests de extractores de inteligencia: emails, teléfonos, nombres, hashes, CC, IBAN.
Sin red real (httpx mockeado).
"""

from __future__ import annotations

import httpx
import pytest
from http_mock import MockRouter, patch_network
from specter.collectors.extractors import (
    CreditCardExtractorCollector,
    EmailExtractorCollector,
    HashExtractorCollector,
    IBANExtractorCollector,
    NameExtractorCollector,
    PhoneExtractorCollector,
    _luhn_check,
    _validate_iban,
)
from specter.osint_core.models import EntityType


def _mock_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]) -> None:
    """Desactiva NetGuard para que los tests no bloqueen las peticiones."""
    monkeypatch.setenv("SPECTER_SSRF_ENFORCE", "0")


def _router() -> MockRouter:
    return MockRouter().add(
        "GET",
        r"ejemplo\.test",
        text="""
        <html><body>
        <p>Contacto: juan.perez@ejemplo.com, maria@empresa.org</p>
        <p>Teléfono: +34 612 345 678, +1-555-123-4567</p>
        <p>Persona: Juan Pérez García</p>
        <p>Hash: 5d41402abc4b2a76b9719d911017c592</p>
        <p>Tarjeta: 4532015112830366</p>
        <p>IBAN: ES9121000418450200051332</p>
        </body></html>
        """,
        headers={"content-type": "text/html"},
    )


def test_luhn_valido() -> None:
    assert _luhn_check("4532015112830366") is True
    assert _luhn_check("4532-0151-1283-0366") is True
    assert _luhn_check("4532015112830367") is False


def test_iban_valido() -> None:
    assert _validate_iban("ES9121000418450200051332") is True
    assert _validate_iban("DE89370400440532013000") is True
    assert _validate_iban("ES9121000418450200051333") is False


@pytest.mark.asyncio
async def test_email_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _router())

    result = await EmailExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["emails_found"] == 2
    emails = [e.value for e in result.entities]
    assert "juan.perez@ejemplo.com" in emails
    assert "maria@empresa.org" in emails
    assert all(e.type == EntityType.EMAIL for e in result.entities)


@pytest.mark.asyncio
async def test_email_extractor_texto_directo() -> None:
    result = await EmailExtractorCollector().collect("Contacto: test@dominio.com")

    assert result.metadata["ok"] is True
    assert result.metadata["emails_found"] == 1
    assert result.entities[0].value == "test@dominio.com"


@pytest.mark.asyncio
async def test_email_extractor_error_red(monkeypatch) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("caído", request=request)

    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, MockRouter().add_responder("GET", r"ejemplo\.test", boom))

    result = await EmailExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is False
    assert "caído" in result.metadata["error"]


@pytest.mark.asyncio
async def test_phone_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _router())

    result = await PhoneExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["phones_found"] >= 1
    phones = [e.value for e in result.entities]
    assert any("+34" in p for p in phones)
    assert all(e.type == EntityType.PHONE for e in result.entities)


@pytest.mark.asyncio
async def test_phone_extractor_texto_directo() -> None:
    result = await PhoneExtractorCollector().collect("Llama al +34 612 345 678")

    assert result.metadata["ok"] is True
    assert result.metadata["phones_found"] == 1


@pytest.mark.asyncio
async def test_name_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _router())

    result = await NameExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["names_found"] >= 1
    names = [e.value for e in result.entities]
    assert any("Juan" in n for n in names)
    assert all(e.type == EntityType.PERSON for e in result.entities)


@pytest.mark.asyncio
async def test_name_extractor_texto_directo() -> None:
    result = await NameExtractorCollector().collect("El señor Juan Pérez García asistió.")

    assert result.metadata["ok"] is True
    assert result.metadata["names_found"] >= 1


@pytest.mark.asyncio
async def test_hash_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _router())

    result = await HashExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["hashes_found"] >= 1
    hashes = [e.value for e in result.entities]
    assert "5d41402abc4b2a76b9719d911017c592" in hashes
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_hash_extractor_texto_directo() -> None:
    result = await HashExtractorCollector().collect("MD5: 5d41402abc4b2a76b9719d911017c592")

    assert result.metadata["ok"] is True
    assert result.metadata["hashes_found"] == 1


@pytest.mark.asyncio
async def test_creditcard_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _router())

    result = await CreditCardExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["cards_found"] == 1
    assert result.entities[0].value == "4532015112830366"
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_creditcard_extractor_texto_directo() -> None:
    result = await CreditCardExtractorCollector().collect("Tarjeta: 4532015112830366")

    assert result.metadata["ok"] is True
    assert result.metadata["cards_found"] == 1


@pytest.mark.asyncio
async def test_creditcard_extractor_rechaza_invalido() -> None:
    result = await CreditCardExtractorCollector().collect("Tarjeta: 1234567890123456")

    assert result.metadata["ok"] is True
    assert result.metadata["cards_found"] == 0


@pytest.mark.asyncio
async def test_iban_extractor(monkeypatch) -> None:
    _mock_dns(monkeypatch, {"ejemplo.test": ["93.184.215.14"]})
    patch_network(monkeypatch, _router())

    result = await IBANExtractorCollector().collect("https://ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["ibans_found"] == 1
    assert result.entities[0].value == "ES9121000418450200051332"
    assert all(e.type == EntityType.ALIAS for e in result.entities)


@pytest.mark.asyncio
async def test_iban_extractor_texto_directo() -> None:
    result = await IBANExtractorCollector().collect("IBAN: ES9121000418450200051332")

    assert result.metadata["ok"] is True
    assert result.metadata["ibans_found"] == 1


@pytest.mark.asyncio
async def test_iban_extractor_rechaza_invalido() -> None:
    result = await IBANExtractorCollector().collect("IBAN: ES9121000418450200051333")

    assert result.metadata["ok"] is True
    assert result.metadata["ibans_found"] == 0

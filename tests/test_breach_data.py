"""
Tests de los colectores de brechas de datos (HIBP, LeakLookup, LeakIX,
IntelligenceX). Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.breach_data import (
    HaveIBeenPwnedCollector,
    IntelligenceXCollector,
    LeakIXCollector,
    LeakLookupCollector,
)
from specter.osint_core.models import EntityType

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        # --- HIBP ---
        .add(
            "GET",
            r"haveibeenpwned\.com/api/v3/breachedaccount/victim",
            json=[
                {
                    "Name": "TestBreach",
                    "Title": "Test Breach 2024",
                    "Domain": "test.com",
                    "BreachDate": "2024-01-01",
                    "PwnCount": 1000,
                    "DataClasses": ["Emails", "Passwords"],
                    "IsVerified": True,
                }
            ],
        )
        .add(
            "GET",
            r"haveibeenpwned\.com/api/v3/breachedaccount/clean",
            status_code=404,
            json={},
        )
        # --- LeakLookup ---
        .add(
            "GET",
            r"leak-lookup\.com/api/search",
            json={
                "results": [
                    {"name": "LeakA", "date": "2023-01-01"},
                    {"name": "LeakB", "date": "2023-06-01"},
                ]
            },
        )
        # --- LeakIX ---
        .add(
            "GET",
            r"leakix\.net/search",
            text="""
            <html><body>
            <table>
              <tr><td>443</td><td>https</td></tr>
              <tr><td>80</td><td>http</td></tr>
            </table>
            <table>
              <tr><td>TestLeak</td><td>2024-01-01</td></tr>
            </table>
            </body></html>
            """,
        )
        # --- IntelligenceX ---
        .add(
            "GET",
            r"intelx\.io/search",
            text="""
            <html><body>
            <div class="result"><a href="/view/123">Breach Result Alpha</a></div>
            <div class="result"><a href="/view/456">Breach Result Beta</a></div>
            </body></html>
            """,
        )
    )


async def test_hibp_requiere_key_sin_configurar(monkeypatch) -> None:
    """Sin hibp_api_key, el colector retorna requires_key."""
    patch_httpx(monkeypatch, _router())
    result = await HaveIBeenPwnedCollector().collect("victim@test.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_key"] == "hibp_api_key"


async def test_hibp_con_key_encuentra_brechas(monkeypatch) -> None:
    """Con key configurada, HIBP retorna entidades EMAIL y BREACH."""
    patch_httpx(monkeypatch, _router())
    monkeypatch.setenv("HIBP_API_KEY", "test-key-123")
    result = await HaveIBeenPwnedCollector().collect("victim@test.com")
    assert result.metadata["ok"] is True
    assert result.metadata["pwned"] is True
    assert result.metadata["breaches"] == 1
    email_nodes = [e for e in result.entities if e.type == EntityType.EMAIL]
    breach_nodes = [e for e in result.entities if e.type == EntityType.BREACH]
    assert len(email_nodes) == 1
    assert len(breach_nodes) == 1
    assert breach_nodes[0].value == "TestBreach"


async def test_hibp_404_sin_brechas(monkeypatch) -> None:
    """404 en HIBP = sin brechas conocidas (no es error)."""
    patch_httpx(monkeypatch, _router())
    monkeypatch.setenv("HIBP_API_KEY", "test-key-123")
    result = await HaveIBeenPwnedCollector().collect("clean@test.com")
    assert result.metadata["ok"] is True
    assert result.metadata["pwned"] is False
    assert result.metadata["breaches"] == 0


async def test_leaklookup_extrae_brechas(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await LeakLookupCollector().collect("victim@test.com")
    assert result.metadata["ok"] is True
    assert result.metadata["breaches"] == 2
    values = [e.value for e in result.entities]
    assert "LeakA" in values
    assert "LeakB" in values


async def test_leakix_extrae_puertos_y_brechas(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await LeakIXCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["ports"] >= 1
    assert result.metadata["breaches"] >= 1


async def test_intelligencex_extrae_resultados(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await IntelligenceXCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["results"] == 2
    values = [e.value for e in result.entities]
    assert "Breach Result Alpha" in values
    assert "Breach Result Beta" in values


async def test_colectores_brecha_sobreviven_a_error_de_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    for collector, target in (
        (LeakLookupCollector(), "victim@test.com"),
        (LeakIXCollector(), "ejemplo.test"),
        (IntelligenceXCollector(), "ejemplo.test"),
    ):
        result = await collector.collect(target)
        assert result.metadata["ok"] is False, collector.name

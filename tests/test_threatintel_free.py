"""
Tests de los colectores ThreatIntel gratuitos adicionales.
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.threatintel_free import (
    AlienVaultOTXCollector,
    BlocklistCollector,
    DroneBLCollector,
    MalwarePatrolCollector,
    OpenPhishCollector,
    PhishTankCollector,
    SpamhausCollector,
    ThreatCrowdCollector,
    ThreatMinerCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        # AlienVault OTX
        .add(
            "GET",
            r"otx\.alienvault\.com/api/v1/indicators/hostname/ejemplo\.test",
            json={
                "pulse_info": {
                    "count": 2,
                    "pulses": [
                        {"id": "abc123", "name": "Malware Campaign", "created": "2026-01-01"},
                        {"id": "def456", "name": "Phishing Wave", "created": "2026-01-02"},
                    ],
                },
                "url_list": [
                    {"url": "http://ejemplo.test/login", "date": "2026-01-01"},
                    {"url": "http://ejemplo.test/admin", "date": "2026-01-02"},
                ],
            },
        )
        # ThreatCrowd
        .add(
            "GET",
            r"threatcrowd\.org/searchApi/v2/domain/report",
            json={
                "response_code": "1",
                "votes": -1,
                "urls": ["http://ejemplo.test/malware", "http://ejemplo.test/phish"],
                "emails": ["admin@ejemplo.test"],
            },
        )
        # ThreatMiner
        .add(
            "GET",
            r"api\.threatminer\.org/v2/domain\.php",
            json={
                "status_code": "200",
                "results": ["sub1.ejemplo.test", "sub2.ejemplo.test", "sub3.ejemplo.test"],
            },
        )
        # PhishTank
        .add(
            "POST",
            r"checkurl\.phishtank\.com/checkurl",
            json={
                "in_database": True,
                "valid": True,
                "phish_id": "12345",
            },
        )
        # OpenPhish
        .add(
            "GET",
            r"openphish\.com/feed\.txt",
            text="http://ejemplo.test/login\nhttp://other.com/phish\nhttp://ejemplo.test/admin",
        )
        # MalwarePatrol
        .add(
            "GET",
            r"malwarepatrol\.net/cgi-bin/download\.cgi",
            text="# Lista de dominios maliciosos\nejemplo.test\n# Fin",
        )
        # Spamhaus
        .add(
            "GET",
            r"api\.spamhaus\.org/api/v1/zen/1\.2\.3\.4",
            json={"listed": True, "lists": ["SBL", "XBL"]},
        )
        # Blocklist.de
        .add(
            "GET",
            r"lists\.blocklist\.de/lists/all\.txt",
            text="1.2.3.4\n5.6.7.8\n9.10.11.12",
        )
        # DroneBL
        .add(
            "GET",
            r"dronebl\.org/api/lookup",
            json={"listed": True, "categories": ["spam", "botnet"]},
        )
    )


async def test_alienvault_otx_pulsos_y_urls(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await AlienVaultOTXCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["pulses"] == 2
    values = [e.value for e in result.entities]
    assert "Malware Campaign" in values
    assert "http://ejemplo.test/login" in values


async def test_threatcrowd_votos_y_emails(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await ThreatCrowdCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["found"] is True
    values = [e.value for e in result.entities]
    assert "http://ejemplo.test/malware" in values
    assert "admin@ejemplo.test" in values


async def test_threatminer_subdominios(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await ThreatMinerCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["subdomains"] == 3
    values = [e.value for e in result.entities]
    assert "sub1.ejemplo.test" in values
    assert "sub2.ejemplo.test" in values


async def test_phishtank_detecta_phishing(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await PhishTankCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["phishing"] is True


async def test_openphish_urls_activas(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await OpenPhishCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["matches"] == 2
    values = [e.value for e in result.entities]
    assert "http://ejemplo.test/login" in values
    assert "http://ejemplo.test/admin" in values


async def test_malwarepatrol_listado(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await MalwarePatrolCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["listed"] is True


async def test_spamhaus_listado(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await SpamhausCollector().collect("1.2.3.4")
    assert result.metadata["ok"] is True
    assert result.metadata["listed"] is True


async def test_blocklist_de_listado(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await BlocklistCollector().collect("1.2.3.4")
    assert result.metadata["ok"] is True
    assert result.metadata["listed"] is True


async def test_dronebl_listado(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await DroneBLCollector().collect("1.2.3.4")
    assert result.metadata["ok"] is True
    assert result.metadata["listed"] is True


async def test_colectores_sobreviven_a_error_de_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    for collector, target in (
        (AlienVaultOTXCollector(), "ejemplo.test"),
        (ThreatCrowdCollector(), "ejemplo.test"),
        (ThreatMinerCollector(), "ejemplo.test"),
        (PhishTankCollector(), "ejemplo.test"),
        (OpenPhishCollector(), "ejemplo.test"),
        (MalwarePatrolCollector(), "ejemplo.test"),
        (SpamhausCollector(), "1.2.3.4"),
        (BlocklistCollector(), "1.2.3.4"),
        (DroneBLCollector(), "1.2.3.4"),
    ):
        result = await collector.collect(target)
        assert result.metadata["ok"] is False, collector.name


async def test_ips_privadas_omitidas(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    for collector in (SpamhausCollector(), BlocklistCollector(), DroneBLCollector()):
        result = await collector.collect("10.0.0.1")
        assert result.metadata["ok"] is False

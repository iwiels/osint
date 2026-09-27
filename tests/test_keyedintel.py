"""
Tests de los colectores Fase B (API keys vía env/bóveda) y del gate por key.
Sin key -> omisión limpia (requires_key); el agente ni lo intenta.
Red 100% mockeada.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.threatintel import (
    AbuseIPDBCollector,
    GreyNoiseCollector,
    HunterCollector,
    ShodanCollector,
    VirusTotalCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        .add(
            "GET",
            r"virustotal\.com/api/v3/ip_addresses/1\.2\.3\.4",
            json={
                "data": {
                    "attributes": {
                        "reputation": -10,
                        "country": "US",
                        "as_owner": "ExampleNet",
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 1,
                            "harmless": 70,
                        },
                    }
                }
            },
        )
        .add(
            "GET",
            r"virustotal\.com/api/v3/domains/ejemplo\.test",
            json={"data": {"attributes": {"reputation": 0, "last_analysis_stats": {}}}},
        )
        .add(
            "GET",
            r"api\.shodan\.io/shodan/host/1\.2\.3\.4",
            json={
                "ip_str": "1.2.3.4",
                "ports": [22, 443],
                "org": "ExampleOrg",
                "isp": "ExampleISP",
                "country_name": "United States",
                "hostnames": ["h.ejemplo.test"],
                "vulns": {"CVE-2024-0001": {}},
            },
        )
        .add(
            "GET",
            r"api\.shodan\.io/shodan/host/search",
            json={"total": 1, "matches": [{"ip_str": "5.6.7.8"}]},
        )
        .add(
            "GET",
            r"api\.greynoise\.io/v3/community/1\.2\.3\.4",
            json={
                "ip": "1.2.3.4",
                "noise": True,
                "riot": False,
                "classification": "malicious",
                "name": "Test Scanner",
                "link": "https://viz.greynoise.io/riot/1.2.3.4",
                "last_seen": "2026-01-01",
            },
        )
        .add(
            "GET",
            r"api\.abuseipdb\.com/api/v2/check",
            json={
                "data": {
                    "abuseConfidenceScore": 87,
                    "totalReports": 12,
                    "countryCode": "US",
                    "usageType": "Data Center",
                    "isp": "ExampleISP",
                    "domain": "ejemplo.test",
                }
            },
        )
        .add(
            "GET",
            r"api\.hunter\.io/v2/email-verifier",
            json={"data": {"status": "valid", "score": 92, "_regexp": True}},
        )
        .add(
            "GET",
            r"api\.hunter\.io/v2/domain-search",
            json={
                "data": {
                    "emails": [
                        {
                            "value": "ana@ejemplo.test",
                            "first_name": "Ana",
                            "last_name": "López",
                            "position": "CTO",
                            "confidence": 95,
                        }
                    ]
                }
            },
        )
    )


async def test_sin_key_se_omiten_en_silencio(monkeypatch) -> None:
    """Sin env ni bóveda: requires_key, sin tocar la red."""
    for collector, target in (
        (VirusTotalCollector(), "1.2.3.4"),
        (ShodanCollector(), "1.2.3.4"),
        (GreyNoiseCollector(), "1.2.3.4"),
        (AbuseIPDBCollector(), "1.2.3.4"),
        (HunterCollector(), "ana@ejemplo.test"),
    ):
        for var in (
            "VIRUSTOTAL_API_KEY",
            "SHODAN_API_KEY",
            "GREYNOISE_API_KEY",
            "ABUSEIPDB_API_KEY",
            "HUNTER_API_KEY",
        ):
            monkeypatch.delenv(var, raising=False)
        result = await collector.collect(target)
        assert result.metadata["ok"] is False
        assert result.metadata["requires_key"].endswith("_api_key")


async def test_virustotal_ip_con_reputacion(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    patch_httpx(monkeypatch, _router())
    result = await VirusTotalCollector().collect("1.2.3.4")
    assert result.metadata == {"ok": True, "malicious": 5}
    node = result.entities[0]
    assert node.attributes["as_owner"] == "ExampleNet"
    assert node.confidence == 0.9


async def test_shodan_host_y_favicon_search(monkeypatch) -> None:
    monkeypatch.setenv("SHODAN_API_KEY", "sh-test")
    patch_httpx(monkeypatch, _router())
    host = await ShodanCollector().collect("1.2.3.4")
    assert host.metadata == {"ok": True, "ports": 2}
    assert "h.ejemplo.test" in [e.value for e in host.entities]

    fav = await ShodanCollector().collect("ejemplo.test", favicon_hash=-761616281)
    assert fav.metadata == {"ok": True, "matches": 1}
    assert fav.entities[0].value == "5.6.7.8"
    assert fav.entities[0].attributes["favicon_mmh3"] == -761616281


async def test_greynoise_y_abuseipdb(monkeypatch) -> None:
    monkeypatch.setenv("GREYNOISE_API_KEY", "gn-test")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-test")
    patch_httpx(monkeypatch, _router())
    gn = await GreyNoiseCollector().collect("1.2.3.4")
    assert gn.metadata == {"ok": True, "noise": True}
    assert gn.entities[0].attributes["classification"] == "malicious"
    ab = await AbuseIPDBCollector().collect("1.2.3.4")
    assert ab.metadata == {"ok": True, "abuse_score": 87}
    assert ab.entities[0].confidence == 0.85


async def test_hunter_verifica_email_y_cosecha_dominio(monkeypatch) -> None:
    monkeypatch.setenv("HUNTER_API_KEY", "hu-test")
    patch_httpx(monkeypatch, _router())
    email = await HunterCollector().collect("ana@ejemplo.test")
    assert email.metadata == {"ok": True, "status": "valid"}
    domain = await HunterCollector().collect("ejemplo.test")
    assert domain.metadata == {"ok": True, "emails": 1}
    node = next(e for e in domain.entities if e.value == "ana@ejemplo.test")
    assert node.attributes["position"] == "CTO"

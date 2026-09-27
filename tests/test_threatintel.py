"""
Tests de los colectores ThreatIntel Fase A (fuentes gratuitas sin key).
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import json

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.threatintel import (
    HackertargetCollector,
    InternetDBCollector,
    ThreatFoxCollector,
    UrlscanCollector,
    WaybackCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        .add(
            "GET",
            r"internetdb\.shodan\.io/1\.2\.3\.4",
            json={
                "ip": "1.2.3.4",
                "ports": [80, 443],
                "cpes": ["cpe:/a:nginx:nginx:1.25"],
                "hostnames": ["mail.ejemplo.test"],
                "tags": ["web"],
                "vulns": ["CVE-2024-1234"],
            },
        )
        .add("GET", r"internetdb\.shodan\.io/9\.9\.9\.9", status_code=404, json={})
        .add(
            "POST",
            r"threatfox-api\.abuse\.ch",
            json={
                "query_status": "ok",
                "data": [
                    {
                        "ioc": "1.2.3.4",
                        "threat_type": "botnet_cc",
                        "malware": "Emotet",
                        "confidence_level": "high",
                        "reporter": "abusech",
                        "first_seen": "2026-01-01 00:00:00",
                    }
                ],
            },
        )
        .add(
            "GET",
            r"urlscan\.io/api/v1/search",
            json={
                "total": 1,
                "results": [
                    {
                        "task": {"url": "http://ejemplo.test/login"},
                        "page": {
                            "url": "http://ejemplo.test/login",
                            "ip": "1.2.3.4",
                            "country": "AR",
                        },
                    }
                ],
            },
        )
        .add(
            "GET",
            r"api\.hackertarget\.com/reverseiplookup",
            text="a.ejemplo.test\nb.ejemplo.test\n",
        )
        .add(
            "GET",
            r"web\.archive\.org/cdx",
            json=[
                ["timestamp", "original", "statuscode", "mimetype"],
                ["20200101000000", "http://ejemplo.test/", "200", "text/html"],
                ["20210101000000", "http://ejemplo.test/admin/", "200", "text/html"],
                ["20220101000000", "http://ejemplo.test/app.bak", "200", "application/zip"],
            ],
        )
    )


async def test_internetdb_expone_puertos_y_cves(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await InternetDBCollector().collect("1.2.3.4")
    assert result.metadata["ok"] is True
    assert result.metadata["ports"] == 2
    values = [e.value for e in result.entities]
    assert "1.2.3.4" in values and "mail.ejemplo.test" in values
    assert "CVE-2024-1234" in values


async def test_internetdb_404_y_privada_sin_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    missing = await InternetDBCollector().collect("9.9.9.9")
    assert missing.metadata["ok"] is True and missing.metadata["present"] is False
    skipped = await InternetDBCollector().collect("10.0.0.1")
    assert skipped.metadata["ok"] is False  # privada: ni se consulta


async def test_threatfox_marca_malware_con_confianza(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await ThreatFoxCollector().collect("1.2.3.4")
    assert result.metadata["ok"] is True and result.metadata["malicious"] is True
    fams = [e for e in result.entities if e.value == "Emotet"]
    assert len(fams) == 1 and fams[0].confidence == 0.9


async def test_threatfox_sin_resultado_no_es_error(monkeypatch) -> None:
    router = MockRouter().add("POST", r"threatfox", json={"query_status": "no_result", "data": []})
    patch_httpx(monkeypatch, router)
    result = await ThreatFoxCollector().collect("limpio.test")
    assert result.metadata == {"ok": True, "malicious": False}


async def test_urlscan_observa_urls_e_ips(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await UrlscanCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    values = [e.value for e in result.entities]
    assert "http://ejemplo.test/login" in values and "1.2.3.4" in values


async def test_hackertarget_cohospedaje(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await HackertargetCollector().collect("1.2.3.4")
    assert result.metadata == {"ok": True, "cohosted": 2}
    assert {e.value for e in result.entities} >= {"1.2.3.4", "a.ejemplo.test"}


async def test_wayback_historial_y_rutas_sensibles(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await WaybackCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["snapshots"] == 3
    # Las 3 matchean ("test" va en el propio dominio + admin + bak).
    assert result.metadata["interesting_urls"] == 3
    payload = json.loads(result.raw_payload)
    assert payload["first"] == "20200101000000" and payload["last"] == "20220101000000"


async def test_colectores_sobreviven_a_error_de_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    for collector, target in (
        (InternetDBCollector(), "1.2.3.4"),
        (ThreatFoxCollector(), "1.2.3.4"),
        (UrlscanCollector(), "ejemplo.test"),
        (HackertargetCollector(), "1.2.3.4"),
        (WaybackCollector(), "ejemplo.test"),
    ):
        result = await collector.collect(target)
        assert result.metadata["ok"] is False, collector.name

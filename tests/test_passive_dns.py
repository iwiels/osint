"""
Tests de los colectores Passive DNS (resolución histórica).
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.passive_dns import (
    CIRCLPassiveDNSCollector,
    DNSDBChecker,
    DNSGrepCollector,
    MnemonicPassiveDNSCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    circl_text = (
        '{"rrname": "ejemplo.test", "rrtype": "A", "rdata": "1.2.3.4",'
        ' "time_first": 1577836800, "time_last": 1704067200}\n'
        '{"rrname": "ejemplo.test", "rrtype": "NS", "rdata": "ns1.ejemplo.test",'
        ' "time_first": 1577836800, "time_last": 1704067200}\n'
    )
    dnsdb_text = (
        '{"count": 2, "time_first": 1577836800, "time_last": 1704067200}\n'
        '{"rrname": "ejemplo.test", "rrtype": "A", "rdata": "1.2.3.4",'
        ' "time_first": 1577836800, "time_last": 1704067200}\n'
        '{"rrname": "otro.test", "rrtype": "A", "rdata": "1.2.3.4",'
        ' "time_first": 1577836800, "time_last": 1704067200}\n'
    )
    return (
        MockRouter()
        .add(
            "GET",
            r"api\.dnsgrep\.com/v1/search/ejemplo\.test",
            json=[
                {
                    "name": "ejemplo.test",
                    "type": "A",
                    "ttl": 300,
                    "rdata": "1.2.3.4",
                    "first_seen": "2020-01-01",
                    "last_seen": "2024-01-01",
                },
                {
                    "name": "ejemplo.test",
                    "type": "MX",
                    "ttl": 300,
                    "rdata": "mail.ejemplo.test",
                    "first_seen": "2020-01-01",
                    "last_seen": "2024-01-01",
                },
            ],
        )
        .add(
            "GET",
            r"api\.mnemonic\.no/pdns/v3/ejemplo\.test",
            json={
                "responseCode": 200,
                "size": 2,
                "count": 2,
                "data": [
                    {
                        "query": "ejemplo.test",
                        "rrtype": "a",
                        "answer": "1.2.3.4",
                        "ttl": 300,
                        "lastSeenTimestamp": 1704067200000,
                    },
                    {
                        "query": "ejemplo.test",
                        "rrtype": "cname",
                        "answer": "alias.ejemplo.test",
                        "ttl": 300,
                        "lastSeenTimestamp": 1704067200000,
                    },
                ],
            },
        )
        .add("GET", r"circl\.lu/pdns/query/ejemplo\.test", text=circl_text)
        .add("GET", r"api\.dnsdb\.info/lookup/rdata/ip/1\.2\.3\.4", text=dnsdb_text)
    )


async def test_dnsgrep_resuelve_historial(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await DNSGrepCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["records"] == 2
    values = [e.value for e in result.entities]
    assert "1.2.3.4" in values
    assert "mail.ejemplo.test" in values


async def test_mnemonic_con_ttl_y_fechas(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await MnemonicPassiveDNSCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["records"] == 2
    values = [e.value for e in result.entities]
    assert "1.2.3.4" in values
    assert "alias.ejemplo.test" in values


async def test_circl_ndjson(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await CIRCLPassiveDNSCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["records"] == 2
    values = [e.value for e in result.entities]
    assert "1.2.3.4" in values
    assert "ns1.ejemplo.test" in values


async def test_dnsdb_requiere_key(monkeypatch) -> None:
    """Sin key: requires_key, sin tocar la red."""
    monkeypatch.delenv("DNSDB_API_KEY", raising=False)
    result = await DNSDBChecker().collect("1.2.3.4")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_key"] == "dnsdb_api_key"


async def test_dnsdb_con_key(monkeypatch) -> None:
    monkeypatch.setenv("DNSDB_API_KEY", "dnsdb-test")
    patch_httpx(monkeypatch, _router())
    result = await DNSDBChecker().collect("1.2.3.4")
    assert result.metadata["ok"] is True
    assert result.metadata["records"] == 2
    values = [e.value for e in result.entities]
    assert "ejemplo.test" in values
    assert "otro.test" in values


async def test_colectores_sobreviven_a_error_de_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    for collector, target in (
        (DNSGrepCollector(), "ejemplo.test"),
        (MnemonicPassiveDNSCollector(), "ejemplo.test"),
        (CIRCLPassiveDNSCollector(), "ejemplo.test"),
        (DNSDBChecker(), "1.2.3.4"),
    ):
        result = await collector.collect(target)
        assert result.metadata["ok"] is False, collector.name

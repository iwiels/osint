"""
Tests de los colectores de red (DNS, crt.sh, TLS y enriquecimiento IP).

Todo el tráfico sale del arnés en memoria: no hay resolución real ni sockets.
"""

from __future__ import annotations

import json
import socket
import ssl

import dns.resolver
import httpx
import pytest
from http_mock import MockRouter, patch_httpx, patch_network
from specter.collectors.network import CrtShCollector, DNSCollector, IPEnricher, TLSCollector
from specter.osint_core.models import EntityType, RelationType

DOMAIN_ZONE = {
    "example.com/A": ["93.184.216.34"],
    "example.com/AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
    "example.com/MX": ["mail.example.com"],
    "example.com/NS": ["ns1.example.com"],
    "example.com/TXT": ["v=spf1 -all"],
    "_dmarc.example.com/TXT": ["v=DMARC1; p=reject"],
    # SOA y CNAME quedan sin zona → NoAnswer (rama `continue`).
}


async def test_dns_collector_construye_entidades_y_relaciones(monkeypatch):
    _, fake_dns = patch_network(monkeypatch, MockRouter(), DOMAIN_ZONE)

    result = await DNSCollector().collect("Example.COM")

    values = {e.value for e in result.entities}
    assert "example.com" in values
    assert "93.184.216.34" in values
    assert "2606:2800:220:1:248:1893:25c8:1946" in values
    assert "v=DMARC1; p=reject" not in values  # el nodo DMARC lleva prefijo
    assert any(
        e.type == EntityType.DNS_RECORD and e.value.startswith("DMARC:") for e in result.entities
    )

    ip_nodes = [e for e in result.entities if e.type == EntityType.IP_ADDRESS]
    assert {n.attributes["version"] for n in ip_nodes} == {4, 6}

    resolves = [r for r in result.relations if r.relation_type == RelationType.RESOLVES_TO]
    assert len(resolves) == len(ip_nodes)
    assert result.metadata["total_entities_found"] == len(result.entities)

    payload = json.loads(result.raw_payload)
    assert payload["records"]["A"] == ["93.184.216.34"]
    assert payload["records"]["DMARC"] == ["v=DMARC1; p=reject"]
    assert "example.com/a" in fake_dns.queries
    assert "_dmarc.example.com/txt" in fake_dns.queries


async def test_dns_collector_registra_errores_por_tipo(monkeypatch):
    zone = {
        "example.com/A": dns.resolver.LifetimeTimeout(),
        "example.com/SOA": RuntimeError("servidor DNS caído"),
    }
    patch_network(monkeypatch, MockRouter(), zone)

    result = await DNSCollector().collect("example.com")

    payload = json.loads(result.raw_payload)
    assert "A" not in payload["records"]  # LifetimeTimeout se ignora en silencio
    assert "servidor DNS caído" in payload["records"]["SOA_error"]
    assert [e.type for e in result.entities] == [EntityType.DOMAIN]


async def test_crtsh_extrae_subdominios_y_normaliza_wildcards(monkeypatch):
    router = MockRouter().add(
        "GET",
        r"crt\.sh",
        json=[
            {"name_value": "*.example.com\nwww.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "example.com"},  # el dominio raíz no es subdominio
        ],
    )
    patch_httpx(monkeypatch, router)

    result = await CrtShCollector().collect("example.com")

    subs = {e.value for e in result.entities if e.type == EntityType.SUBDOMAIN}
    assert subs == {"www.example.com", "api.example.com"}
    assert result.metadata["subdomains_count"] == 2
    assert all(
        r.relation_type == RelationType.SUBDOMAIN_OF
        for r in result.relations
        if r.target_id == "domain:example.com"
    )
    assert router.count(r"crt\.sh") == 1


async def test_crtsh_respuesta_no_json_conserva_payload_crudo(monkeypatch):
    router = MockRouter().add("GET", r"crt\.sh", text="<html>rate limited</html>")
    patch_httpx(monkeypatch, router)

    result = await CrtShCollector().collect("example.com")

    assert result.raw_payload == "<html>rate limited</html>"
    assert result.metadata["subdomains_count"] == 0


async def test_crtsh_estado_no_200_sin_subdominios(monkeypatch):
    router = MockRouter().add("GET", r"crt\.sh", text="boom", status_code=503)
    patch_httpx(monkeypatch, router)

    result = await CrtShCollector().collect("example.com")

    assert result.metadata["subdomains_count"] == 0
    assert json.loads(result.raw_payload) == {"subdomains": []}


async def test_crtsh_error_de_transporte_queda_en_evidencia(monkeypatch):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sin ruta al host", request=request)

    patch_httpx(monkeypatch, MockRouter().add_responder("GET", r"crt\.sh", boom))

    result = await CrtShCollector().collect("example.com")

    assert "sin ruta al host" in json.loads(result.raw_payload)["error"]


CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Let's Encrypt"),),),
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Apr  1 00:00:00 2026 GMT",
}


class _FakeSocket:
    def __enter__(self) -> _FakeSocket:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class _FakeContext:
    def __init__(self, cert: dict | None = None, error: Exception | None = None) -> None:
        self._cert = cert
        self._error = error
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED

    def wrap_socket(self, sock: _FakeSocket, server_hostname: str | None = None):
        if self._error:
            raise self._error
        return _FakeSSLSocket(self._cert or {})


class _FakeSSLSocket(_FakeSocket):
    def __init__(self, cert: dict) -> None:
        self._cert = cert

    def getpeercert(self) -> dict:
        return self._cert


def _patch_tls(monkeypatch, context: _FakeContext) -> None:
    monkeypatch.setattr(ssl, "create_default_context", lambda *a, **k: context)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _FakeSocket())


async def test_tls_collector_extrae_certificado_e_emisor(monkeypatch):
    _patch_tls(monkeypatch, _FakeContext(cert=CERT))

    result = await TLSCollector().collect("example.com")

    cert = next(e for e in result.entities if e.type == EntityType.SSL_CERTIFICATE)
    assert cert.value == "tls:example.com"
    assert cert.attributes["sans"] == ["example.com", "www.example.com"]
    assert cert.attributes["valid_until"] == "Apr  1 00:00:00 2026 GMT"

    org = next(e for e in result.entities if e.type == EntityType.ORGANIZATION)
    assert org.value == "Let's Encrypt"
    assert org.attributes["role"] == "Certificate Authority"
    assert result.metadata["has_cert"] is True


async def test_tls_collector_degrada_sin_explotar(monkeypatch):
    _patch_tls(monkeypatch, _FakeContext(error=ssl.SSLError("handshake fallido")))

    result = await TLSCollector().collect("example.com")

    assert [e.type for e in result.entities] == [EntityType.DOMAIN]
    assert result.metadata["has_cert"] is False
    assert "handshake fallido" in json.loads(result.raw_payload)["error"]


async def test_ip_enricher_resuelve_ptr_y_rdap(monkeypatch):
    zone = {"4.3.2.1.in-addr.arpa/PTR": ["host.example.com"]}
    router = MockRouter().add(
        "GET",
        r"rdap\.arin\.net",
        json={"name": "EXAMPLE-NET", "country": "US", "handle": "NET-1"},
    )
    patch_network(monkeypatch, router, zone)

    result = await IPEnricher().collect("1.2.3.4")

    assert any(e.value == "host.example.com" for e in result.entities)
    org = next(e for e in result.entities if e.type == EntityType.ORGANIZATION)
    assert org.value == "EXAMPLE-NET"
    assert org.attributes["country"] == "US"
    assert result.metadata["ptr_records"] == 1
    assert any(r.relation_type == RelationType.HOSTED_ON for r in result.relations)


async def test_ip_enricher_sin_ptr_ni_rdap(monkeypatch):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("rdap no responde", request=request)

    patch_network(monkeypatch, MockRouter().add_responder("GET", r"rdap\.arin\.net", boom), {})

    result = await IPEnricher().collect("1.2.3.4")

    payload = json.loads(result.raw_payload)
    assert payload["ptr"] == []
    assert "rdap no responde" in payload["rdap_error"]
    assert [e.type for e in result.entities] == [EntityType.IP_ADDRESS]


@pytest.mark.parametrize("zone", [{}, None])
async def test_dns_collector_sin_zona_no_genera_registros(monkeypatch, zone):
    patch_network(monkeypatch, MockRouter(), zone)

    result = await DNSCollector().collect("example.com")

    payload = json.loads(result.raw_payload)
    assert payload["records"] == {}
    assert not result.relations


async def test_ip_enricher_asn_cymru_y_geo_ipapi(monkeypatch):
    zone = {"8.8.8.8.origin.asn.cymru.com/TXT": ['"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"']}
    router = (
        MockRouter()
        .add("GET", r"rdap\.arin\.net", status_code=404, json={})
        .add(
            "GET",
            r"ip-api\.com",
            json={
                "status": "success",
                "country": "United States",
                "city": "Mountain View",
                "lat": 37.4,
                "lon": -122.1,
                "isp": "Google",
                "org": "Google",
                "proxy": False,
                "hosting": True,
                "query": "8.8.8.8",
            },
        )
    )
    patch_network(monkeypatch, router, zone)

    result = await IPEnricher().collect("8.8.8.8")

    payload = json.loads(result.raw_payload)
    assert payload["asn"] == {"asn": "15169", "prefix": "8.8.8.0/24", "country": "US"}
    assert payload["geo"]["city"] == "Mountain View"
    asn = next(e for e in result.entities if e.type == EntityType.ASN)
    assert asn.value == "AS15169"
    geo = next(e for e in result.entities if e.type == EntityType.GEO_LOCATION)
    assert geo.value == "37.4,-122.1"

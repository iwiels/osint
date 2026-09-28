"""
Tests exhaustivos para los colectores ThreatIntel mejorados:
- ShodanCollector (API con key y fallback a InternetDB sin key)
- CensysCollector (Hosts, servicios, certificados SSL/TLS y degradación)
- VirusTotalCollector (Reputación de IP/dominio/hash y degradación)
- HaveIBeenPwnedCollector (Verificación de brechas y degradación)
- Soporte de calificación OTAN (Almirantazgo)
- Registro y descubribilidad en CollectorRegistry

Red 100% mockeada vía tests/http_mock.py: cero conexiones a internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.registry import CollectorRegistry
from specter.collectors.threatintel_enhanced import (
    CensysCollector,
    HaveIBeenPwnedCollector,
    ShodanCollector,
    VirusTotalCollector,
)
from specter.osint_core.models import EntityType, RelationType

pytestmark = pytest.mark.asyncio


def _enhanced_router() -> MockRouter:
    return (
        MockRouter()
        # --- Shodan InternetDB (Free public endpoint) ---
        .add(
            "GET",
            r"internetdb\.shodan\.io/1\.2\.3\.4",
            json={
                "ip": "1.2.3.4",
                "ports": [80, 443],
                "cpes": ["cpe:/a:nginx:nginx:1.25"],
                "hostnames": ["mail.ejemplo.test"],
                "tags": ["web", "cloud"],
                "vulns": ["CVE-2024-1234"],
            },
        )
        .add("GET", r"internetdb\.shodan\.io/9\.9\.9\.9", status_code=404, json={})
        # --- Shodan API REST (Keyed) ---
        .add(
            "GET",
            r"api\.shodan\.io/shodan/host/1\.2\.3\.4",
            json={
                "ip_str": "1.2.3.4",
                "ports": [22, 443],
                "asn": "AS15169",
                "org": "Google LLC",
                "isp": "Google",
                "os": "Linux 5.x",
                "country_name": "United States",
                "country_code": "US",
                "city": "Mountain View",
                "latitude": 37.4056,
                "longitude": -122.0775,
                "hostnames": ["dns.google"],
                "vulns": ["CVE-2021-44228"],
                "data": [
                    {
                        "port": 22,
                        "transport": "tcp",
                        "product": "OpenSSH",
                        "version": "8.2",
                        "data": "SSH-2.0-OpenSSH_8.2",
                    },
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "version": "1.20",
                        "data": "HTTP/1.1 200 OK",
                    },
                ],
            },
        )
        .add(
            "GET",
            r"api\.shodan\.io/shodan/host/search",
            json={"total": 1, "matches": [{"ip_str": "8.8.8.8"}]},
        )
        .add("GET", r"api\.shodan\.io/shodan/host/8\.8\.8\.8", status_code=404, json={})
        # --- Censys API v2 ---
        .add(
            "GET",
            r"search\.censys\.io/api/v2/hosts/1\.2\.3\.4",
            json={
                "code": 200,
                "status": "OK",
                "result": {
                    "ip": "1.2.3.4",
                    "autonomous_system": {"asn": 15169, "name": "Google LLC"},
                    "location": {
                        "country": "United States",
                        "city": "Dallas",
                        "coordinates": {"latitude": 32.7767, "longitude": -96.7970},
                    },
                    "services": [
                        {
                            "port": 443,
                            "service_name": "HTTPS",
                            "tls": {
                                "certificates": {
                                    "leaf_data": {
                                        "fingerprint_sha256": (
                                            "0123456789abcdef0123456789abcdef"
                                            "0123456789abcdef0123456789abcdef"
                                        ),
                                        "names": ["ejemplo.test", "api.ejemplo.test"],
                                        "issuer": {"common_name": ["Let's Encrypt Authority X3"]},
                                        "validity": {
                                            "start": "2026-01-01T00:00:00Z",
                                            "end": "2026-12-31T23:59:59Z",
                                        },
                                    }
                                }
                            },
                        },
                        {"port": 80, "service_name": "HTTP"},
                    ],
                },
            },
        )
        .add(
            "GET",
            r"search\.censys\.io/api/v2/certificates/search",
            json={
                "code": 200,
                "status": "OK",
                "result": {
                    "hits": [
                        {
                            "fingerprint_sha256": (
                                "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                            ),
                            "names": ["ejemplo.test"],
                            "issuer_dn": "CN=DigiCert Global Root CA",
                            "validity": {"start": "2025-01-01", "end": "2027-01-01"},
                        }
                    ]
                },
            },
        )
        .add("GET", r"search\.censys\.io/api/v2/hosts/9\.9\.9\.9", status_code=404, json={})
        # --- VirusTotal v3 ---
        .add(
            "GET",
            r"virustotal\.com/api/v3/ip_addresses/1\.2\.3\.4",
            json={
                "data": {
                    "attributes": {
                        "reputation": -25,
                        "country": "US",
                        "as_owner": "Google LLC",
                        "last_analysis_stats": {
                            "malicious": 8,
                            "suspicious": 2,
                            "harmless": 65,
                            "undetected": 10,
                        },
                        "categories": {"Forcepoint ThreatSeeker": "malicious"},
                        "resolutions": [{"hostname": "badhost.ejemplo.test"}],
                    }
                }
            },
        )
        .add(
            "GET",
            r"virustotal\.com/api/v3/domains/ejemplo\.test",
            json={
                "data": {
                    "attributes": {
                        "reputation": 10,
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 80,
                            "undetected": 5,
                        },
                        "categories": {},
                        "resolutions": [{"ip_address": "1.2.3.4"}],
                    }
                }
            },
        )
        .add("GET", r"virustotal\.com/api/v3/ip_addresses/9\.9\.9\.9", status_code=404, json={})
        # --- HaveIBeenPwned v3 ---
        .add(
            "GET",
            r"haveibeenpwned\.com/api/v3/breachedaccount/victim%40ejemplo\.test",
            json=[
                {
                    "Name": "Adobe",
                    "Title": "Adobe Creative Cloud",
                    "Domain": "adobe.com",
                    "BreachDate": "2013-10-04",
                    "AddedDate": "2013-12-04T00:00:00Z",
                    "PwnCount": 152445165,
                    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
                    "IsVerified": True,
                },
                {
                    "Name": "LinkedIn",
                    "Title": "LinkedIn 2016",
                    "Domain": "linkedin.com",
                    "BreachDate": "2016-05-18",
                    "AddedDate": "2016-05-21T00:00:00Z",
                    "PwnCount": 164000000,
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsVerified": True,
                },
            ],
        )
        .add(
            "GET",
            r"haveibeenpwned\.com/api/v3/breachedaccount/clean%40ejemplo\.test",
            status_code=404,
            json={},
        )
    )


# ---------------------------------------------------------------------------
# Tests: ShodanCollector (con key y fallback a InternetDB sin key)
# ---------------------------------------------------------------------------


async def test_shodan_sin_key_degrada_a_internetdb_free(monkeypatch) -> None:
    """Verifica que sin SHODAN_API_KEY ShodanCollector degrada automáticamente a InternetDB."""
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    patch_httpx(monkeypatch, _enhanced_router())

    collector = ShodanCollector()
    result = await collector.collect("1.2.3.4")

    assert result.metadata["ok"] is True
    assert result.metadata["degraded"] is True
    assert result.metadata["api_key_used"] is False
    assert result.metadata["source"] == "internetdb"
    assert result.metadata["ports"] == 2
    assert result.metadata["vulns"] == 1
    assert result.metadata["admiralty"] == "C"

    entity_types = {e.type for e in result.entities}
    assert EntityType.IP_ADDRESS in entity_types
    assert EntityType.CVE in entity_types
    assert EntityType.PORT in entity_types
    assert EntityType.DOMAIN in entity_types

    cve_nodes = [e for e in result.entities if e.type == EntityType.CVE]
    assert len(cve_nodes) == 1
    assert cve_nodes[0].value == "CVE-2024-1234"

    # Verificar relaciones
    rel_types = {r.relation_type for r in result.relations}
    assert RelationType.VULNERABLE_TO in rel_types
    assert RelationType.RUNS_PORT in rel_types
    assert RelationType.RESOLVES_TO in rel_types


async def test_shodan_con_key_extrae_grafo_completo(monkeypatch) -> None:
    """Verifica la consulta con SHODAN_API_KEY: IP, ASN, GEO, CVE, PORT y DOMAIN."""
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-secret-test-key")
    patch_httpx(monkeypatch, _enhanced_router())

    collector = ShodanCollector()
    result = await collector.collect("1.2.3.4")

    assert result.metadata["ok"] is True
    assert result.metadata["api_key_used"] is True
    assert result.metadata["degraded"] is False
    assert result.metadata["ports"] == 2
    assert result.metadata["vulns"] == 1
    assert result.metadata["admiralty"] == "C"

    # Verificar nodos
    nodes_by_type = {e.type: e for e in result.entities}
    assert EntityType.IP_ADDRESS in nodes_by_type
    assert EntityType.ASN in nodes_by_type
    assert EntityType.GEO_LOCATION in nodes_by_type
    assert EntityType.CVE in nodes_by_type
    assert EntityType.PORT in nodes_by_type

    asn_node = nodes_by_type[EntityType.ASN]
    assert asn_node.value == "AS15169"

    geo_node = nodes_by_type[EntityType.GEO_LOCATION]
    assert geo_node.value == "37.4056,-122.0775"
    assert "Mountain View" in geo_node.label

    # Verificar aristas: HOSTED_ON, LOCATED_IN, VULNERABLE_TO, RUNS_PORT
    rel_types = {r.relation_type for r in result.relations}
    assert RelationType.HOSTED_ON in rel_types
    assert RelationType.LOCATED_IN in rel_types
    assert RelationType.VULNERABLE_TO in rel_types
    assert RelationType.RUNS_PORT in rel_types
    assert RelationType.RESOLVES_TO in rel_types


async def test_shodan_favicon_hash_search(monkeypatch) -> None:
    """Búsqueda por favicon hash con API key."""
    monkeypatch.setenv("SHODAN_API_KEY", "shodan-key")
    patch_httpx(monkeypatch, _enhanced_router())

    collector = ShodanCollector()
    result = await collector.collect("ejemplo.test", favicon_hash=12345678)

    assert result.metadata["ok"] is True
    assert result.metadata["matches"] == 1
    assert result.entities[0].value == "8.8.8.8"
    assert result.entities[0].attributes["favicon_mmh3"] == 12345678


async def test_shodan_degradacion_ip_privada_y_404(monkeypatch) -> None:
    """IPs privadas se omiten limpiamente y 404 devuelve present=False."""
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    patch_httpx(monkeypatch, _enhanced_router())

    collector = ShodanCollector()
    private_res = await collector.collect("192.168.1.1")
    assert private_res.metadata["ok"] is False
    assert private_res.metadata["skipped"] == "IP no pública"

    not_found = await collector.collect("9.9.9.9")
    assert not_found.metadata["ok"] is True
    assert not_found.metadata["present"] is False


# ---------------------------------------------------------------------------
# Tests: CensysCollector
# ---------------------------------------------------------------------------


async def test_censys_degradacion_sin_keys(monkeypatch) -> None:
    """Sin credenciales CENSYS_API_ID / CENSYS_API_SECRET, retorna omisión limpia."""
    monkeypatch.delenv("CENSYS_API_ID", raising=False)
    monkeypatch.delenv("CENSYS_API_SECRET", raising=False)

    collector = CensysCollector()
    result = await collector.collect("1.2.3.4")

    assert result.metadata["ok"] is False
    assert "censys_api_id" in result.metadata["requires_key"]
    assert result.metadata["admiralty"] == "C"


async def test_censys_consulta_host_y_certificados(monkeypatch) -> None:
    """Consulta de host Censys: extrae certificados SSL, huella SHA256 y dominios."""
    monkeypatch.setenv("CENSYS_API_ID", "test-censys-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-censys-secret")
    patch_httpx(monkeypatch, _enhanced_router())

    collector = CensysCollector()
    result = await collector.collect("1.2.3.4")

    assert result.metadata["ok"] is True
    assert result.metadata["services"] == 2
    assert result.metadata["admiralty"] == "C"

    # Verificar entidades
    entity_types = {e.type for e in result.entities}
    assert EntityType.IP_ADDRESS in entity_types
    assert EntityType.SSL_CERTIFICATE in entity_types
    assert EntityType.DOMAIN in entity_types
    assert EntityType.ASN in entity_types

    cert = next(e for e in result.entities if e.type == EntityType.SSL_CERTIFICATE)
    assert cert.value.startswith("0123456789abcdef")
    assert cert.attributes["port"] == 443

    # Dominios asociados al cert
    domains = [e.value for e in result.entities if e.type == EntityType.DOMAIN]
    assert "ejemplo.test" in domains
    assert "api.ejemplo.test" in domains

    # Aristas
    rel_types = {r.relation_type for r in result.relations}
    assert RelationType.ASSOCIATED_WITH in rel_types
    assert RelationType.RESOLVES_TO in rel_types
    assert RelationType.HOSTED_ON in rel_types


async def test_censys_busqueda_certificados_por_dominio(monkeypatch) -> None:
    """Búsqueda de certificados por nombre de dominio en Censys."""
    monkeypatch.setenv("CENSYS_API_ID", "test-censys-id")
    monkeypatch.setenv("CENSYS_API_SECRET", "test-censys-secret")
    patch_httpx(monkeypatch, _enhanced_router())

    collector = CensysCollector()
    result = await collector.collect("ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["hits"] == 1
    assert any(e.type == EntityType.SSL_CERTIFICATE for e in result.entities)
    assert any(e.type == EntityType.DOMAIN for e in result.entities)


# ---------------------------------------------------------------------------
# Tests: VirusTotalCollector
# ---------------------------------------------------------------------------


async def test_virustotal_degradacion_sin_key(monkeypatch) -> None:
    """Sin VIRUSTOTAL_API_KEY, retorna omisión limpia sin errores."""
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    collector = VirusTotalCollector()
    result = await collector.collect("1.2.3.4")

    assert result.metadata["ok"] is False
    assert result.metadata["requires_key"] == "virustotal_api_key"
    assert result.metadata["admiralty"] == "C"


async def test_virustotal_reputacion_ip_y_dominio(monkeypatch) -> None:
    """Evaluación de reputación de seguridad para IP y dominio."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    patch_httpx(monkeypatch, _enhanced_router())

    collector = VirusTotalCollector()

    # Test IP maliciosa
    ip_res = await collector.collect("1.2.3.4")
    assert ip_res.metadata["ok"] is True
    assert ip_res.metadata["malicious"] == 8
    assert ip_res.metadata["suspicious"] == 2
    assert ip_res.metadata["reputation"] == -25
    assert ip_res.metadata["admiralty"] == "C"

    ip_node = ip_res.entities[0]
    assert ip_node.attributes["malicious"] == 8
    assert ip_node.attributes["as_owner"] == "Google LLC"
    assert ip_node.confidence == 0.9

    # Verificar resolución
    assert any(
        e.type == EntityType.DOMAIN and e.value == "badhost.ejemplo.test" for e in ip_res.entities
    )
    assert any(r.relation_type == RelationType.RESOLVES_TO for r in ip_res.relations)

    # Test Dominio limpio
    dom_res = await collector.collect("ejemplo.test")
    assert dom_res.metadata["ok"] is True
    assert dom_res.metadata["malicious"] == 0
    assert dom_res.metadata["reputation"] == 10
    assert any(e.type == EntityType.IP_ADDRESS and e.value == "1.2.3.4" for e in dom_res.entities)


# ---------------------------------------------------------------------------
# Tests: HaveIBeenPwnedCollector
# ---------------------------------------------------------------------------


async def test_haveibeenpwned_degradacion_sin_key(monkeypatch) -> None:
    """Sin HIBP_API_KEY, degrada limpiamente informando key faltante."""
    monkeypatch.delenv("HIBP_API_KEY", raising=False)

    collector = HaveIBeenPwnedCollector()
    result = await collector.collect("victim@ejemplo.test")

    assert result.metadata["ok"] is False
    assert result.metadata["requires_key"] == "hibp_api_key"
    assert result.metadata["admiralty"] == "C"


async def test_haveibeenpwned_valida_formato_email() -> None:
    """Si el objetivo no es un email, lo rechaza sin consultar la red."""
    collector = HaveIBeenPwnedCollector()
    result = await collector.collect("not-an-email-target")

    assert result.metadata["ok"] is False
    assert "email" in result.metadata["error"]


async def test_haveibeenpwned_correo_limpio_404(monkeypatch) -> None:
    """Un email no encontrado en brechas retorna pwned=False y 0 brechas."""
    monkeypatch.setenv("HIBP_API_KEY", "hibp-test-key")
    patch_httpx(monkeypatch, _enhanced_router())

    collector = HaveIBeenPwnedCollector()
    result = await collector.collect("clean@ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["pwned"] is False
    assert result.metadata["breaches"] == 0
    assert result.metadata["admiralty"] == "C"

    email_node = result.entities[0]
    assert email_node.type == EntityType.EMAIL
    assert email_node.attributes["pwned"] is False


async def test_haveibeenpwned_correo_expuesto(monkeypatch) -> None:
    """Un email expuesto genera nodos BREACH y aristas EXPOSED_IN."""
    monkeypatch.setenv("HIBP_API_KEY", "hibp-test-key")
    patch_httpx(monkeypatch, _enhanced_router())

    collector = HaveIBeenPwnedCollector()
    result = await collector.collect("victim@ejemplo.test")

    assert result.metadata["ok"] is True
    assert result.metadata["pwned"] is True
    assert result.metadata["breaches"] == 2
    assert result.metadata["admiralty"] == "C"

    # Verificar entidades
    email_node = next(e for e in result.entities if e.type == EntityType.EMAIL)
    assert email_node.attributes["pwned"] is True
    assert email_node.attributes["breach_count"] == 2

    breach_nodes = [e for e in result.entities if e.type == EntityType.BREACH]
    assert len(breach_nodes) == 2
    breach_names = {b.value for b in breach_nodes}
    assert "Adobe" in breach_names
    assert "LinkedIn" in breach_names

    # Verificar aristas EXPOSED_IN
    exposed_relations = [r for r in result.relations if r.relation_type == RelationType.EXPOSED_IN]
    assert len(exposed_relations) == 2
    assert all(r.source_id == email_node.id for r in exposed_relations)


# ---------------------------------------------------------------------------
# Tests: Resiliencia ante caídas de red y errores
# ---------------------------------------------------------------------------


async def test_colectores_sobreviven_a_fallo_de_red(monkeypatch) -> None:
    """Ningún colector debe tumbar el proceso si la red falla o responde con error."""
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    monkeypatch.setenv("CENSYS_API_ID", "test")
    monkeypatch.setenv("CENSYS_API_SECRET", "test")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test")
    monkeypatch.setenv("HIBP_API_KEY", "test")

    # Router vacío -> todas las peticiones devuelven 599
    patch_httpx(monkeypatch, MockRouter())

    for collector, target in (
        (ShodanCollector(), "1.2.3.4"),
        (CensysCollector(), "1.2.3.4"),
        (VirusTotalCollector(), "1.2.3.4"),
        (HaveIBeenPwnedCollector(), "user@ejemplo.test"),
    ):
        result = await collector.collect(target)
        assert result.metadata["ok"] is False, f"Collector {collector.name} falló inesperadamente"
        assert "error" in result.metadata


# ---------------------------------------------------------------------------
# Tests: Registro y descubribilidad en CollectorRegistry
# ---------------------------------------------------------------------------


async def test_registro_y_descubrimiento_de_colectores_mejorados() -> None:
    """Verifica que los colectores se registran y descubren en CollectorRegistry."""
    registry = CollectorRegistry()
    registry.register_enhanced_collectors()

    names = registry.names()
    assert "shodan" in names
    assert "censys" in names
    assert "virustotal" in names
    assert "haveibeenpwned" in names

    assert isinstance(registry.get("shodan"), ShodanCollector)
    assert isinstance(registry.get("censys"), CensysCollector)
    assert isinstance(registry.get("virustotal"), VirusTotalCollector)
    assert isinstance(registry.get("haveibeenpwned"), HaveIBeenPwnedCollector)

    for item in registry.describe():
        assert item["kind"] == "builtin"

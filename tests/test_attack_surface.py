"""
Tests para AttackSurfaceCollector: agregación multi-fuente pasiva de subdominios,
sanitización, resolución DNS concurrente, integración con herramientas CLI y aristas en el grafo.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import dns.resolver
import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.attack_surface import AttackSurfaceCollector, is_valid_subdomain
from specter.collectors.registry import CollectorRegistry, default_registry
from specter.osint_core.models import EntityType, RelationType


class MockAsyncResolver:
    """Resolver DNS asíncrono para tests."""

    def __init__(self, zone: dict[str, list[str]] | None = None):
        self.zone = {k.lower(): v for k, v in (zone or {}).items()}
        self.queries: list[tuple[str, str]] = []

    async def resolve(self, qname: str, rdtype: str = "A", **kwargs: Any) -> list[Any]:
        clean_name = str(qname).rstrip(".").lower()
        key = f"{clean_name}/{rdtype.lower()}"
        self.queries.append((clean_name, rdtype))

        if key not in self.zone:
            raise dns.resolver.NXDOMAIN()

        values = self.zone[key]

        class _MockAnswer:
            def __init__(self, text: str):
                self._text = text

            def to_text(self) -> str:
                return self._text

        return [_MockAnswer(v) for v in values]


@pytest.fixture
def mock_router() -> MockRouter:
    router = MockRouter()
    # 1. crt.sh
    router.add(
        "GET",
        r"crt\.sh",
        json=[
            {"name_value": "api.example.com\n*.wildcard.example.com"},
            {"name_value": "example.com"},  # Root domain: debe filtrarse
        ],
    )
    # 2. HackerTarget
    router.add(
        "GET",
        r"api\.hackertarget\.com/hostsearch",
        text="api.example.com,93.184.216.34\nmail.example.com,93.184.216.35\n",
    )
    # 3. AlienVault OTX
    router.add(
        "GET",
        r"otx\.alienvault\.com",
        json={
            "passive_dns": [
                {"hostname": "dev.example.com", "address": "93.184.216.36"},
                {"hostname": "api.example.com", "address": "93.184.216.34"},
            ]
        },
    )
    # 4. RapidDNS
    router.add(
        "GET",
        r"rapiddns\.io",
        text="""
        <html><body><table>
        <tr><td>staging.example.com</td><td>93.184.216.37</td></tr>
        <tr><td>api.example.com</td><td>93.184.216.34</td></tr>
        </table></body></html>
        """,
    )
    # 5. Anubis
    router.add(
        "GET",
        r"jldc\.me/anubis",
        json=["vpn.example.com", "api.example.com", "invalid@sub.example.com"],
    )
    return router


@pytest.mark.asyncio
async def test_attack_surface_all_sources_aggregation(monkeypatch, mock_router):
    patch_httpx(monkeypatch, mock_router)
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    zone = {
        "api.example.com/a": ["93.184.216.34"],
        "mail.example.com/a": ["93.184.216.35"],
        "staging.example.com/a": ["93.184.216.37"],
        # dev.example.com, vpn.example.com, wildcard.example.com no resuelven
    }
    resolver = MockAsyncResolver(zone)
    collector = AttackSurfaceCollector(resolver=resolver)

    result = await collector.collect("example.com")

    assert result.collector_name == "attack_surface"
    assert result.source_target == "example.com"

    # Verificar nodo DOMAIN raíz
    domain_nodes = [e for e in result.entities if e.type == EntityType.DOMAIN]
    assert len(domain_nodes) == 1
    assert domain_nodes[0].value == "example.com"
    assert domain_nodes[0].attributes.get("target") is True

    # Verificar subdominios descubiertos y deduplicados
    sub_nodes = [e for e in result.entities if e.type == EntityType.SUBDOMAIN]
    sub_values = {e.value for e in sub_nodes}

    expected_subs = {
        "api.example.com",
        "wildcard.example.com",
        "mail.example.com",
        "dev.example.com",
        "staging.example.com",
        "vpn.example.com",
    }
    assert expected_subs.issubset(sub_values)
    assert "example.com" not in sub_values
    assert "invalid@sub.example.com" not in sub_values

    # api.example.com fue descubierto por múltiples fuentes
    api_node = next(e for e in sub_nodes if e.value == "api.example.com")
    sources = set(api_node.attributes.get("sources", []))
    assert "crt.sh" in sources
    assert "hackertarget" in sources
    assert "alienvault" in sources
    assert "rapiddns" in sources
    assert "anubis" in sources
    assert api_node.confidence == 0.95  # Resuelto

    # Verificar nodos IP
    ip_nodes = [e for e in result.entities if e.type == EntityType.IP_ADDRESS]
    ip_values = {e.value for e in ip_nodes}
    assert "93.184.216.34" in ip_values
    assert "93.184.216.35" in ip_values

    # Relaciones SUBDOMAIN_OF
    sub_edges = [r for r in result.relations if r.relation_type == RelationType.SUBDOMAIN_OF]
    assert len(sub_edges) == len(sub_nodes)
    for edge in sub_edges:
        assert edge.target_id == "domain:example.com"

    # Relaciones RESOLVES_TO
    resolves_edges = [r for r in result.relations if r.relation_type == RelationType.RESOLVES_TO]
    assert len(resolves_edges) >= 3
    api_resolves = [r for r in resolves_edges if r.source_id == "subdomain:api.example.com"]
    assert len(api_resolves) == 1
    assert api_resolves[0].target_id == "ip_address:93.184.216.34"


def test_is_valid_subdomain():
    domain = "example.com"
    assert is_valid_subdomain("api.example.com", domain) is True
    assert is_valid_subdomain("*.api.example.com", domain) is True
    assert is_valid_subdomain("sub-domain.v1.example.com", domain) is True
    assert is_valid_subdomain("my_service.example.com", domain) is True

    # Casos inválidos
    assert is_valid_subdomain("example.com", domain) is False
    assert is_valid_subdomain("*.example.com", domain) is False
    assert is_valid_subdomain("notexample.com", domain) is False
    assert is_valid_subdomain("attacker.com", domain) is False
    assert is_valid_subdomain("bad..example.com", domain) is False
    assert is_valid_subdomain("-start.example.com", domain) is False
    assert is_valid_subdomain("end-.example.com", domain) is False
    assert is_valid_subdomain("user@pass.example.com", domain) is False
    assert is_valid_subdomain("", domain) is False


@pytest.mark.asyncio
async def test_attack_surface_cli_fallback_when_tools_missing(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    router = MockRouter()
    router.add("GET", r".*", json=[])
    patch_httpx(monkeypatch, router)

    collector = AttackSurfaceCollector(resolver=MockAsyncResolver({}))
    result = await collector.collect("example.com")

    assert result.collector_name == "attack_surface"
    assert result.metadata["cli_tools_available"] == []


@pytest.mark.asyncio
async def test_attack_surface_cli_execution_when_present(monkeypatch):
    # Mockear shutil.which para reportar subfinder y amass disponibles
    def fake_which(cmd: str) -> str | None:
        if cmd in ("subfinder", "amass"):
            return f"/usr/bin/{cmd}"
        return None

    monkeypatch.setattr("shutil.which", fake_which)

    # Mockear subprocess
    async def fake_create_subprocess_exec(*args, **kwargs):
        cmd = args[0]
        proc = AsyncMock()
        if "subfinder" in cmd:
            stdout_data = b"subfinder-found.example.com\ncommon.example.com\n"
        elif "amass" in cmd:
            stdout_data = b"amass-found.example.com\ncommon.example.com\n"
        else:
            stdout_data = b""

        proc.communicate.return_value = (stdout_data, b"")
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    router = MockRouter()
    router.add("GET", r".*", json=[])
    patch_httpx(monkeypatch, router)

    collector = AttackSurfaceCollector(resolver=MockAsyncResolver({}))
    result = await collector.collect("example.com")

    sub_values = {e.value for e in result.entities if e.type == EntityType.SUBDOMAIN}
    assert "subfinder-found.example.com" in sub_values
    assert "amass-found.example.com" in sub_values
    assert "common.example.com" in sub_values

    common_node = next(
        e
        for e in result.entities
        if e.type == EntityType.SUBDOMAIN and e.value == "common.example.com"
    )
    sources = set(common_node.attributes.get("sources", []))
    assert "subfinder" in sources
    assert "amass" in sources


@pytest.mark.asyncio
async def test_attack_surface_resilience_to_source_failures(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    # crt.sh falla con 500, hackertarget falla con 429, alienvault devuelve JSON válido
    router = MockRouter()
    router.add("GET", r"crt\.sh", status_code=500, text="Internal Server Error")
    router.add("GET", r"api\.hackertarget\.com", status_code=429, text="API count exceeded")
    router.add(
        "GET",
        r"otx\.alienvault\.com",
        json={"passive_dns": [{"hostname": "survivor.example.com"}]},
    )
    router.add("GET", r"rapiddns\.io", status_code=502, text="Bad Gateway")
    router.add("GET", r"jldc\.me", status_code=404, text="Not Found")
    patch_httpx(monkeypatch, router)

    collector = AttackSurfaceCollector(resolver=MockAsyncResolver({}))
    result = await collector.collect("example.com")

    # A pesar de los 4 fallos, no lanza excepción y captura el sobreviviente
    sub_values = {e.value for e in result.entities if e.type == EntityType.SUBDOMAIN}
    assert sub_values == {"survivor.example.com"}

    raw_payload = json.loads(result.raw_payload)
    assert "crt.sh" in raw_payload.get("errors", {})
    assert "hackertarget" in raw_payload.get("errors", {})


def test_attack_surface_registry():
    collector = AttackSurfaceCollector()
    assert collector.name == "attack_surface"

    reg = CollectorRegistry()
    spec = reg.register(collector)
    assert spec.name == "attack_surface"
    assert "attack_surface" in reg
    assert reg.get("attack_surface") is collector

    # Registro por defecto
    assert "attack_surface" in default_registry


@pytest.mark.asyncio
async def test_attack_surface_ipv6_and_shared_ip(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    router = MockRouter()
    router.add(
        "GET",
        r"crt\.sh",
        json=[
            {"name_value": "sub1.example.com\nsub2.example.com\nipv6.example.com"},
        ],
    )
    patch_httpx(monkeypatch, router)

    shared_ip = "192.0.2.1"
    ipv6_addr = "2001:db8::1"
    zone = {
        "sub1.example.com/a": [shared_ip],
        "sub2.example.com/a": [shared_ip],
        "ipv6.example.com/aaaa": [ipv6_addr],
    }
    resolver = MockAsyncResolver(zone)
    collector = AttackSurfaceCollector(resolver=resolver)

    result = await collector.collect("example.com")

    # Verificar que solo hay un nodo IP para el IP compartido
    ip_nodes = [e for e in result.entities if e.type == EntityType.IP_ADDRESS]
    ip_map = {e.value: e for e in ip_nodes}
    assert shared_ip in ip_map
    assert ipv6_addr in ip_map
    assert len(ip_nodes) == 2

    # Verificar atributos de versión
    assert ip_map[shared_ip].attributes["version"] == 4
    assert ip_map[ipv6_addr].attributes["version"] == 6

    # Ambos subdominios tienen arista RESOLVES_TO hacia shared_ip
    resolves_to = [r for r in result.relations if r.relation_type == RelationType.RESOLVES_TO]
    shared_sources = {r.source_id for r in resolves_to if r.target_id == f"ip_address:{shared_ip}"}
    assert shared_sources == {
        "subdomain:sub1.example.com",
        "subdomain:sub2.example.com",
    }


@pytest.mark.asyncio
async def test_attack_surface_cli_timeout_handling(monkeypatch):
    def fake_which(cmd: str) -> str | None:
        return "/usr/bin/subfinder" if cmd == "subfinder" else None

    monkeypatch.setattr("shutil.which", fake_which)

    async def fake_proc_timeout(*args, **kwargs):
        proc = AsyncMock()
        proc.communicate.side_effect = TimeoutError()
        proc.kill = MagicMock()
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_proc_timeout)

    router = MockRouter()
    router.add("GET", r".*", json=[])
    patch_httpx(monkeypatch, router)

    collector = AttackSurfaceCollector(resolver=MockAsyncResolver({}), cli_timeout=0.1)
    result = await collector.collect("example.com")

    raw = json.loads(result.raw_payload)
    assert "subfinder" in raw["errors"]
    assert "Timeout" in raw["errors"]["subfinder"]


@pytest.mark.asyncio
async def test_attack_surface_sync_resolver_fallback(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    router = MockRouter()
    router.add(
        "GET",
        r"crt\.sh",
        json=[{"name_value": "sync.example.com"}],
    )
    patch_httpx(monkeypatch, router)

    class SyncFakeAnswer:
        def __init__(self, ip: str):
            self.ip = ip

        def to_text(self) -> str:
            return self.ip

    class SyncResolver:
        def resolve(self, qname: str, rdtype: str = "A"):
            if str(qname).rstrip(".").lower() == "sync.example.com" and rdtype == "A":
                return [SyncFakeAnswer("10.0.0.1")]
            raise dns.resolver.NXDOMAIN()

    collector = AttackSurfaceCollector(resolver=SyncResolver())
    result = await collector.collect("example.com")

    ip_nodes = [e for e in result.entities if e.type == EntityType.IP_ADDRESS]
    assert len(ip_nodes) == 1
    assert ip_nodes[0].value == "10.0.0.1"


@pytest.mark.asyncio
async def test_attack_surface_empty_target():
    collector = AttackSurfaceCollector(resolver=MockAsyncResolver({}))
    result = await collector.collect("")
    assert result.collector_name == "attack_surface"
    assert len(result.entities) == 0
    assert result.metadata["total_subdomains_found"] == 0

"""
Tests para la capa de caché de alto rendimiento (specter.cache)
y el generador de dossiers forenses ejecutivos (specter.visualizer.exporter).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
from specter.cache import (
    cache_get,
    cache_invalidate,
    cache_set,
    close_cache,
    osint_cache,
)
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.ledger import ForensicLedger
from specter.osint_core.models import (
    CaseMetadata,
    CollectorResult,
    EntityNode,
    EntityType,
    RawEvidence,
    RelationEdge,
    RelationType,
)
from specter.visualizer.exporter import (
    DossierExporter,
    export_case_dossier_html,
    export_case_dossier_markdown,
)


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Aísla el directorio de caché y fija la clave de firma forense."""
    cache_dir = tmp_path / "cache_store"
    monkeypatch.setenv("SPECTER_CACHE_DIR", str(cache_dir))
    key_hex = "7365637265742d666f72656e7369632d6b65792d33322d62797465732121"
    monkeypatch.setenv("SPECTER_LEDGER_KEY", key_hex)
    close_cache()
    yield cache_dir
    close_cache()


@pytest.fixture
def test_db(tmp_path: Path):
    db_file = tmp_path / "forensic_test.db"
    return Database(db_file)


# =====================================================================
# 1. PRUEBAS DE CACHÉ
# =====================================================================


def test_cache_set_and_get():
    """Prueba almacenamiento básico, recuperación y valor por defecto."""
    assert cache_get("missing_key") is None
    assert cache_get("missing_key", default="fallback") == "fallback"

    assert cache_set("entity:domain:threat.com", {"ip": "1.2.3.4", "score": 90}) is True
    val = cache_get("entity:domain:threat.com")
    assert isinstance(val, dict)
    assert val["ip"] == "1.2.3.4"
    assert val["score"] == 90


def test_cache_ttl_expiration():
    """Prueba la expiración por TTL."""
    cache_set("temp_token", "secret_123", ttl=1)
    assert cache_get("temp_token") == "secret_123"

    # Esperar a que expire el TTL
    time.sleep(1.2)
    assert cache_get("temp_token") is None


def test_cache_invalidate_pattern():
    """Prueba invalidación selectiva por patrones fnmatch y purga total."""
    cache_set("dns:target1.com", "A_RECORD")
    cache_set("dns:target2.com", "MX_RECORD")
    cache_set("whois:target1.com", "REGISTRAR")
    cache_set("shodan:1.1.1.1", "PORTS")

    # Invalidar solo llaves dns:*
    del_count = cache_invalidate("dns:*")
    assert del_count == 2
    assert cache_get("dns:target1.com") is None
    assert cache_get("dns:target2.com") is None
    assert cache_get("whois:target1.com") == "REGISTRAR"
    assert cache_get("shodan:1.1.1.1") == "PORTS"

    # Invalida whois con prefijo simple
    del_count = cache_invalidate("whois*")
    assert del_count == 1
    assert cache_get("whois:target1.com") is None

    # Purga total
    total_cleared = cache_invalidate("*")
    assert total_cleared == 1
    assert cache_get("shodan:1.1.1.1") is None


def test_osint_cache_decorator_sync():
    """Prueba decorador @osint_cache en funciones síncronas."""
    call_count = 0

    @osint_cache(ttl_seconds=2, key_prefix="dns_sync")
    def resolve_domain(domain: str) -> dict[str, str]:
        nonlocal call_count
        call_count += 1
        return {"domain": domain, "resolved": True}

    # Primera llamada: ejecuta función
    res1 = resolve_domain("example.com")
    assert res1["resolved"] is True
    assert call_count == 1

    # Segunda llamada: recupera de caché
    res2 = resolve_domain("example.com")
    assert res2 == res1
    assert call_count == 1

    # Argumento distinto: ejecuta función
    res3 = resolve_domain("other.com")
    assert res3["domain"] == "other.com"
    assert call_count == 2

    # Expiración TTL
    time.sleep(2.1)
    res4 = resolve_domain("example.com")
    assert res4["domain"] == "example.com"
    assert call_count == 3


@pytest.mark.asyncio
async def test_osint_cache_decorator_async():
    """Prueba decorador @osint_cache en funciones asíncronas."""
    call_count = 0

    @osint_cache(ttl_seconds=3, key_prefix="ct_async")
    async def fetch_certificates(domain: str) -> list[str]:
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.01)
        return [f"sub1.{domain}", f"sub2.{domain}"]

    # Primera ejecución
    r1 = await fetch_certificates("corp.org")
    assert len(r1) == 2
    assert call_count == 1

    # Segunda ejecución: resultado en caché
    r2 = await fetch_certificates("corp.org")
    assert r2 == r1
    assert call_count == 1

    # Invalidación selectiva
    cache_invalidate("ct_async:*")
    r3 = await fetch_certificates("corp.org")
    assert r3 == r1
    assert call_count == 2


def test_osint_cache_collector_class_method():
    """Prueba que métodos en clases de colectores compartan caché entre instancias."""
    invocations = 0

    class MockCollector:
        def __init__(self, name: str):
            self.name = name

        @osint_cache(ttl_seconds=60, key_prefix="collector_query")
        def query(self, target: str) -> str:
            nonlocal invocations
            invocations += 1
            return f"Result for {target}"

    c1 = MockCollector("agent_a")
    c2 = MockCollector("agent_b")

    out1 = c1.query("investigation_target")
    assert invocations == 1
    assert out1 == "Result for investigation_target"

    # Segunda instancia con el mismo nombre y target aprovecha la caché
    c3 = MockCollector("agent_a")
    out2 = c3.query("investigation_target")
    assert invocations == 1
    assert out2 == out1

    # Instancia con nombre distinto ejecuta de nuevo
    out3 = c2.query("investigation_target")
    assert invocations == 2
    assert out3 == "Result for investigation_target"


# =====================================================================
# 2. PRUEBAS DE EXPORTACIÓN DE DOSSIER (HTML & MARKDOWN)
# =====================================================================


def _populate_sample_case(db: Database) -> CaseMetadata:
    case = CaseMetadata(
        case_id="case-dossier-2026",
        name="Operación Centinela Oscuro",
        description="Investigación de infraestructura C2 y atribución de actores de amenaza.",
        investigator="Cap. Elena Vance",
    )
    db.create_case(case)

    ledger = ForensicLedger(db)
    ledger.initialize_case_genesis(case)

    # Nodos de prueba
    e_dom = EntityNode.create(
        EntityType.DOMAIN, "apt-command.xyz", "C2 Dominio Principal", confidence=0.98
    )
    e_ip = EntityNode.create(
        EntityType.IP_ADDRESS, "198.51.100.77", "Host C2 Primario", confidence=0.95
    )
    e_email = EntityNode.create(
        EntityType.EMAIL, "operator@apt-command.xyz", "Correo del Registrador", confidence=0.88
    )
    e_alias = EntityNode.create(EntityType.ALIAS, "ghost_root", "Alias Atribuido", confidence=0.75)

    # Relaciones
    r1 = RelationEdge(
        source_id=e_dom.id,
        target_id=e_ip.id,
        relation_type=RelationType.RESOLVES_TO,
        confidence=0.95,
    )
    r2 = RelationEdge(
        source_id=e_email.id,
        target_id=e_dom.id,
        relation_type=RelationType.REGISTERED_BY,
        confidence=0.85,
    )
    r3 = RelationEdge(
        source_id=e_alias.id,
        target_id=e_email.id,
        relation_type=RelationType.USES_ALIAS,
        confidence=0.75,
    )

    graph = OSINTGraph(db)
    graph.ingest_collector_result(
        case.case_id,
        CollectorResult(
            collector_name="dns_collector",
            source_target="apt-command.xyz",
            entities=[e_dom, e_ip],
            relations=[r1],
        ),
    )
    graph.ingest_collector_result(
        case.case_id,
        CollectorResult(
            collector_name="threatfox",
            source_target="198.51.100.77",
            entities=[e_email, e_alias],
            relations=[r2, r3],
        ),
    )

    # Evidencias en ledger
    ev1 = RawEvidence(
        id="ev-001",
        case_id=case.case_id,
        collector="dns_collector",
        source_url="https://dns.lookup/apt-command.xyz",
        raw_payload='{"A": ["198.51.100.77"]}',
        payload_hash="auto",
    )
    ledger.record_evidence_action(case.case_id, "dns_collector", "DNS A Record Query", ev1)

    ev2 = RawEvidence(
        id="ev-002",
        case_id=case.case_id,
        collector="threatfox",
        source_url="https://threatfox.abuse.ch/ioc/123",
        raw_payload='{"threat_type": "botnet_c2"}',
        payload_hash="auto",
    )
    ledger.record_evidence_action(case.case_id, "threatfox", "ThreatFox IOC Match", ev2)

    return case


def test_export_case_dossier_html_full(test_db: Database, tmp_path: Path):
    """Prueba exhaustiva de exportación del dossier ejecutivo autónomo en HTML."""
    case = _populate_sample_case(test_db)
    graph_engine = OSINTGraph(test_db)

    output_file = tmp_path / "dossier_centinela.html"
    returned_path = export_case_dossier_html(
        case.case_id, test_db, graph_engine=graph_engine, output_path=output_file
    )

    assert returned_path == str(output_file.resolve())
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")

    # 1. Header y sellos
    assert case.case_id in content
    assert "Operación Centinela Oscuro" in content
    assert "Cap. Elena Vance" in content
    assert "CONFIDENCIAL / FORENSE" in content
    assert "SELLADO CRIPTOGRÁFICO" in content or "HMAC" in content

    # 2. Resumen y Almirantazgo
    assert "Resumen Ejecutivo y Métricas de Inteligencia" in content
    assert "Sistema Almirantazgo OTAN" in content
    assert "dns_collector" in content
    assert "threatfox" in content
    assert "Escala de Fiabilidad de la Fuente" in content

    # 3. Métricas de red (Hubs, Betweenness, PageRank, Louvain)
    assert "Centros de Conectividad (Hubs - Degree)" in content
    assert "Nodos Puente (Betweenness Centrality)" in content
    assert "Nodos de Mayor Influencia (PageRank)" in content
    assert "Células y Comunidades Cohesivas" in content or "Comunidad" in content

    # 4. Línea temporal
    assert "Reconstrucción Temporal" in content
    assert "Ventana Temporal Total" in content

    # 5. Inventario de entidades y relaciones
    assert "apt-command.xyz" in content
    assert "198.51.100.77" in content
    assert "operator@apt-command.xyz" in content
    assert "ghost_root" in content
    assert "RESOLVES_TO" in content

    # 6. Cadena de custodia
    assert "7. Ledger de Auditoría (SHA-256 y HMAC opcional)" in content
    assert "DNS A Record Query" in content

    # 7. Reglas print-ready (@media print y @page A4)
    assert "@media print" in content
    assert "size: A4" in content
    assert "margin: 15mm" in content


def test_export_case_dossier_html_via_dossier_exporter_class(test_db: Database, tmp_path: Path):
    """Prueba que DossierExporter.export_case_dossier_html funcione."""
    case = _populate_sample_case(test_db)
    exporter = DossierExporter(test_db)

    out = tmp_path / "class_dossier.html"
    res = exporter.export_case_dossier_html(case.case_id, output_path=out)
    assert Path(res).exists()
    assert "apt-command.xyz" in Path(res).read_text(encoding="utf-8")


def test_export_case_dossier_markdown(test_db: Database, tmp_path: Path):
    """Prueba export_case_dossier_markdown y su compatibilidad."""
    case = _populate_sample_case(test_db)

    out_md = tmp_path / "dossier.md"
    res = export_case_dossier_markdown(case.case_id, test_db, output_path=out_md)
    assert Path(res).exists()
    content = Path(res).read_text(encoding="utf-8")

    assert f"# Dossier Forense OSINT: {case.name}" in content
    assert "apt-command.xyz" in content
    assert "## 2b. Relaciones con Confianza" in content
    assert "## 2c. Fiabilidad de Fuentes (Almirantazgo OTAN)" in content
    assert "## 3. Cadena de Custodia Criptográfica (Forensic Audit)" in content


def test_export_case_dossier_nonexistent_case(test_db: Database):
    """Verifica manejo de error ante caso inexistente."""
    with pytest.raises(ValueError, match="no encontrado"):
        export_case_dossier_html("case-inexistente", test_db)
    with pytest.raises(ValueError, match="no encontrado"):
        export_case_dossier_markdown("case-inexistente", test_db)


def test_export_case_dossier_default_paths(
    test_db: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Verifica generación en ruta predeterminada de reportes."""
    reports_dir = tmp_path / "reports_default"
    monkeypatch.setenv("SPECTER_REPORTS_DIR", str(reports_dir))

    case = _populate_sample_case(test_db)

    # HTML sin output_path especificado
    html_path = export_case_dossier_html(case.case_id, test_db)
    assert Path(html_path).exists()
    assert Path(html_path).parent == reports_dir.resolve()

    # Markdown sin output_path especificado
    md_path = export_case_dossier_markdown(case.case_id, test_db)
    assert Path(md_path).exists()
    assert Path(md_path).parent == reports_dir.resolve()

    # HTML pasando output_path como tercer argumento posicional
    custom_pos_path = tmp_path / "custom_pos.html"
    res_pos = export_case_dossier_html(case.case_id, test_db, custom_pos_path)
    assert res_pos == str(custom_pos_path.resolve())
    assert custom_pos_path.exists()

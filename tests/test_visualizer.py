import tempfile
from pathlib import Path

import pytest
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.ledger import ForensicLedger
from specter.osint_core.models import (
    CaseMetadata,
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)
from specter.visualizer.exporter import DossierExporter


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_vis.db"
        yield Database(db_path)


def test_dossier_export_html_and_md(temp_db, tmp_path: Path):
    case = CaseMetadata(
        case_id="case-vis-001",
        name="Operación Muestra Visual",
        description="Prueba de generación de HTML autónomo",
        investigator="Investigador_Vis",
    )
    temp_db.create_case(case)

    ledger = ForensicLedger(temp_db)
    ledger.initialize_case_genesis(case)

    # Inyectar entidades de prueba
    e1 = EntityNode.create(EntityType.DOMAIN, "threat.com", "Threat Domain")
    e2 = EntityNode.create(EntityType.IP_ADDRESS, "192.0.2.1", "C2 IP")
    r1 = RelationEdge(source_id=e1.id, target_id=e2.id, relation_type=RelationType.RESOLVES_TO)

    graph = OSINTGraph(temp_db)
    graph.ingest_collector_result(
        case.case_id,
        CollectorResult(
            collector_name="test", source_target="threat.com", entities=[e1, e2], relations=[r1]
        ),
    )

    exporter = DossierExporter(temp_db)

    # Exportar HTML
    html_file = tmp_path / "report.html"
    exported_html_path = exporter.export_html(case.case_id, html_file)
    assert Path(exported_html_path).exists()
    content = Path(exported_html_path).read_text(encoding="utf-8")
    assert "threat.com" in content
    assert "vis-network" in content
    assert "Integridad del ledger verificada" in content

    # Exportar Markdown
    md_file = tmp_path / "report.md"
    exported_md_path = exporter.export_markdown(case.case_id, md_file)
    assert Path(exported_md_path).exists()
    md_content = Path(exported_md_path).read_text(encoding="utf-8")
    assert "# Dossier Forense OSINT" in md_content
    assert "threat.com" in md_content

import tempfile
from pathlib import Path

import pytest
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.models import (
    CaseMetadata,
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_graph.db"
        yield Database(db_path)


@pytest.fixture
def sample_case(temp_db):
    case = CaseMetadata(
        case_id="case-graph-01",
        name="Test Grafo",
        description="Test de correlación",
        investigator="Analista_02",
    )
    temp_db.create_case(case)
    return case


def test_graph_ingestion_and_subgraph(temp_db, sample_case):
    graph = OSINTGraph(temp_db)

    # Entidades
    e_domain = EntityNode.create(EntityType.DOMAIN, "target.org", "Target Corp")
    e_sub = EntityNode.create(EntityType.SUBDOMAIN, "vpn.target.org", "VPN Portal")
    e_ip = EntityNode.create(EntityType.IP_ADDRESS, "203.0.113.5", "VPN IP")
    e_alias = EntityNode.create(EntityType.ALIAS, "johndoe", "John Doe Profile")

    # Relaciones
    r1 = RelationEdge(
        source_id=e_sub.id,
        target_id=e_domain.id,
        relation_type=RelationType.SUBDOMAIN_OF,
    )
    r2 = RelationEdge(
        source_id=e_sub.id,
        target_id=e_ip.id,
        relation_type=RelationType.RESOLVES_TO,
    )
    r3 = RelationEdge(
        source_id=e_alias.id,
        target_id=e_domain.id,
        relation_type=RelationType.ADMINISTERS,
    )

    result = CollectorResult(
        collector_name="test_collector",
        source_target="target.org",
        entities=[e_domain, e_sub, e_ip, e_alias],
        relations=[r1, r2, r3],
    )

    graph.ingest_collector_result(sample_case.case_id, result)

    # Validar subgrafo
    subgraph = graph.query_subgraph(sample_case.case_id)
    assert subgraph["total_nodes"] == 4
    assert subgraph["total_edges"] == 3

    # Validar búsqueda por término
    filtered = graph.query_subgraph(sample_case.case_id, search_term="vpn")
    assert filtered["total_nodes"] >= 1

    # Validar camino más corto
    path = graph.find_shortest_path(sample_case.case_id, e_alias.id, e_ip.id)
    assert path is not None
    # johndoe -> target.org -> vpn.target.org -> 203.0.113.5 (4 nodos)
    assert len(path) == 4
    assert path[0]["id"] == e_alias.id
    assert path[-1]["id"] == e_ip.id

    # Validar métricas
    metrics = graph.analyze_metrics(sample_case.case_id)
    assert metrics["total_nodes"] == 4
    assert metrics["total_edges"] == 3
    assert len(metrics["top_central_nodes"]) > 0

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


def test_subgraph_synthesizes_stub_nodes_from_relations(temp_db, sample_case):
    from specter.osint_core.models import GraphSubgraph

    graph = OSINTGraph(temp_db)

    # Solo agregamos una entidad base
    person = EntityNode.create(EntityType.PERSON, "Josue Pizango", "Josue Pizango")
    temp_db.upsert_entities(sample_case.case_id, [person])

    # Agregamos relaciones a nodos que NO fueron insertados en la tabla entities
    r_social = RelationEdge(
        source_id=person.id,
        target_id="social_profile:https://facebook.com/pizangochang.josuealejandro",
        relation_type=RelationType.ASSOCIATED_WITH,
    )
    r_custom = RelationEdge(
        source_id=person.id,
        target_id="custom_unknown:orphan_target",
        relation_type=RelationType.ASSOCIATED_WITH,
    )
    r_plain = RelationEdge(
        source_id=person.id,
        target_id="plain_id_without_colon",
        relation_type=RelationType.ASSOCIATED_WITH,
    )

    temp_db.upsert_relations(sample_case.case_id, [r_social, r_custom, r_plain])

    # El subgrafo debe sintetizar type y value válidos para todos los nodos
    subgraph = graph.query_subgraph(sample_case.case_id)
    assert subgraph["total_nodes"] == 4
    assert subgraph["total_edges"] == 3

    # Validación Pydantic no debe fallar con ResponseValidationError / ValidationError
    validated = GraphSubgraph.model_validate(subgraph)
    assert len(validated.nodes) == 4

    nodes_by_id = {n.id: n for n in validated.nodes}

    # Nodo social sintetizado con tipo SOCIAL_PROFILE y value URL
    soc_node = nodes_by_id["social_profile:https://facebook.com/pizangochang.josuealejandro"]
    assert soc_node.type == EntityType.SOCIAL_PROFILE
    assert soc_node.value == "https://facebook.com/pizangochang.josuealejandro"

    # Nodo con prefijo desconocido sintetizado con UNKNOWN
    custom_node = nodes_by_id["custom_unknown:orphan_target"]
    assert custom_node.type == EntityType.UNKNOWN
    assert custom_node.value == "orphan_target"

    # Nodo sin dos puntos sintetizado con UNKNOWN y value igual al ID
    plain_node = nodes_by_id["plain_id_without_colon"]
    assert plain_node.type == EntityType.UNKNOWN
    assert plain_node.value == "plain_id_without_colon"

    # Métricas y camino más corto deben funcionar sin romper
    metrics = graph.analyze_metrics(sample_case.case_id)
    assert metrics["total_nodes"] == 4
    path = graph.find_shortest_path(sample_case.case_id, person.id, soc_node.id)
    assert path is not None
    assert len(path) == 2
    assert path[1]["type"] == EntityType.SOCIAL_PROFILE.value
    assert path[1]["value"] == "https://facebook.com/pizangochang.josuealejandro"


def test_subgraph_filtering_empty_when_no_match(temp_db, sample_case):
    graph = OSINTGraph(temp_db)
    person = EntityNode.create(EntityType.PERSON, "Josue Pizango", "Josue Pizango")
    temp_db.upsert_entities(sample_case.case_id, [person])

    # Filtrar por un término inexistente DEBE devolver 0 nodos, no el grafo completo
    res_term = graph.query_subgraph(sample_case.case_id, search_term="inexistente_xyz_123")
    assert res_term["total_nodes"] == 0
    assert res_term["nodes"] == []
    assert res_term["total_edges"] == 0

    # Filtrar por un entity_type inexistente DEBE devolver 0 nodos
    res_type = graph.query_subgraph(sample_case.case_id, entity_type="PHONE")
    assert res_type["total_nodes"] == 0
    assert res_type["nodes"] == []

    # Filtrar por center_id inexistente DEBE devolver 0 nodos
    res_center = graph.query_subgraph(sample_case.case_id, center_id="person:no_existe")
    assert res_center["total_nodes"] == 0


def test_from_node_id_handles_raw_urls_and_social_platforms():
    # URL directa de red social sin prefijo type:
    node_fb = EntityNode.from_node_id("https://facebook.com/pizangochang.josuealejandro")
    assert node_fb.type == EntityType.SOCIAL_PROFILE
    assert node_fb.value == "https://facebook.com/pizangochang.josuealejandro"
    assert node_fb.id == "https://facebook.com/pizangochang.josuealejandro"

    # URL directa HTTP de Twitter
    node_tw = EntityNode.from_node_id("http://twitter.com/osint_analyst")
    assert node_tw.type == EntityType.SOCIAL_PROFILE
    assert node_tw.value == "http://twitter.com/osint_analyst"

    # URL genérica: no debe recortar "http:" y dejar "//example.com"
    node_web = EntityNode.from_node_id("https://example.com/investigation/doc.pdf")
    assert node_web.value == "https://example.com/investigation/doc.pdf"
    assert node_web.type in (EntityType.UNKNOWN, EntityType.FILE_ARTIFACT)

    # Prefijo con alias estándar como ip:
    node_ip = EntityNode.from_node_id("ip:198.51.100.1")
    assert node_ip.type == EntityType.IP_ADDRESS
    assert node_ip.value == "198.51.100.1"

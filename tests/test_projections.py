"""
Tests para las proyecciones CQRS de SpecterOSINT.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.models import (
    CaseMetadata,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)
from specter.osint_core.projections import (
    CorrelationsProjection,
    GraphProjection,
    ProjectionManager,
    TimelineProjection,
)


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_projections.db"
        yield Database(db_path)


@pytest.fixture
def graph(temp_db):
    return OSINTGraph(temp_db)


@pytest.fixture
def sample_case(temp_db):
    case = CaseMetadata(
        case_id="case-test-001",
        name="Caso de Prueba",
        description="Descripción del caso de prueba",
        investigator="Analista_Test",
    )
    temp_db.create_case(case)
    return case


@pytest.fixture
def sample_data(temp_db, sample_case):
    """Crea datos de prueba en el grafo."""
    entities = [
        EntityNode.create(EntityType.DOMAIN, "example.com", "Example Domain"),
        EntityNode.create(EntityType.SUBDOMAIN, "www.example.com", "WWW"),
        EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1", "Server IP"),
    ]
    relations = [
        RelationEdge(
            source_id="subdomain:www.example.com",
            target_id="domain:example.com",
            relation_type=RelationType.SUBDOMAIN_OF,
        ),
        RelationEdge(
            source_id="subdomain:www.example.com",
            target_id="ip_address:192.168.1.1",
            relation_type=RelationType.RESOLVES_TO,
        ),
    ]

    temp_db.upsert_entities(sample_case.case_id, entities)
    temp_db.upsert_relations(sample_case.case_id, relations)

    return {"entities": entities, "relations": relations}


class TestGraphProjection:
    """Tests para GraphProjection."""

    @pytest.mark.asyncio
    async def test_rebuild(self, temp_db, graph, sample_case, sample_data):
        """Test reconstruir la proyección de grafo."""
        projection = await GraphProjection.rebuild(temp_db, graph, sample_case.case_id)

        assert projection.name == "graph"
        assert projection.case_id == sample_case.case_id
        # Nota: los stubs de relaciones pueden añadir nodos adicionales
        assert len(projection.nodes) >= 3
        assert len(projection.edges) == 2

    @pytest.mark.asyncio
    async def test_update_entity_added(self, temp_db, graph, sample_case, sample_data):
        """Test actualizar proyección con entidad añadida."""
        projection = await GraphProjection.rebuild(temp_db, graph, sample_case.case_id)

        initial_count = len(projection.nodes)
        new_entity = EntityNode.create(EntityType.EMAIL, "test@example.com")
        event = {
            "type": "entity_added",
            "data": new_entity.model_dump(),
        }

        await projection.update(event)

        assert len(projection.nodes) == initial_count + 1
        assert "email:test@example.com" in projection.nodes

    @pytest.mark.asyncio
    async def test_update_relation_added(self, temp_db, graph, sample_case, sample_data):
        """Test actualizar proyección con relación añadida."""
        projection = await GraphProjection.rebuild(temp_db, graph, sample_case.case_id)

        new_relation = RelationEdge(
            source_id="domain:example.com",
            target_id="email:test@example.com",
            relation_type=RelationType.CONTAINS_METADATA,
        )
        event = {
            "type": "relation_added",
            "data": new_relation.model_dump(),
        }

        await projection.update(event)

        assert len(projection.edges) == 3

    @pytest.mark.asyncio
    async def test_get_neighbors(self, temp_db, graph, sample_case, sample_data):
        """Test obtener vecinos de un nodo."""
        projection = await GraphProjection.rebuild(temp_db, graph, sample_case.case_id)

        neighbors = projection.get_neighbors("subdomain:www.example.com")

        assert len(neighbors) >= 2

    @pytest.mark.asyncio
    async def test_get_subgraph(self, temp_db, graph, sample_case, sample_data):
        """Test obtener subgrafo centrado en un nodo."""
        projection = await GraphProjection.rebuild(temp_db, graph, sample_case.case_id)

        subgraph = projection.get_subgraph("subdomain:www.example.com", max_depth=1)

        assert len(subgraph["nodes"]) >= 3
        assert len(subgraph["edges"]) == 2


class TestTimelineProjection:
    """Tests para TimelineProjection."""

    @pytest.mark.asyncio
    async def test_rebuild(self, temp_db, sample_case, sample_data):
        """Test reconstruir la proyección de timeline."""
        projection = await TimelineProjection.rebuild(temp_db, sample_case.case_id)

        assert projection.name == "timeline"
        assert projection.case_id == sample_case.case_id
        assert len(projection.events) > 0

    @pytest.mark.asyncio
    async def test_update(self, temp_db, sample_case, sample_data):
        """Test actualizar proyección de timeline."""
        projection = await TimelineProjection.rebuild(temp_db, sample_case.case_id)

        initial_count = len(projection.events)

        event = {
            "timestamp": "2024-01-01T00:00:00+00:00",
            "kind": "entity",
            "artifact_id": "test-event",
        }

        await projection.update(event)

        assert len(projection.events) == initial_count + 1

    @pytest.mark.asyncio
    async def test_get_events_range(self, temp_db, sample_case, sample_data):
        """Test obtener eventos en un rango temporal."""
        projection = await TimelineProjection.rebuild(temp_db, sample_case.case_id)

        events = projection.get_events_range(
            start="2020-01-01T00:00:00+00:00",
            end="2030-01-01T00:00:00+00:00",
        )

        assert len(events) > 0


class TestCorrelationsProjection:
    """Tests para CorrelationsProjection."""

    @pytest.mark.asyncio
    async def test_rebuild(self, temp_db, sample_case, sample_data):
        """Test reconstruir la proyección de correlaciones."""
        projection = await CorrelationsProjection.rebuild(temp_db, sample_case.case_id)

        assert projection.name == "correlations"
        assert projection.case_id == sample_case.case_id

    @pytest.mark.asyncio
    async def test_update_entity_shared(self, temp_db, sample_case, sample_data):
        """Test actualizar proyección con entidad compartida."""
        projection = await CorrelationsProjection.rebuild(temp_db, sample_case.case_id)

        event = {
            "type": "entity_shared",
            "entity_id": "domain:example.com",
            "case_ids": [sample_case.case_id, "case-otro"],
        }

        await projection.update(event)

        assert "domain:example.com" in projection.shared_entities

    @pytest.mark.asyncio
    async def test_get_related_cases(self, temp_db, sample_case, sample_data):
        """Test obtener casos relacionados."""
        projection = await CorrelationsProjection.rebuild(temp_db, sample_case.case_id)

        event = {
            "type": "entity_shared",
            "entity_id": "domain:example.com",
            "case_ids": [sample_case.case_id, "case-relacionado"],
        }

        await projection.update(event)

        related = projection.get_related_cases(sample_case.case_id)

        assert "case-relacionado" in related


class TestProjectionManager:
    """Tests para ProjectionManager."""

    @pytest.mark.asyncio
    async def test_rebuild_all(self, temp_db, graph, sample_case, sample_data):
        """Test reconstruir todas las proyecciones."""
        manager = ProjectionManager(temp_db, graph)
        await manager.rebuild_all(sample_case.case_id)

        assert manager.get_graph_projection(sample_case.case_id) is not None
        assert manager.get_timeline_projection(sample_case.case_id) is not None
        assert manager.get_correlations_projection(sample_case.case_id) is not None

    @pytest.mark.asyncio
    async def test_update(self, temp_db, graph, sample_case, sample_data):
        """Test actualizar todas las proyecciones."""
        manager = ProjectionManager(temp_db, graph)
        await manager.rebuild_all(sample_case.case_id)

        graph_proj = manager.get_graph_projection(sample_case.case_id)
        assert graph_proj is not None
        initial_count = len(graph_proj.nodes)

        event = {
            "type": "entity_added",
            "data": EntityNode.create(EntityType.EMAIL, "new@example.com").model_dump(),
        }

        await manager.update(sample_case.case_id, event)

        graph_proj = manager.get_graph_projection(sample_case.case_id)
        assert graph_proj is not None
        assert len(graph_proj.nodes) == initial_count + 1
        assert "email:new@example.com" in graph_proj.nodes

    @pytest.mark.asyncio
    async def test_get_projection(self, temp_db, graph, sample_case, sample_data):
        """Test obtener una proyección específica."""
        manager = ProjectionManager(temp_db, graph)
        await manager.rebuild_all(sample_case.case_id)

        projection = manager.get_projection("graph", sample_case.case_id)

        assert projection is not None
        assert projection.name == "graph"

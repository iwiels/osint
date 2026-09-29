"""
Tests para las queries CQRS de SpecterOSINT.
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
from specter.osint_core.queries import (
    GetCaseQuery,
    GetCorrelationsQuery,
    GetEntitiesQuery,
    GetGraphQuery,
    GetTimelineQuery,
    SearchEvidenceQuery,
)


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_queries.db"
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
        EntityNode.create(EntityType.EMAIL, "admin@example.com", "Admin Email"),
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


class TestGetCaseQuery:
    """Tests para GetCaseQuery."""

    @pytest.mark.asyncio
    async def test_get_case_success(self, temp_db, sample_case):
        """Test obtener un caso exitosamente."""
        query = GetCaseQuery(db=temp_db, case_id=sample_case.case_id)

        result = await query.execute()

        assert result.success is True
        assert result.data["case"]["case_id"] == sample_case.case_id
        assert result.data["case"]["name"] == sample_case.name

    @pytest.mark.asyncio
    async def test_get_case_not_found(self, temp_db):
        """Test obtener un caso que no existe."""
        query = GetCaseQuery(db=temp_db, case_id="case-inexistente")

        result = await query.execute()

        assert result.success is False
        assert "no encontrado" in result.message

    @pytest.mark.asyncio
    async def test_get_case_validation(self, temp_db):
        """Test validación de GetCaseQuery."""
        query = GetCaseQuery(db=temp_db, case_id="")

        errors = query.validate()

        assert len(errors) > 0


class TestGetEntitiesQuery:
    """Tests para GetEntitiesQuery."""

    @pytest.mark.asyncio
    async def test_get_entities_success(self, temp_db, sample_case, sample_data):
        """Test obtener entidades exitosamente."""
        query = GetEntitiesQuery(db=temp_db, case_id=sample_case.case_id)

        result = await query.execute()

        assert result.success is True
        # Nota: upsert_relations crea stubs para extremos, por lo que hay más entidades
        assert result.data["total"] >= 4
        assert len(result.data["entities"]) >= 4

    @pytest.mark.asyncio
    async def test_get_entities_with_type_filter(self, temp_db, sample_case, sample_data):
        """Test obtener entidades filtradas por tipo."""
        query = GetEntitiesQuery(
            db=temp_db,
            case_id=sample_case.case_id,
            entity_type=EntityType.DOMAIN,
        )

        result = await query.execute()

        assert result.success is True
        assert result.data["total"] == 1
        assert result.data["entities"][0]["type"] == "DOMAIN"

    @pytest.mark.asyncio
    async def test_get_entities_pagination(self, temp_db, sample_case, sample_data):
        """Test paginación de entidades."""
        query = GetEntitiesQuery(
            db=temp_db,
            case_id=sample_case.case_id,
            limit=2,
            offset=0,
        )

        result = await query.execute()

        assert result.success is True
        assert result.data["total"] >= 4
        assert len(result.data["entities"]) == 2

    @pytest.mark.asyncio
    async def test_get_entities_case_not_found(self, temp_db):
        """Test obtener entidades de un caso inexistente."""
        query = GetEntitiesQuery(db=temp_db, case_id="case-inexistente")

        result = await query.execute()

        assert result.success is False


class TestGetGraphQuery:
    """Tests para GetGraphQuery."""

    @pytest.mark.asyncio
    async def test_get_graph_success(self, temp_db, graph, sample_case, sample_data):
        """Test obtener el grafo exitosamente."""
        query = GetGraphQuery(
            db=temp_db,
            graph=graph,
            case_id=sample_case.case_id,
        )

        result = await query.execute()

        assert result.success is True
        # Nota: los stubs de relaciones pueden añadir nodos adicionales
        assert result.data["graph"]["total_nodes"] >= 4
        assert result.data["graph"]["total_edges"] == 2

    @pytest.mark.asyncio
    async def test_get_graph_with_search(self, temp_db, graph, sample_case, sample_data):
        """Test obtener el grafo con búsqueda."""
        query = GetGraphQuery(
            db=temp_db,
            graph=graph,
            case_id=sample_case.case_id,
            search_term="www",
        )

        result = await query.execute()

        assert result.success is True
        assert result.data["graph"]["total_nodes"] >= 1

    @pytest.mark.asyncio
    async def test_get_graph_case_not_found(self, temp_db, graph):
        """Test obtener grafo de un caso inexistente."""
        query = GetGraphQuery(
            db=temp_db,
            graph=graph,
            case_id="case-inexistente",
        )

        result = await query.execute()

        assert result.success is False


class TestSearchEvidenceQuery:
    """Tests para SearchEvidenceQuery."""

    @pytest.mark.asyncio
    async def test_search_evidence_success(self, temp_db, sample_case):
        """Test buscar evidencias exitosamente."""
        from specter.osint_core.models import RawEvidence, current_utc_iso

        # Insertar evidencia de prueba
        evidence = RawEvidence(
            id="ev-test-001",
            case_id=sample_case.case_id,
            collector="test_collector",
            source_url="https://example.com/data",
            raw_payload='{"test": "data"}',
            payload_hash="abc123",
            timestamp=current_utc_iso(),
        )
        temp_db.insert_evidence(evidence)

        query = SearchEvidenceQuery(db=temp_db, case_id=sample_case.case_id)

        result = await query.execute()

        assert result.success is True
        assert result.data["total"] == 1

    @pytest.mark.asyncio
    async def test_search_evidence_with_collector_filter(self, temp_db, sample_case):
        """Test buscar evidencias filtradas por colector."""
        from specter.osint_core.models import RawEvidence, current_utc_iso

        evidence = RawEvidence(
            id="ev-test-002",
            case_id=sample_case.case_id,
            collector="specific_collector",
            source_url="https://example.com",
            raw_payload="{}",
            payload_hash="def456",
            timestamp=current_utc_iso(),
        )
        temp_db.insert_evidence(evidence)

        query = SearchEvidenceQuery(
            db=temp_db,
            case_id=sample_case.case_id,
            collector="specific_collector",
        )

        result = await query.execute()

        assert result.success is True
        assert result.data["total"] == 1

    @pytest.mark.asyncio
    async def test_search_evidence_case_not_found(self, temp_db):
        """Test buscar evidencias de un caso inexistente."""
        query = SearchEvidenceQuery(db=temp_db, case_id="case-inexistente")

        result = await query.execute()

        assert result.success is False


class TestGetTimelineQuery:
    """Tests para GetTimelineQuery."""

    @pytest.mark.asyncio
    async def test_get_timeline_success(self, temp_db, sample_case, sample_data):
        """Test obtener el timeline exitosamente."""
        query = GetTimelineQuery(db=temp_db, case_id=sample_case.case_id)

        result = await query.execute()

        assert result.success is True
        assert "timeline" in result.data
        assert result.data["timeline"]["case_id"] == sample_case.case_id

    @pytest.mark.asyncio
    async def test_get_timeline_invalid_bucket(self, temp_db, sample_case):
        """Test obtener timeline con bucket inválido."""
        query = GetTimelineQuery(
            db=temp_db,
            case_id=sample_case.case_id,
            bucket="invalid",
        )

        errors = query.validate()

        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_get_timeline_case_not_found(self, temp_db):
        """Test obtener timeline de un caso inexistente."""
        query = GetTimelineQuery(db=temp_db, case_id="case-inexistente")

        result = await query.execute()

        assert result.success is False


class TestGetCorrelationsQuery:
    """Tests para GetCorrelationsQuery."""

    @pytest.mark.asyncio
    async def test_get_correlations_success(self, temp_db, sample_case, sample_data):
        """Test obtener correlaciones exitosamente."""
        query = GetCorrelationsQuery(db=temp_db, case_id=sample_case.case_id)

        result = await query.execute()

        assert result.success is True
        assert "correlations" in result.data

    @pytest.mark.asyncio
    async def test_get_correlations_global(self, temp_db):
        """Test obtener correlaciones globales."""
        query = GetCorrelationsQuery(db=temp_db, case_id=None)

        result = await query.execute()

        assert result.success is True

"""
Tests para los comandos CQRS de WraithOSINT.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from specter.osint_core.commands import (
    CreateCaseCommand,
    DeleteCaseCommand,
    ExportReportCommand,
    ResolveEntityCommand,
    RunCollectorCommand,
    UpdateGraphCommand,
)
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


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_commands.db"
        yield Database(db_path)


@pytest.fixture
def graph(temp_db):
    return OSINTGraph(temp_db)


@pytest.fixture
def ledger(temp_db):
    return ForensicLedger(temp_db, signing_key=None)


@pytest.fixture
def sample_case(temp_db, ledger):
    case = CaseMetadata(
        case_id="case-test-001",
        name="Caso de Prueba",
        description="Descripción del caso de prueba",
        investigator="Analista_Test",
    )
    temp_db.create_case(case)
    # Inicializar el ledger con bloque génesis
    ledger.initialize_case_genesis(case)
    return case


@pytest.fixture
def sample_case_no_ledger(temp_db):
    """Caso sin inicializar ledger (para tests de validación)."""
    case = CaseMetadata(
        case_id="case-test-002",
        name="Caso sin Ledger",
        description="Caso para tests de validación",
        investigator="Analista_Test",
    )
    temp_db.create_case(case)
    return case


class TestCreateCaseCommand:
    """Tests para CreateCaseCommand."""

    @pytest.mark.asyncio
    async def test_create_case_success(self, temp_db, ledger):
        """Test crear un caso exitosamente."""
        cmd = CreateCaseCommand(
            db=temp_db,
            ledger=ledger,
            name="Nuevo Caso",
            description="Descripción del nuevo caso",
            investigator="Analista_01",
        )

        result = await cmd.execute()

        assert result.success is True
        assert "case_id" in result.data
        assert result.data["name"] == "Nuevo Caso"
        assert "genesis_hash" in result.data

    @pytest.mark.asyncio
    async def test_create_case_validation_empty_name(self, temp_db, ledger):
        """Test validación con nombre vacío."""
        cmd = CreateCaseCommand(
            db=temp_db,
            ledger=ledger,
            name="",
            description="Descripción",
        )

        errors = cmd.validate()

        assert len(errors) > 0
        assert any("name" in e for e in errors)

    @pytest.mark.asyncio
    async def test_create_case_undo(self, temp_db, ledger):
        """Test deshacer creación de caso."""
        cmd = CreateCaseCommand(
            db=temp_db,
            ledger=ledger,
            name="Caso a Deshacer",
            description="Descripción",
        )

        result = await cmd.execute()
        assert result.success is True

        undo_result = await cmd.undo()
        assert undo_result.success is True

        # Verificar que el caso fue eliminado
        case = temp_db.get_case(result.data["case_id"])
        assert case is None


class TestDeleteCaseCommand:
    """Tests para DeleteCaseCommand."""

    @pytest.mark.asyncio
    async def test_delete_case_success(self, temp_db, ledger, sample_case):
        """Test eliminar un caso exitosamente."""
        cmd = DeleteCaseCommand(
            db=temp_db,
            ledger=ledger,
            case_id=sample_case.case_id,
        )

        result = await cmd.execute()

        assert result.success is True
        assert result.data["case_id"] == sample_case.case_id

        # Verificar que el caso fue eliminado
        case = temp_db.get_case(sample_case.case_id)
        assert case is None

    @pytest.mark.asyncio
    async def test_delete_case_not_found(self, temp_db, ledger):
        """Test eliminar un caso que no existe."""
        cmd = DeleteCaseCommand(
            db=temp_db,
            ledger=ledger,
            case_id="case-inexistente",
        )

        result = await cmd.execute()

        assert result.success is False
        assert "no existe" in result.message


class TestRunCollectorCommand:
    """Tests para RunCollectorCommand."""

    @pytest.mark.asyncio
    async def test_run_collector_success(self, temp_db, graph, ledger, sample_case):
        """Test ejecutar un colector exitosamente."""

        class MockCollector:
            name = "mock_collector"

            async def collect(self, target: str, **kwargs):
                return CollectorResult(
                    collector_name="mock_collector",
                    source_target=target,
                    entities=[
                        EntityNode.create(EntityType.DOMAIN, target, "Test Domain"),
                    ],
                    relations=[],
                )

        cmd = RunCollectorCommand(
            db=temp_db,
            graph=graph,
            ledger=ledger,
            case_id=sample_case.case_id,
            collector=MockCollector(),
            target="example.com",
        )

        result = await cmd.execute()

        assert result.success is True
        assert result.data["collector"] == "mock_collector"
        assert result.data["entities_found"] == 1

    @pytest.mark.asyncio
    async def test_run_collector_no_ledger(self, temp_db, graph, ledger, sample_case_no_ledger):
        """Test ejecutar colector sin ledger inicializado."""

        class MockCollector:
            name = "mock_collector"

            async def collect(self, target: str, **kwargs):
                return CollectorResult(
                    collector_name="mock_collector",
                    source_target=target,
                    entities=[
                        EntityNode.create(EntityType.DOMAIN, target, "Test Domain"),
                    ],
                    relations=[],
                )

        cmd = RunCollectorCommand(
            db=temp_db,
            graph=graph,
            ledger=ledger,
            case_id=sample_case_no_ledger.case_id,
            collector=MockCollector(),
            target="example.com",
        )

        result = await cmd.execute()

        assert result.success is False
        assert "Génesis" in result.message or "ledger" in result.message.lower()

    @pytest.mark.asyncio
    async def test_run_collector_case_not_found(self, temp_db, graph, ledger):
        """Test ejecutar colector con caso inexistente."""

        class MockCollector:
            name = "mock_collector"

            async def collect(self, target: str, **kwargs):
                return CollectorResult(
                    collector_name="mock_collector",
                    source_target=target,
                )

        cmd = RunCollectorCommand(
            db=temp_db,
            graph=graph,
            ledger=ledger,
            case_id="case-inexistente",
            collector=MockCollector(),
            target="example.com",
        )

        result = await cmd.execute()

        assert result.success is False
        assert "no existe" in result.message


class TestResolveEntityCommand:
    """Tests para ResolveEntityCommand."""

    @pytest.mark.asyncio
    async def test_resolve_entity_success(self, temp_db, graph, ledger, sample_case):
        """Test resolver una entidad exitosamente."""
        cmd = ResolveEntityCommand(
            db=temp_db,
            graph=graph,
            ledger=ledger,
            case_id=sample_case.case_id,
            entity_type=EntityType.DOMAIN,
            value="example.com",
            label="Example Domain",
            confidence=0.95,
        )

        result = await cmd.execute()

        assert result.success is True
        assert result.data["entity_id"] == "domain:example.com"
        assert result.data["type"] == "DOMAIN"

    @pytest.mark.asyncio
    async def test_resolve_entity_validation(self, temp_db, graph, ledger, sample_case):
        """Test validación de ResolveEntityCommand."""
        cmd = ResolveEntityCommand(
            db=temp_db,
            graph=graph,
            ledger=ledger,
            case_id=sample_case.case_id,
            entity_type=EntityType.DOMAIN,
            value="",  # Valor vacío
        )

        errors = cmd.validate()

        assert len(errors) > 0
        assert any("value" in e for e in errors)


class TestUpdateGraphCommand:
    """Tests para UpdateGraphCommand."""

    @pytest.mark.asyncio
    async def test_update_graph_success(self, temp_db, graph, ledger, sample_case):
        """Test actualizar el grafo exitosamente."""
        entities = [
            EntityNode.create(EntityType.DOMAIN, "example.com"),
            EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1"),
        ]
        relations = [
            RelationEdge(
                source_id="domain:example.com",
                target_id="ip:192.168.1.1",
                relation_type=RelationType.RESOLVES_TO,
            ),
        ]

        cmd = UpdateGraphCommand(
            db=temp_db,
            graph=graph,
            ledger=ledger,
            case_id=sample_case.case_id,
            entities=entities,
            relations=relations,
        )

        result = await cmd.execute()

        assert result.success is True
        assert result.data["entities_added"] == 2
        assert result.data["relations_added"] == 1

    @pytest.mark.asyncio
    async def test_update_graph_validation_empty(self, temp_db, graph, ledger, sample_case):
        """Test validación con entidades y relaciones vacías."""
        cmd = UpdateGraphCommand(
            db=temp_db,
            graph=graph,
            ledger=ledger,
            case_id=sample_case.case_id,
            entities=[],
            relations=[],
        )

        errors = cmd.validate()

        assert len(errors) > 0


class TestExportReportCommand:
    """Tests para ExportReportCommand."""

    @pytest.mark.asyncio
    async def test_export_report_success(self, temp_db, ledger, sample_case):
        """Test exportar un reporte exitosamente."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"

            cmd = ExportReportCommand(
                db=temp_db,
                ledger=ledger,
                case_id=sample_case.case_id,
                output_path=output_path,
                format="json",
            )

            result = await cmd.execute()

            assert result.success is True
            assert output_path.exists()
            assert result.data["format"] == "json"

    @pytest.mark.asyncio
    async def test_export_report_invalid_format(self, temp_db, ledger, sample_case):
        """Test exportar con formato inválido."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.xml"

            cmd = ExportReportCommand(
                db=temp_db,
                ledger=ledger,
                case_id=sample_case.case_id,
                output_path=output_path,
                format="xml",  # Formato inválido
            )

            errors = cmd.validate()

            assert len(errors) > 0
            assert any("format" in e for e in errors)

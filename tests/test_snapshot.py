"""
Tests del Snapshot Service.

Cubre captura de snapshots, diff forense, revert y persistencia.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from specter.osint_core.database import Database
from specter.osint_core.models import (
    CaseMetadata,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)
from specter.osint_core.snapshot import SnapshotService


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    """BD aislada para tests."""
    db_path = tmp_path / "test.db"
    return Database(db_path)


@pytest.fixture()
def snapshot_service(db: Database, tmp_path: Path) -> SnapshotService:
    """Servicio de snapshots con directorio temporal."""
    snapshots_dir = tmp_path / "snapshots"
    return SnapshotService(db, snapshots_dir)


@pytest.fixture()
def sample_case(db: Database) -> str:
    """Caso de prueba con entidades y relaciones."""
    case = CaseMetadata(
        case_id="case-test",
        name="Caso Test",
        description="Prueba de snapshots",
        investigator="pytest",
    )
    db.create_case(case)

    # Entidades iniciales
    domain = EntityNode.create(EntityType.DOMAIN, "example.com", "Example")
    ip = EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1", "Example IP")
    db.upsert_entities("case-test", [domain, ip])

    # Relación inicial
    rel = RelationEdge(
        source_id=domain.id,
        target_id=ip.id,
        relation_type=RelationType.RESOLVES_TO,
    )
    db.upsert_relations("case-test", [rel])

    return "case-test"


def test_capture_snapshot(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """capture() crea un snapshot con las entidades y relaciones actuales."""
    snapshot = snapshot_service.capture(sample_case, description="Snapshot inicial")

    assert snapshot.metadata.case_id == sample_case
    assert snapshot.metadata.entity_count == 2
    assert snapshot.metadata.relation_count == 1
    assert snapshot.metadata.description == "Snapshot inicial"
    assert len(snapshot.entities) == 2
    assert len(snapshot.relations) == 1


def test_snapshot_persistido_en_disco(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """El snapshot se guarda en disco como JSON."""
    snapshot = snapshot_service.capture(sample_case)

    path = snapshot_service._snapshot_path(snapshot.metadata.snapshot_id)
    assert path.exists()

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["metadata"]["case_id"] == sample_case
    assert len(data["entities"]) == 2


def test_load_snapshot(db: Database, snapshot_service: SnapshotService, sample_case: str) -> None:
    """load() recupera un snapshot desde disco."""
    snapshot = snapshot_service.capture(sample_case)
    loaded = snapshot_service.load(snapshot.metadata.snapshot_id)

    assert loaded is not None
    assert loaded.metadata.snapshot_id == snapshot.metadata.snapshot_id
    assert len(loaded.entities) == len(snapshot.entities)
    assert len(loaded.relations) == len(snapshot.relations)


def test_load_snapshot_inexistente(snapshot_service: SnapshotService) -> None:
    """load() retorna None si no existe."""
    assert snapshot_service.load("snap-inexistente") is None


def test_diff_sin_cambios(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """diff() entre snapshots idénticos no muestra cambios."""
    snap1 = snapshot_service.capture(sample_case)
    snap2 = snapshot_service.capture(sample_case)

    diff = snapshot_service.diff(snap1, snap2)
    assert diff.is_empty is True
    assert diff.summary["added_entities"] == 0


def test_diff_con_cambios(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """diff() detecta entidades añadidas, eliminadas y modificadas."""
    snap1 = snapshot_service.capture(sample_case)

    # Añadir entidad
    new_entity = EntityNode.create(EntityType.EMAIL, "test@example.com")
    db.upsert_entities(sample_case, [new_entity])

    # Modificar entidad existente
    modified_ip = EntityNode.create(
        EntityType.IP_ADDRESS, "192.168.1.1", "Modified IP", confidence=0.5
    )
    db.upsert_entities(sample_case, [modified_ip])

    snap2 = snapshot_service.capture(sample_case)

    diff = snapshot_service.diff(snap1, snap2)
    assert diff.is_empty is False
    assert len(diff.added_entities) == 1
    assert diff.added_entities[0].value == "test@example.com"
    assert len(diff.modified_entities) == 1


def test_diff_relaciones(db: Database, snapshot_service: SnapshotService, sample_case: str) -> None:
    """diff() detecta relaciones añadidas y eliminadas."""
    snap1 = snapshot_service.capture(sample_case)

    # Añadir nueva relación
    domain = EntityNode.create(EntityType.DOMAIN, "example.com")
    email = EntityNode.create(EntityType.EMAIL, "admin@example.com")
    db.upsert_entities(sample_case, [email])

    new_rel = RelationEdge(
        source_id=email.id,
        target_id=domain.id,
        relation_type=RelationType.REGISTERED_BY,
    )
    db.upsert_relations(sample_case, [new_rel])

    snap2 = snapshot_service.capture(sample_case)

    diff = snapshot_service.diff(snap1, snap2)
    assert len(diff.added_relations) == 1
    assert diff.added_relations[0].relation_type == RelationType.REGISTERED_BY


def test_revert_snapshot(db: Database, snapshot_service: SnapshotService, sample_case: str) -> None:
    """revert() restaura el grafo al estado del snapshot."""
    # Capturar estado inicial
    snap1 = snapshot_service.capture(sample_case, description="Antes de cambios")

    # Hacer cambios
    new_entity = EntityNode.create(EntityType.PERSON, "John Doe")
    db.upsert_entities(sample_case, [new_entity])

    # Verificar que hay más entidades
    entities = db.get_case_entities(sample_case)
    assert len(entities) == 3

    # Revertir
    result = snapshot_service.revert(sample_case, snap1)
    assert result["status"] == "REVERTED"
    assert result["removed_entities"] == 1

    # Verificar que se restauró
    entities_after = db.get_case_entities(sample_case)
    assert len(entities_after) == 2


def test_revert_snapshot_caso_incorrecto(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """revert() lanza error si el snapshot no pertenece al caso."""
    snapshot = snapshot_service.capture(sample_case)

    with pytest.raises(ValueError, match="no pertenece al caso"):
        snapshot_service.revert("case-otro", snapshot)


def test_list_snapshots(db: Database, snapshot_service: SnapshotService, sample_case: str) -> None:
    """list_snapshots() retorna snapshots ordenados por fecha."""
    snap1 = snapshot_service.capture(sample_case, description="Primero")
    snap2 = snapshot_service.capture(sample_case, description="Segundo")

    snapshots = snapshot_service.list_snapshots(sample_case)
    assert len(snapshots) == 2
    # Más reciente primero
    assert snapshots[0].snapshot_id == snap2.metadata.snapshot_id
    assert snapshots[1].snapshot_id == snap1.metadata.snapshot_id


def test_list_snapshots_filtra_por_caso(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """list_snapshots() filtra por caseID."""
    # Crear otro caso
    case2 = CaseMetadata(
        case_id="case-otro",
        name="Otro",
        description="Otro caso",
        investigator="pytest",
    )
    db.create_case(case2)

    snapshot_service.capture(sample_case)
    snapshot_service.capture("case-otro")

    snapshots = snapshot_service.list_snapshots(sample_case)
    assert len(snapshots) == 1
    assert snapshots[0].case_id == sample_case


def test_delete_snapshot(db: Database, snapshot_service: SnapshotService, sample_case: str) -> None:
    """delete_snapshot() elimina el archivo de disco."""
    snapshot = snapshot_service.capture(sample_case)
    path = snapshot_service._snapshot_path(snapshot.metadata.snapshot_id)
    assert path.exists()

    result = snapshot_service.delete_snapshot(snapshot.metadata.snapshot_id)
    assert result is True
    assert not path.exists()

    # Eliminar de nuevo retorna False
    result = snapshot_service.delete_snapshot(snapshot.metadata.snapshot_id)
    assert result is False


def test_cleanup_old_snapshots(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """cleanup_old_snapshots() elimina snapshots antiguos."""
    # Crear 5 snapshots
    for i in range(5):
        snapshot_service.capture(sample_case, description=f"Snapshot {i}")

    snapshots = snapshot_service.list_snapshots(sample_case)
    assert len(snapshots) == 5

    # Mantener solo 3
    deleted = snapshot_service.cleanup_old_snapshots(sample_case, keep=3)
    assert deleted == 2

    snapshots_after = snapshot_service.list_snapshots(sample_case)
    assert len(snapshots_after) == 3


def test_snapshot_metadata_tags(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """Los tags se guardan en los metadatos."""
    snapshot = snapshot_service.capture(
        sample_case, description="Con tags", tags=["pre-cambio", "backup"]
    )
    assert snapshot.metadata.tags == ["pre-cambio", "backup"]


def test_snapshot_diff_summary(
    db: Database, snapshot_service: SnapshotService, sample_case: str
) -> None:
    """El summary del diff cuenta correctamente los cambios."""
    snap1 = snapshot_service.capture(sample_case)

    # Añadir 2 entidades
    db.upsert_entities(
        sample_case,
        [
            EntityNode.create(EntityType.PERSON, "Alice"),
            EntityNode.create(EntityType.PERSON, "Bob"),
        ],
    )

    snap2 = snapshot_service.capture(sample_case)
    diff = snapshot_service.diff(snap1, snap2)

    summary = diff.summary
    assert summary["added_entities"] == 2
    assert summary["removed_entities"] == 0
    assert summary["modified_entities"] == 0


def test_snapshot_vacio(db: Database, snapshot_service: SnapshotService) -> None:
    """Capturar snapshot de caso sin entidades."""
    case = CaseMetadata(
        case_id="case-vacio",
        name="Vacío",
        description="Sin entidades",
        investigator="pytest",
    )
    db.create_case(case)

    snapshot = snapshot_service.capture("case-vacio")
    assert snapshot.metadata.entity_count == 0
    assert snapshot.metadata.relation_count == 0
    assert len(snapshot.entities) == 0


def test_revert_snapshot_vacio(db: Database, snapshot_service: SnapshotService) -> None:
    """Revertir a snapshot vacío elimina todas las entidades."""
    case = CaseMetadata(
        case_id="case-revert",
        name="Revert",
        description="Prueba revert",
        investigator="pytest",
    )
    db.create_case(case)

    # Capturar vacío
    snap_vacio = snapshot_service.capture("case-revert")

    # Añadir entidades
    db.upsert_entities(
        "case-revert",
        [
            EntityNode.create(EntityType.DOMAIN, "test.com"),
        ],
    )

    # Revertir a vacío
    result = snapshot_service.revert("case-revert", snap_vacio)
    assert result["removed_entities"] == 1

    entities = db.get_case_entities("case-revert")
    assert len(entities) == 0

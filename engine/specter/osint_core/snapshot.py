"""
WraithOSINT - Snapshot Service
Servicio de snapshots del grafo forense con capacidad de captura,
diff forense y revert en caso de corrupción o error.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from specter.osint_core.database import Database
from specter.osint_core.models import EntityNode, RelationEdge, current_utc_iso


class SnapshotMetadata(BaseModel):
    """Metadatos de un snapshot."""

    snapshot_id: str
    case_id: str
    created_at: str = Field(default_factory=current_utc_iso)
    description: str = ""
    entity_count: int = 0
    relation_count: int = 0
    tags: list[str] = Field(default_factory=list)


@dataclass
class GraphSnapshot:
    """Snapshot completo del grafo de un caso."""

    metadata: SnapshotMetadata
    entities: dict[str, EntityNode] = field(default_factory=dict)
    relations: dict[str, RelationEdge] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializa el snapshot a dict."""
        return {
            "metadata": self.metadata.model_dump(),
            "entities": {k: v.model_dump() for k, v in self.entities.items()},
            "relations": {k: v.model_dump() for k, v in self.relations.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GraphSnapshot:
        """Deserializa un snapshot desde dict."""
        metadata = SnapshotMetadata(**data["metadata"])
        entities = {k: EntityNode(**v) for k, v in data.get("entities", {}).items()}
        relations = {k: RelationEdge(**v) for k, v in data.get("relations", {}).items()}
        return cls(metadata=metadata, entities=entities, relations=relations)


class SnapshotDiff(BaseModel):
    """Diferencia forense entre dos snapshots."""

    added_entities: list[EntityNode] = Field(default_factory=list)
    removed_entities: list[EntityNode] = Field(default_factory=list)
    modified_entities: list[dict[str, Any]] = Field(default_factory=list)
    added_relations: list[RelationEdge] = Field(default_factory=list)
    removed_relations: list[RelationEdge] = Field(default_factory=list)
    modified_relations: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True si no hay cambios."""
        return not any(
            [
                self.added_entities,
                self.removed_entities,
                self.modified_entities,
                self.added_relations,
                self.removed_relations,
                self.modified_relations,
            ]
        )

    @property
    def summary(self) -> dict[str, int]:
        """Resumen de cambios."""
        return {
            "added_entities": len(self.added_entities),
            "removed_entities": len(self.removed_entities),
            "modified_entities": len(self.modified_entities),
            "added_relations": len(self.added_relations),
            "removed_relations": len(self.removed_relations),
            "modified_relations": len(self.modified_relations),
        }


class SnapshotService:
    """Servicio de snapshots del grafo forense.

    Captura el estado del grafo antes de operaciones destructivas,
    permite diffs forenses y revertir a un estado anterior.
    """

    def __init__(self, db: Database, snapshots_dir: str | Path | None = None) -> None:
        self.db = db
        if snapshots_dir is None:
            snapshots_dir = Path(db.db_path).parent / "snapshots"
        self.snapshots_dir = Path(snapshots_dir)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def _snapshot_path(self, snapshot_id: str) -> Path:
        """Ruta de un snapshot en disco."""
        return self.snapshots_dir / f"{snapshot_id}.json"

    def capture(
        self,
        case_id: str,
        description: str = "",
        tags: list[str] | None = None,
    ) -> GraphSnapshot:
        """Captura un snapshot del estado actual del grafo.

        Args:
            case_id: ID del caso.
            description: Descripción del snapshot.
            tags: Etiquetas para clasificar el snapshot.

        Returns:
            El snapshot capturado.
        """
        entities_list = self.db.get_case_entities(case_id)
        relations_list = self.db.get_case_relations(case_id)

        entities = {e.id: e for e in entities_list}
        relations = {r.edge_id: r for r in relations_list}

        snapshot_id = f"snap-{uuid.uuid4().hex[:12]}"
        metadata = SnapshotMetadata(
            snapshot_id=snapshot_id,
            case_id=case_id,
            description=description,
            entity_count=len(entities),
            relation_count=len(relations),
            tags=tags or [],
        )

        snapshot = GraphSnapshot(
            metadata=metadata,
            entities=entities,
            relations=relations,
        )

        # Persistir en disco
        path = self._snapshot_path(snapshot_id)
        path.write_text(
            json.dumps(snapshot.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        return snapshot

    def load(self, snapshot_id: str) -> GraphSnapshot | None:
        """Carga un snapshot desde disco.

        Returns:
            El snapshot o None si no existe.
        """
        path = self._snapshot_path(snapshot_id)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return GraphSnapshot.from_dict(data)

    def diff(
        self,
        from_snapshot: GraphSnapshot,
        to_snapshot: GraphSnapshot,
    ) -> SnapshotDiff:
        """Calcula la diferencia forense entre dos snapshots.

        Args:
            from_snapshot: Snapshot origen (estado anterior).
            to_snapshot: Snapshot destino (estado posterior).

        Returns:
            La diferencia entre ambos snapshots.
        """
        diff = SnapshotDiff()

        from_entities = from_snapshot.entities
        to_entities = to_snapshot.entities

        # Entidades añadidas
        for eid, entity in to_entities.items():
            if eid not in from_entities:
                diff.added_entities.append(entity)

        # Entidades eliminadas
        for eid, entity in from_entities.items():
            if eid not in to_entities:
                diff.removed_entities.append(entity)

        # Entidades modificadas
        for eid, from_entity in from_entities.items():
            to_entity = to_entities.get(eid)
            if to_entity and from_entity != to_entity:
                diff.modified_entities.append(
                    {
                        "id": eid,
                        "before": from_entity.model_dump(),
                        "after": to_entity.model_dump(),
                    }
                )

        from_relations = from_snapshot.relations
        to_relations = to_snapshot.relations

        # Relaciones añadidas
        for rid, rel in to_relations.items():
            if rid not in from_relations:
                diff.added_relations.append(rel)

        # Relaciones eliminadas
        for rid, rel in from_relations.items():
            if rid not in to_relations:
                diff.removed_relations.append(rel)

        # Relaciones modificadas
        for rid, from_rel in from_relations.items():
            to_rel = to_relations.get(rid)
            if to_rel and from_rel != to_rel:
                diff.modified_relations.append(
                    {
                        "edge_id": rid,
                        "before": from_rel.model_dump(),
                        "after": to_rel.model_dump(),
                    }
                )

        return diff

    def revert(self, case_id: str, snapshot: GraphSnapshot) -> dict[str, Any]:
        """Revierte el grafo de un caso a un snapshot.

        Args:
            case_id: ID del caso.
            snapshot: Snapshot al que revertir.

        Returns:
            Resumen de la operación de revert.
        """
        # Verificar que el snapshot es del caso
        if snapshot.metadata.case_id != case_id:
            raise ValueError(
                f"Snapshot {snapshot.metadata.snapshot_id} no pertenece al caso {case_id}"
            )

        # Eliminar entidades actuales que no están en el snapshot
        current_entities = self.db.get_case_entities(case_id)
        current_ids = {e.id for e in current_entities}
        snapshot_ids = set(snapshot.entities.keys())

        # Eliminar entidades que no están en el snapshot
        removed_entities = current_ids - snapshot_ids
        if removed_entities:
            self._delete_entities(case_id, removed_entities)

        # Eliminar relaciones actuales que no están en el snapshot
        current_relations = self.db.get_case_relations(case_id)
        current_rel_ids = {r.edge_id for r in current_relations}
        snapshot_rel_ids = set(snapshot.relations.keys())

        removed_relations = current_rel_ids - snapshot_rel_ids
        if removed_relations:
            self._delete_relations(case_id, removed_relations)

        # Insertar/actualizar entidades del snapshot
        entities_to_upsert = list(snapshot.entities.values())
        if entities_to_upsert:
            self.db.upsert_entities(case_id, entities_to_upsert)

        # Insertar/actualizar relaciones del snapshot
        relations_to_upsert = list(snapshot.relations.values())
        if relations_to_upsert:
            self.db.upsert_relations(case_id, relations_to_upsert)

        return {
            "status": "REVERTED",
            "case_id": case_id,
            "snapshot_id": snapshot.metadata.snapshot_id,
            "removed_entities": len(removed_entities),
            "removed_relations": len(removed_relations),
            "restored_entities": len(entities_to_upsert),
            "restored_relations": len(relations_to_upsert),
        }

    def _delete_entities(self, case_id: str, entity_ids: set[str]) -> None:
        """Elimina entidades de un caso."""
        with self.db.get_connection() as conn:
            for eid in entity_ids:
                conn.execute(
                    "DELETE FROM entities WHERE case_id = ? AND id = ?",
                    (case_id, eid),
                )

    def _delete_relations(self, case_id: str, relation_ids: set[str]) -> None:
        """Elimina relaciones de un caso."""
        with self.db.get_connection() as conn:
            for rid in relation_ids:
                conn.execute(
                    "DELETE FROM relations WHERE case_id = ? AND edge_id = ?",
                    (case_id, rid),
                )

    def list_snapshots(self, case_id: str) -> list[SnapshotMetadata]:
        """Lista los snapshots de un caso.

        Returns:
            Lista de metadatos de snapshots ordenados por fecha descendente.
        """
        snapshots: list[SnapshotMetadata] = []
        for path in self.snapshots_dir.glob("snap-*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                metadata = SnapshotMetadata(**data["metadata"])
                if metadata.case_id == case_id:
                    snapshots.append(metadata)
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        return sorted(snapshots, key=lambda s: s.created_at, reverse=True)

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Elimina un snapshot de disco.

        Returns:
            True si existía y fue eliminado.
        """
        path = self._snapshot_path(snapshot_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def cleanup_old_snapshots(self, case_id: str, keep: int = 10) -> int:
        """Elimina snapshots antiguos manteniendo solo los más recientes.

        Args:
            case_id: ID del caso.
            keep: Número de snapshots a mantener.

        Returns:
            Número de snapshots eliminados.
        """
        snapshots = self.list_snapshots(case_id)
        if len(snapshots) <= keep:
            return 0

        to_delete = snapshots[keep:]
        deleted = 0
        for snap in to_delete:
            if self.delete_snapshot(snap.snapshot_id):
                deleted += 1
        return deleted

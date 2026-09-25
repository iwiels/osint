"""
SpecterOSINT - Database Layer
Gestor de persistencia SQLite optimizado para grafos y auditoría forense inmutable.
"""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from specter.osint_core.models import (
    CaseMetadata,
    EntityNode,
    EntityType,
    LedgerBlock,
    RawEvidence,
    RelationEdge,
    RelationType,
)


class Database:
    def __init__(self, db_path: str | Path = "data/specter_osint.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self.get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    investigator TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                );

                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    label TEXT,
                    attributes_json TEXT NOT NULL DEFAULT '{}',
                    confidence REAL NOT NULL DEFAULT 1.0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (case_id, id),
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS relations (
                    edge_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    attributes_json TEXT NOT NULL DEFAULT '{}',
                    confidence REAL NOT NULL DEFAULT 1.0,
                    first_seen TEXT NOT NULL,
                    PRIMARY KEY (case_id, edge_id),
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS evidences (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    raw_payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS forensic_ledger (
                    case_id TEXT NOT NULL,
                    block_index INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    action TEXT NOT NULL,
                    evidence_id TEXT,
                    evidence_hash TEXT,
                    prev_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL,
                    PRIMARY KEY (case_id, block_index),
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_entities_case_type ON entities(case_id, type);
                CREATE INDEX IF NOT EXISTS idx_relations_case ON relations(case_id, source_id, target_id);
                CREATE INDEX IF NOT EXISTS idx_evidences_case ON evidences(case_id);
                CREATE INDEX IF NOT EXISTS idx_ledger_case ON forensic_ledger(case_id, block_index);
                """
            )

    # --- Operaciones de Casos ---

    def create_case(self, case: CaseMetadata) -> CaseMetadata:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO cases (case_id, name, description, investigator, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    case.case_id,
                    case.name,
                    case.description,
                    case.investigator,
                    case.created_at,
                    case.status,
                ),
            )
        return case

    def get_case(self, case_id: str) -> CaseMetadata | None:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return CaseMetadata(
                case_id=row["case_id"],
                name=row["name"],
                description=row["description"],
                investigator=row["investigator"],
                created_at=row["created_at"],
                status=row["status"],
            )

    def list_cases(self) -> list[CaseMetadata]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM cases ORDER BY created_at DESC")
            return [
                CaseMetadata(
                    case_id=row["case_id"],
                    name=row["name"],
                    description=row["description"],
                    investigator=row["investigator"],
                    created_at=row["created_at"],
                    status=row["status"],
                )
                for row in cursor.fetchall()
            ]

    # --- Operaciones de Evidencias ---

    def insert_evidence(self, evidence: RawEvidence) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO evidences (id, case_id, collector, source_url, raw_payload, payload_hash, timestamp, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.id,
                    evidence.case_id,
                    evidence.collector,
                    evidence.source_url,
                    evidence.raw_payload,
                    evidence.payload_hash,
                    evidence.timestamp,
                    json.dumps(evidence.metadata),
                ),
            )

    def get_evidence(self, evidence_id: str) -> RawEvidence | None:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM evidences WHERE id = ?", (evidence_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return RawEvidence(
                id=row["id"],
                case_id=row["case_id"],
                collector=row["collector"],
                source_url=row["source_url"],
                raw_payload=row["raw_payload"],
                payload_hash=row["payload_hash"],
                timestamp=row["timestamp"],
                metadata=json.loads(row["metadata_json"]),
            )

    # --- Operaciones de Grafo (Entidades y Relaciones) ---

    def upsert_entities(self, case_id: str, entities: list[EntityNode]) -> None:
        if not entities:
            return
        with self.get_connection() as conn:
            for entity in entities:
                conn.execute(
                    """
                    INSERT INTO entities (id, case_id, type, value, label, attributes_json, confidence, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(case_id, id) DO UPDATE SET
                        label = COALESCE(excluded.label, entities.label),
                        attributes_json = excluded.attributes_json,
                        confidence = MAX(entities.confidence, excluded.confidence),
                        last_seen = excluded.last_seen
                    """,
                    (
                        entity.id,
                        case_id,
                        entity.type.value,
                        entity.value,
                        entity.label,
                        json.dumps(entity.attributes),
                        entity.confidence,
                        entity.first_seen,
                        entity.last_seen,
                    ),
                )

    def upsert_relations(self, case_id: str, relations: list[RelationEdge]) -> None:
        if not relations:
            return
        with self.get_connection() as conn:
            for rel in relations:
                conn.execute(
                    """
                    INSERT INTO relations (edge_id, case_id, source_id, target_id, relation_type, attributes_json, confidence, first_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(case_id, edge_id) DO UPDATE SET
                        attributes_json = excluded.attributes_json,
                        confidence = MAX(relations.confidence, excluded.confidence)
                    """,
                    (
                        rel.edge_id,
                        case_id,
                        rel.source_id,
                        rel.target_id,
                        rel.relation_type.value,
                        json.dumps(rel.attributes),
                        rel.confidence,
                        rel.first_seen,
                    ),
                )

    def get_case_entities(self, case_id: str, entity_type: str | None = None) -> list[EntityNode]:
        with self.get_connection() as conn:
            query = "SELECT * FROM entities WHERE case_id = ?"
            params: list[Any] = [case_id]
            if entity_type:
                query += " AND type = ?"
                params.append(entity_type.upper())
            cursor = conn.execute(query, params)
            return [
                EntityNode(
                    id=row["id"],
                    type=EntityType(row["type"]),
                    value=row["value"],
                    label=row["label"],
                    attributes=json.loads(row["attributes_json"]),
                    confidence=row["confidence"],
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                )
                for row in cursor.fetchall()
            ]

    def get_case_relations(self, case_id: str) -> list[RelationEdge]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM relations WHERE case_id = ?", (case_id,))
            return [
                RelationEdge(
                    source_id=row["source_id"],
                    target_id=row["target_id"],
                    relation_type=RelationType(row["relation_type"]),
                    attributes=json.loads(row["attributes_json"]),
                    confidence=row["confidence"],
                    first_seen=row["first_seen"],
                )
                for row in cursor.fetchall()
            ]

    # --- Operaciones de Forensic Ledger ---

    def insert_ledger_block(self, block: LedgerBlock) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO forensic_ledger (case_id, block_index, timestamp, collector, action, evidence_id, evidence_hash, prev_hash, block_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block.case_id,
                    block.block_index,
                    block.timestamp,
                    block.collector,
                    block.action,
                    block.evidence_id,
                    block.evidence_hash,
                    block.prev_hash,
                    block.block_hash,
                ),
            )

    def get_case_ledger(self, case_id: str) -> list[LedgerBlock]:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM forensic_ledger WHERE case_id = ? ORDER BY block_index ASC",
                (case_id,),
            )
            return [
                LedgerBlock(
                    case_id=row["case_id"],
                    block_index=row["block_index"],
                    timestamp=row["timestamp"],
                    collector=row["collector"],
                    action=row["action"],
                    evidence_id=row["evidence_id"],
                    evidence_hash=row["evidence_hash"],
                    prev_hash=row["prev_hash"],
                    block_hash=row["block_hash"],
                )
                for row in cursor.fetchall()
            ]

    def get_latest_ledger_block(self, case_id: str) -> LedgerBlock | None:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM forensic_ledger WHERE case_id = ? ORDER BY block_index DESC LIMIT 1",
                (case_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return LedgerBlock(
                case_id=row["case_id"],
                block_index=row["block_index"],
                timestamp=row["timestamp"],
                collector=row["collector"],
                action=row["action"],
                evidence_id=row["evidence_id"],
                evidence_hash=row["evidence_hash"],
                prev_hash=row["prev_hash"],
                block_hash=row["block_hash"],
            )

"""
SpecterOSINT - Database Layer
Gestor de persistencia SQLite para casos, grafos y auditoría de evidencias.
"""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from specter.osint_core.models import (
    AgentMessage,
    AgentSession,
    CaseMetadata,
    EntityNode,
    EntityType,
    LedgerBlock,
    RawEvidence,
    RelationEdge,
    RelationType,
    current_utc_iso,
    parse_entity_type,
    parse_relation_type,
)


def _row_to_evidence(row: sqlite3.Row) -> RawEvidence:
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


def _row_to_block(row: sqlite3.Row) -> LedgerBlock:
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
        signature=row["signature"],
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
                    signature TEXT,
                    PRIMARY KEY (case_id, block_index),
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_entities_case_type ON entities(case_id, type);
                CREATE INDEX IF NOT EXISTS idx_relations_case ON relations(case_id, source_id, target_id);
                CREATE INDEX IF NOT EXISTS idx_evidences_case ON evidences(case_id);
                CREATE INDEX IF NOT EXISTS idx_ledger_case ON forensic_ledger(case_id, block_index);

                -- Conversaciones del agente (estilo opencode sessions/messages):
                -- qué preguntó el analista y qué ejecutó cada run. Sin FK a
                -- cases a propósito: también hay runs globales sin caso.
                CREATE TABLE IF NOT EXISTS agent_sessions (
                    session_id TEXT PRIMARY KEY,
                    case_id TEXT,
                    provider TEXT NOT NULL DEFAULT '',
                    model TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'running',
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    iterations INTEGER NOT NULL DEFAULT 0,
                    tools_used INTEGER NOT NULL DEFAULT 0,
                    input_tokens INTEGER NOT NULL DEFAULT 0,
                    output_tokens INTEGER NOT NULL DEFAULT 0,
                    prompt TEXT NOT NULL DEFAULT '',
                    summary TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS agent_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL DEFAULT '',
                    tool TEXT,
                    call_id TEXT,
                    extra_json TEXT NOT NULL DEFAULT '{}',
                    ts TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_agent_sessions_case ON agent_sessions(case_id, started_at);
                CREATE INDEX IF NOT EXISTS idx_agent_messages_session ON agent_messages(session_id, seq);
                """
            )
            # Migración incremental: bases creadas antes de la firma HMAC (fase B).
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(forensic_ledger)")}
            if "signature" not in columns:
                conn.execute("ALTER TABLE forensic_ledger ADD COLUMN signature TEXT")

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
            return _row_to_evidence(row) if row else None

    def get_case_evidences(self, case_id: str) -> list[RawEvidence]:
        """Toda la evidencia cruda de un caso, en orden temporal."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM evidences WHERE case_id = ? ORDER BY timestamp ASC", (case_id,)
            )
            return [_row_to_evidence(row) for row in cursor.fetchall()]

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
                for endpoint in (rel.source_id, rel.target_id):
                    stub = EntityNode.from_node_id(endpoint, first_seen=rel.first_seen)
                    conn.execute(
                        """
                        INSERT INTO entities (id, case_id, type, value, label, attributes_json, confidence, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, '{}', 1.0, ?, ?)
                        ON CONFLICT(case_id, id) DO NOTHING
                        """,
                        (
                            stub.id,
                            case_id,
                            stub.type.value,
                            stub.value,
                            stub.label,
                            stub.first_seen,
                            stub.last_seen,
                        ),
                    )
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
            entities: list[EntityNode] = []
            for row in cursor.fetchall():
                try:
                    e_type = parse_entity_type(row["type"], default=EntityType.UNKNOWN)
                    e_val = row["value"] or (
                        row["id"].split(":", 1)[1] if ":" in row["id"] else row["id"]
                    )
                    entities.append(
                        EntityNode(
                            id=row["id"],
                            type=e_type,
                            value=e_val,
                            label=row["label"] or e_val,
                            attributes=json.loads(row["attributes_json"] or "{}"),
                            confidence=row["confidence"] if row["confidence"] is not None else 1.0,
                            first_seen=row["first_seen"] or current_utc_iso(),
                            last_seen=row["last_seen"] or current_utc_iso(),
                        )
                    )
                except Exception:
                    entities.append(EntityNode.from_node_id(row["id"]))

            # Sintetizar stubs para extremos de relaciones que no estén en la tabla entities
            existing_ids = {e.id for e in entities}
            all_known_ids = {
                r[0]
                for r in conn.execute(
                    "SELECT id FROM entities WHERE case_id = ?", (case_id,)
                ).fetchall()
            }
            rel_cursor = conn.execute(
                "SELECT source_id, target_id, first_seen FROM relations WHERE case_id = ?",
                (case_id,),
            )
            stub_entities_to_insert: list[EntityNode] = []
            for r_row in rel_cursor.fetchall():
                for endpoint in (r_row["source_id"], r_row["target_id"]):
                    if endpoint not in all_known_ids:
                        all_known_ids.add(endpoint)
                        stub_node = EntityNode.from_node_id(
                            endpoint, first_seen=r_row["first_seen"]
                        )
                        stub_entities_to_insert.append(stub_node)
                        if endpoint not in existing_ids:
                            existing_ids.add(endpoint)
                            if (
                                not entity_type
                                or stub_node.type.value.upper() == entity_type.upper()
                            ):
                                entities.append(stub_node)

            if stub_entities_to_insert:
                for s in stub_entities_to_insert:
                    conn.execute(
                        """
                        INSERT INTO entities (id, case_id, type, value, label, attributes_json, confidence, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, '{}', 1.0, ?, ?)
                        ON CONFLICT(case_id, id) DO NOTHING
                        """,
                        (s.id, case_id, s.type.value, s.value, s.label, s.first_seen, s.last_seen),
                    )

            return entities

    def get_case_relations(self, case_id: str) -> list[RelationEdge]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM relations WHERE case_id = ?", (case_id,))
            relations: list[RelationEdge] = []
            for row in cursor.fetchall():
                try:
                    rel_type = parse_relation_type(
                        row["relation_type"], default=RelationType.ASSOCIATED_WITH
                    )
                    attrs = {}
                    if row["attributes_json"]:
                        try:
                            attrs = json.loads(row["attributes_json"])
                            if not isinstance(attrs, dict):
                                attrs = {}
                        except Exception:
                            attrs = {}
                    conf = row["confidence"]
                    confidence = float(conf) if conf is not None else 1.0
                    relations.append(
                        RelationEdge(
                            source_id=row["source_id"],
                            target_id=row["target_id"],
                            relation_type=rel_type,
                            attributes=attrs,
                            confidence=confidence,
                            first_seen=row["first_seen"] or current_utc_iso(),
                        )
                    )
                except Exception:
                    continue
            return relations

    # --- Correlación entre casos ---

    def find_shared_entities(
        self, case_id: str | None = None, entity_types: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Entidades con el mismo id canónico presentes en dos o más casos.

        Es la base de la correlación cross-case: un dominio, email o alias que
        aparece en dos investigaciones distintas es un vínculo real, no una
        coincidencia de búsqueda.
        """
        conditions: list[str] = []
        params: list[Any] = []
        if entity_types:
            placeholders = ",".join("?" * len(entity_types))
            conditions.append(f"type IN ({placeholders})")
            params.extend(t.upper() for t in entity_types)
        if case_id:
            conditions.append("id IN (SELECT id FROM entities WHERE case_id = ?)")
            params.append(case_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self.get_connection() as conn:
            cursor = conn.execute(
                f"""
                SELECT id, type, value, MAX(confidence) AS confidence,
                       COUNT(DISTINCT case_id) AS case_count,
                       GROUP_CONCAT(DISTINCT case_id) AS case_ids,
                       MIN(first_seen) AS first_seen,
                       MAX(last_seen) AS last_seen
                FROM entities
                {where}
                GROUP BY id, type
                HAVING case_count >= 2
                ORDER BY case_count DESC, id ASC
                """,
                params,
            )
            return [
                {
                    "id": row["id"],
                    "type": row["type"],
                    "value": row["value"],
                    "confidence": row["confidence"],
                    "case_count": row["case_count"],
                    "case_ids": row["case_ids"].split(","),
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                }
                for row in cursor.fetchall()
            ]

    # --- Operaciones de Forensic Ledger ---

    def insert_ledger_block(self, block: LedgerBlock) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO forensic_ledger (case_id, block_index, timestamp, collector, action, evidence_id, evidence_hash, prev_hash, block_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    block.signature,
                ),
            )

    def get_case_ledger(self, case_id: str) -> list[LedgerBlock]:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM forensic_ledger WHERE case_id = ? ORDER BY block_index ASC",
                (case_id,),
            )
            return [_row_to_block(row) for row in cursor.fetchall()]

    def get_latest_ledger_block(self, case_id: str) -> LedgerBlock | None:
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM forensic_ledger WHERE case_id = ? ORDER BY block_index DESC LIMIT 1",
                (case_id,),
            )
            row = cursor.fetchone()
            return _row_to_block(row) if row else None

    # --- Sesiones del agente (historial de conversación) ---

    @staticmethod
    def _row_to_agent_session(row: sqlite3.Row) -> AgentSession:
        return AgentSession(
            session_id=row["session_id"],
            case_id=row["case_id"],
            provider=row["provider"],
            model=row["model"],
            status=row["status"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            iterations=row["iterations"],
            tools_used=row["tools_used"],
            input_tokens=row["input_tokens"],
            output_tokens=row["output_tokens"],
            prompt=row["prompt"],
            summary=row["summary"],
        )

    def create_agent_session(self, session: AgentSession) -> AgentSession:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO agent_sessions
                    (session_id, case_id, provider, model, status, started_at,
                     ended_at, iterations, tools_used, input_tokens,
                     output_tokens, prompt, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO NOTHING
                """,
                (
                    session.session_id,
                    session.case_id,
                    session.provider,
                    session.model,
                    session.status,
                    session.started_at,
                    session.ended_at,
                    session.iterations,
                    session.tools_used,
                    session.input_tokens,
                    session.output_tokens,
                    session.prompt,
                    session.summary,
                ),
            )
        return session

    def append_agent_message(
        self,
        session_id: str,
        role: str,
        content: str,
        tool: str | None = None,
        call_id: str | None = None,
        extra: dict[str, Any] | None = None,
        ts: str | None = None,
    ) -> None:
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), -1) AS m FROM agent_messages WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO agent_messages
                    (session_id, seq, role, content, tool, call_id, extra_json, ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    int(row["m"]) + 1,
                    role,
                    content,
                    tool,
                    call_id,
                    json.dumps(extra or {}),
                    ts or current_utc_iso(),
                ),
            )

    def finish_agent_session(
        self,
        session_id: str,
        status: str,
        iterations: int,
        tools_used: int,
        input_tokens: int,
        output_tokens: int,
        summary: str,
        ended_at: str | None = None,
    ) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                UPDATE agent_sessions SET
                    status = ?, ended_at = ?,
                    iterations = COALESCE(iterations, 0) + ?,
                    tools_used = COALESCE(tools_used, 0) + ?,
                    input_tokens = COALESCE(input_tokens, 0) + ?,
                    output_tokens = COALESCE(output_tokens, 0) + ?,
                    summary = ?
                WHERE session_id = ?
                """,
                (
                    status,
                    ended_at or current_utc_iso(),
                    iterations,
                    tools_used,
                    input_tokens,
                    output_tokens,
                    summary,
                    session_id,
                ),
            )

    def list_agent_sessions(
        self, case_id: str | None = None, limit: int = 50
    ) -> list[AgentSession]:
        """Sesiones del agente, más recientes primero (opcionalmente de un caso)."""
        with self.get_connection() as conn:
            if case_id is None:
                cursor = conn.execute(
                    "SELECT * FROM agent_sessions ORDER BY started_at DESC LIMIT ?",
                    (max(1, limit),),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM agent_sessions WHERE case_id = ? "
                    "ORDER BY started_at DESC LIMIT ?",
                    (case_id, max(1, limit)),
                )
            return [self._row_to_agent_session(row) for row in cursor.fetchall()]

    def get_latest_case_session(self, case_id: str) -> AgentSession | None:
        """Retorna la sesión más reciente asociada a un caso."""
        sessions = self.list_agent_sessions(case_id=case_id, limit=1)
        return sessions[0] if sessions else None

    def get_agent_session(self, session_id: str) -> AgentSession | None:
        """Una sesión del agente por id (para el detalle del historial)."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM agent_sessions WHERE session_id = ?", (session_id,)
            )
            row = cursor.fetchone()
            return self._row_to_agent_session(row) if row else None

    def delete_agent_session(self, session_id: str) -> bool:
        """Borra una sesión y su transcripción. True si existía."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM agent_sessions WHERE session_id = ?", (session_id,)
            )
            if cursor.fetchone() is None:
                return False
            conn.execute("DELETE FROM agent_messages WHERE session_id = ?", (session_id,))
            conn.execute("DELETE FROM agent_sessions WHERE session_id = ?", (session_id,))
            return True

    def delete_case(self, case_id: str) -> bool:
        """Borra un caso con TODO lo suyo: entidades, relaciones, evidencias,
        ledger y sesiones del agente de ese caso. True si existía."""
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,))
            if cursor.fetchone() is None:
                return False
            # agent_sessions no tiene FK a cases (hay runs globales): borrado explícito.
            conn.execute(
                "DELETE FROM agent_messages WHERE session_id IN "
                "(SELECT session_id FROM agent_sessions WHERE case_id = ?)",
                (case_id,),
            )
            conn.execute("DELETE FROM agent_sessions WHERE case_id = ?", (case_id,))
            # entities/relations/evidences/ledger caen por ON DELETE CASCADE.
            conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            return True

    def get_agent_session_messages(self, session_id: str, limit: int = 500) -> list[AgentMessage]:
        """Transcripción ordenada de una sesión del agente."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM agent_messages WHERE session_id = ? ORDER BY seq ASC LIMIT ?",
                (session_id, max(1, limit)),
            )
            return [
                AgentMessage(
                    id=row["id"],
                    session_id=row["session_id"],
                    seq=row["seq"],
                    role=row["role"],
                    content=row["content"],
                    tool=row["tool"],
                    call_id=row["call_id"],
                    extra=json.loads(row["extra_json"] or "{}"),
                    ts=row["ts"],
                )
                for row in cursor.fetchall()
            ]

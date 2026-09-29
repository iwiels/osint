"""
SpecterOSINT - Event Store
Almacén de eventos inmutables con persistencia SQLite y replay de estado.

Inspirado en el Event Sourcing de OpenCode (packages/core/src/event/), adaptado
a la arquitectura Python/FastAPI de WraithOSINT. Cada evento es un hecho
inmutable con hash SHA-256 para verificación de integridad.

Patrón Durable Event Replay: el estado de un caso se reconstruye reproduciendo
la secuencia ordenada de eventos desde el principio (o desde un punto dado).
"""

import hashlib
import json
import uuid
from typing import Any

from pydantic import BaseModel, Field
from specter.osint_core.database import Database
from specter.osint_core.event_types import EventType
from specter.osint_core.models import current_utc_iso


class CaseEvent(BaseModel):
    """Evento inmutable del dominio.

    Cada evento tiene:
    - id: UUID único del evento
    - aggregate_id: case_id al que pertenece
    - seq: número secuencial monótono por aggregate
    - type: tipo de evento (EventType)
    - data: payload del evento (dict)
    - timestamp: fecha/hora UTC del evento
    - sha256: hash del evento para verificación de integridad
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    aggregate_id: str
    seq: int
    type: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=current_utc_iso)
    sha256: str = ""

    def compute_hash(self) -> str:
        """Calcula el hash SHA-256 del evento (excluyendo el campo sha256)."""
        payload = {
            "id": self.id,
            "aggregate_id": self.aggregate_id,
            "seq": self.seq,
            "type": self.type,
            "data": self.data,
            "timestamp": self.timestamp,
        }
        serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        """Verifica que el hash almacenado coincide con el contenido del evento."""
        return self.sha256 == self.compute_hash()


class EventStore:
    """Almacén de eventos inmutables con persistencia SQLite.

    Los eventos se guardan en la tabla `case_events` y nunca se modifican ni
    se eliminan: solo se añaden. El replay permite reconstruir el estado de
    un caso reproduciendo la secuencia ordenada de eventos.
    """

    def __init__(self, db: Database):
        self.db = db

    def publish(
        self,
        aggregate_id: str,
        event_type: str | EventType,
        data: dict[str, Any],
    ) -> CaseEvent:
        """Publica un evento con secuencia monótona por aggregate.

        Args:
            aggregate_id: ID del agregado (case_id)
            event_type: Tipo de evento (EventType o string)
            data: Payload del evento

        Returns:
            El evento creado con su hash SHA-256 calculado
        """
        event_type_str = event_type.value if isinstance(event_type, EventType) else event_type

        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM case_events WHERE aggregate_id = ?",
                (aggregate_id,),
            ).fetchone()
            next_seq = int(row["max_seq"]) + 1

        event = CaseEvent(
            id=str(uuid.uuid4()),
            aggregate_id=aggregate_id,
            seq=next_seq,
            type=event_type_str,
            data=data,
            timestamp=current_utc_iso(),
        )
        event.sha256 = event.compute_hash()

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO case_events (id, aggregate_id, seq, type, data, timestamp, sha256)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.aggregate_id,
                    event.seq,
                    event.type,
                    json.dumps(event.data, ensure_ascii=False),
                    event.timestamp,
                    event.sha256,
                ),
            )

        return event

    def get_events(
        self,
        aggregate_id: str,
        after: int | None = None,
    ) -> list[CaseEvent]:
        """Obtiene eventos de un aggregate, opcionalmente después de una secuencia.

        Args:
            aggregate_id: ID del agregado (case_id)
            after: Secuencia desde la cual obtener eventos (exclusivo)

        Returns:
            Lista de eventos ordenados por secuencia
        """
        with self.db.get_connection() as conn:
            if after is not None:
                cursor = conn.execute(
                    "SELECT * FROM case_events WHERE aggregate_id = ? AND seq > ? ORDER BY seq ASC",
                    (aggregate_id, after),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM case_events WHERE aggregate_id = ? ORDER BY seq ASC",
                    (aggregate_id,),
                )
            return [self._row_to_event(row) for row in cursor.fetchall()]

    def replay(
        self,
        aggregate_id: str,
        after: int | None = None,
    ) -> dict[str, Any]:
        """Replay de eventos para reconstruir el estado de un caso.

        Reproduce la secuencia ordenada de eventos y construye un resumen del
        estado actual del caso basado en los eventos ocurridos.

        Args:
            aggregate_id: ID del agregado (case_id)
            after: Secuencia desde la cual hacer replay (exclusivo)

        Returns:
            Diccionario con el estado reconstruido del caso
        """
        events = self.get_events(aggregate_id, after=after)

        # Estado reconstruido desde los eventos
        state: dict[str, Any] = {
            "case_id": aggregate_id,
            "total_events": len(events),
            "collectors_run": [],
            "entities_resolved": [],
            "correlations_found": [],
            "graph_updates": [],
            "reports_exported": [],
            "permissions_granted": [],
            "permissions_denied": [],
            "created": False,
            "closed": False,
            "first_event_at": None,
            "last_event_at": None,
        }

        for event in events:
            if state["first_event_at"] is None:
                state["first_event_at"] = event.timestamp
            state["last_event_at"] = event.timestamp

            match event.type:
                case EventType.COLLECTOR_RAN:
                    state["collectors_run"].append(
                        {
                            "collector": event.data.get("collector"),
                            "target": event.data.get("target"),
                            "entities_found": event.data.get("entities_found", 0),
                            "timestamp": event.timestamp,
                        }
                    )
                case EventType.ENTITY_RESOLVED:
                    state["entities_resolved"].append(
                        {
                            "entity_id": event.data.get("entity_id"),
                            "entity_type": event.data.get("entity_type"),
                            "value": event.data.get("value"),
                            "timestamp": event.timestamp,
                        }
                    )
                case EventType.CORRELATION_FOUND:
                    state["correlations_found"].append(
                        {
                            "source_id": event.data.get("source_id"),
                            "target_id": event.data.get("target_id"),
                            "relation_type": event.data.get("relation_type"),
                            "timestamp": event.timestamp,
                        }
                    )
                case EventType.GRAPH_UPDATED:
                    state["graph_updates"].append(
                        {
                            "nodes_added": event.data.get("nodes_added", 0),
                            "edges_added": event.data.get("edges_added", 0),
                            "timestamp": event.timestamp,
                        }
                    )
                case EventType.REPORT_EXPORTED:
                    state["reports_exported"].append(
                        {
                            "format": event.data.get("format"),
                            "path": event.data.get("path"),
                            "timestamp": event.timestamp,
                        }
                    )
                case EventType.CASE_CREATED:
                    state["created"] = True
                    state["name"] = event.data.get("name")
                    state["investigator"] = event.data.get("investigator")
                case EventType.CASE_CLOSED:
                    state["closed"] = True
                    state["close_reason"] = event.data.get("reason")
                case EventType.PERMISSION_GRANTED:
                    state["permissions_granted"].append(
                        {
                            "request_id": event.data.get("request_id"),
                            "tool": event.data.get("tool"),
                            "timestamp": event.timestamp,
                        }
                    )
                case EventType.PERMISSION_DENIED:
                    state["permissions_denied"].append(
                        {
                            "request_id": event.data.get("request_id"),
                            "tool": event.data.get("tool"),
                            "reason": event.data.get("reason"),
                            "timestamp": event.timestamp,
                        }
                    )

        return state

    def get_all_events(self) -> list[CaseEvent]:
        """Todos los eventos del sistema (para auditoría global).

        Returns:
            Lista de todos los eventos ordenados por timestamp
        """
        with self.db.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM case_events ORDER BY timestamp ASC")
            return [self._row_to_event(row) for row in cursor.fetchall()]

    def verify_chain_integrity(self, aggregate_id: str) -> dict[str, Any]:
        """Verifica la integridad de la cadena de eventos de un caso.

        Comprueba que el hash SHA-256 de cada evento coincide con su contenido
        y que la secuencia es monótona y continua.

        Args:
            aggregate_id: ID del agregado (case_id)

        Returns:
            Diccionario con el resultado de la verificación
        """
        events = self.get_events(aggregate_id)

        if not events:
            return {
                "valid": False,
                "error": f"No hay eventos para el caso {aggregate_id}",
                "total_events": 0,
            }

        # Verificar secuencia monótona y continua
        for i, event in enumerate(events):
            expected_seq = i + 1
            if event.seq != expected_seq:
                return {
                    "valid": False,
                    "error": f"Secuencia rota: evento {event.id} tiene seq={event.seq}, esperado {expected_seq}",
                    "total_events": len(events),
                    "tampered_event_id": event.id,
                }

        # Verificar hash de cada evento
        tampered: list[str] = []
        for event in events:
            if not event.verify_integrity():
                tampered.append(event.id)

        if tampered:
            return {
                "valid": False,
                "error": f"Hash inválido en {len(tampered)} evento(s)",
                "total_events": len(events),
                "tampered_event_ids": tampered,
            }

        return {
            "valid": True,
            "case_id": aggregate_id,
            "total_events": len(events),
            "first_event_at": events[0].timestamp,
            "last_event_at": events[-1].timestamp,
            "verified_at": current_utc_iso(),
        }

    @staticmethod
    def _row_to_event(row: Any) -> CaseEvent:
        """Convierte una fila de SQLite en un CaseEvent."""
        return CaseEvent(
            id=row["id"],
            aggregate_id=row["aggregate_id"],
            seq=row["seq"],
            type=row["type"],
            data=json.loads(row["data"]),
            timestamp=row["timestamp"],
            sha256=row["sha256"],
        )

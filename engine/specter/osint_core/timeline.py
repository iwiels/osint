"""
SpecterOSINT - Forensic Timeline
Reconstrucción temporal de un caso: cuándo entró cada artefacto al grafo,
cuándo se recolectó cada evidencia y qué acciones firmó el analista.

El grafo responde *qué* hay; la línea de tiempo responde *cuándo pasó*, que es
lo que sostiene un informe: marcas de tiempo verificables, ráfagas de actividad
y ventanas de recolección (incluida la detección de actividad anómala, p. ej.
una enumeración masiva en una sola hora).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from specter.osint_core.database import Database

BUCKETS = ("hour", "day")
_BUCKET_LENGTH = {"hour": 13, "day": 10}


class CaseTimeline:
    def __init__(self, db: Database):
        self.db = db

    def events(self, case_id: str) -> list[dict[str, Any]]:
        """Eventos del caso (entidades, evidencias, bloques y sesiones del
        agente) ordenados: qué se preguntó y qué ejecutó cada run."""
        events: list[dict[str, Any]] = []

        for entity in self.db.get_case_entities(case_id):
            events.append(
                {
                    "timestamp": entity.first_seen,
                    "kind": "entity",
                    "artifact_id": entity.id,
                    "type": entity.type.value,
                    "value": entity.value,
                    "label": entity.label or entity.value,
                    "confidence": entity.confidence,
                    "last_seen": entity.last_seen,
                }
            )

        for evidence in self.db.get_case_evidences(case_id):
            events.append(
                {
                    "timestamp": evidence.timestamp,
                    "kind": "evidence",
                    "artifact_id": evidence.id,
                    "collector": evidence.collector,
                    "source_url": evidence.source_url,
                    "payload_hash": evidence.payload_hash,
                }
            )

        for block in self.db.get_case_ledger(case_id):
            events.append(
                {
                    "timestamp": block.timestamp,
                    "kind": "ledger",
                    "artifact_id": f"block-{block.block_index}",
                    "collector": block.collector,
                    "action": block.action,
                    "block_index": block.block_index,
                    "block_hash": block.block_hash,
                    "signed": block.signature is not None,
                }
            )

        for sess in self.db.list_agent_sessions(case_id):
            events.append(
                {
                    "timestamp": sess.started_at,
                    "kind": "agent",
                    "artifact_id": sess.session_id,
                    "prompt": sess.prompt,
                    "provider": sess.provider,
                    "model": sess.model,
                    "status": sess.status,
                    "iterations": sess.iterations,
                    "tools_used": sess.tools_used,
                }
            )

        return sorted(events, key=lambda e: (e["timestamp"], e["kind"]))

    def build(
        self, case_id: str, bucket: str = "day", burst_threshold: float = 2.5
    ) -> dict[str, Any]:
        """Línea de tiempo agregada por ventana temporal, con detección de ráfagas."""
        if bucket not in BUCKETS:
            raise ValueError(f"Bucket inválido: {bucket}. Use uno de {list(BUCKETS)}")

        events = self.events(case_id)
        if not events:
            return {
                "case_id": case_id,
                "bucket": bucket,
                "total_events": 0,
                "first_activity": None,
                "last_activity": None,
                "span_hours": None,
                "buckets": [],
                "bursts": [],
                "collectors": {},
                "events": [],
            }

        grouped: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            key = event["timestamp"][: _BUCKET_LENGTH[bucket]]
            grouped.setdefault(key, []).append(event)

        window_count = len(grouped)
        average = len(events) / window_count
        buckets: list[dict[str, Any]] = []
        bursts: list[dict[str, Any]] = []

        for key in sorted(grouped):
            bucket_events = grouped[key]
            kinds = Counter(e["kind"] for e in bucket_events)
            types = Counter(e["type"] for e in bucket_events if e["kind"] == "entity")
            entry = {
                "bucket": key,
                "count": len(bucket_events),
                "entities": kinds.get("entity", 0),
                "evidences": kinds.get("evidence", 0),
                "ledger_blocks": kinds.get("ledger", 0),
                "agent": kinds.get("agent", 0),
                "types": dict(types.most_common()),
            }
            buckets.append(entry)
            ratio = len(bucket_events) / average if average else 0.0
            if len(bucket_events) >= 3 and ratio >= burst_threshold:
                bursts.append(
                    {
                        "bucket": key,
                        "count": len(bucket_events),
                        "ratio_vs_average": round(ratio, 2),
                    }
                )

        return {
            "case_id": case_id,
            "bucket": bucket,
            "total_events": len(events),
            "first_activity": events[0]["timestamp"],
            "last_activity": events[-1]["timestamp"],
            "span_hours": self._span_hours(events[0]["timestamp"], events[-1]["timestamp"]),
            "buckets": buckets,
            "bursts": bursts,
            "collectors": dict(Counter(e["collector"] for e in events if "collector" in e)),
            "events": events,
        }

    @staticmethod
    def _span_hours(first: str, last: str) -> float | None:
        try:
            delta = datetime.fromisoformat(last) - datetime.fromisoformat(first)
        except ValueError:
            return None
        return round(delta.total_seconds() / 3600.0, 2)

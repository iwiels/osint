"""
Tests del timeline forense: agregación por ventana temporal, span y ráfagas.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from specter.osint_core.database import Database
from specter.osint_core.ledger import ForensicLedger
from specter.osint_core.models import (
    CaseMetadata,
    EntityNode,
    EntityType,
    RawEvidence,
)
from specter.osint_core.timeline import CaseTimeline

KEY = bytes(range(32))


@pytest.fixture()
def db(engine_env: Path) -> Database:
    db = Database(engine_env)
    db.create_case(
        CaseMetadata(case_id="case-time", name="Timeline", description="d", investigator="pytest")
    )
    return db


def _entity_at(
    db: Database, case_id: str, value: str, timestamp: str, entity_type=EntityType.DOMAIN
):
    node = EntityNode.create(entity_type, value)
    node.first_seen = timestamp
    node.last_seen = timestamp
    db.upsert_entities(case_id, [node])
    return node


def test_events_mezclan_entidades_evidencias_y_bloques(db):
    ledger = ForensicLedger(db, signing_key=KEY)
    ledger.initialize_case_genesis(db.get_case("case-time"))
    _entity_at(db, "case-time", "target.test", "2026-09-01T10:00:00+00:00")
    ledger.record_evidence_action(
        "case-time",
        "dns_collector",
        "DNS_ENUMERATION: target.test",
        RawEvidence(
            id="ev-1",
            case_id="case-time",
            collector="dns_collector",
            source_url="dns://target.test",
            raw_payload='{"a": "1.2.3.4"}',
            payload_hash="auto",
        ),
    )

    events = CaseTimeline(db).events("case-time")

    assert sorted(e["kind"] for e in events) == ["entity", "evidence", "ledger", "ledger"]
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)
    entity_event = next(e for e in events if e["kind"] == "entity")
    assert entity_event["artifact_id"] == "domain:target.test"
    assert entity_event["type"] == "DOMAIN"
    evidence_event = next(e for e in events if e["kind"] == "evidence")
    assert evidence_event["collector"] == "dns_collector"
    assert evidence_event["payload_hash"] != "auto"  # el ledger recalcula el hash
    ledger_events = [e for e in events if e["kind"] == "ledger"]
    assert [e["block_index"] for e in ledger_events] == [0, 1]
    assert all(e["signed"] is True for e in ledger_events)


def test_build_agrupa_por_dia_y_calcula_span(db):
    _entity_at(db, "case-time", "a.test", "2026-09-01T10:00:00+00:00")
    _entity_at(db, "case-time", "b.test", "2026-09-03T22:30:00+00:00")
    _entity_at(db, "case-time", "c.test", "2026-09-03T23:00:00+00:00")

    report = CaseTimeline(db).build("case-time")

    assert report["bucket"] == "day"
    assert report["total_events"] == 3
    assert report["first_activity"] == "2026-09-01T10:00:00+00:00"
    assert report["last_activity"] == "2026-09-03T23:00:00+00:00"
    assert report["span_hours"] == 61.0
    assert [b["bucket"] for b in report["buckets"]] == ["2026-09-01", "2026-09-03"]
    assert [b["count"] for b in report["buckets"]] == [1, 2]
    assert report["buckets"][1]["entities"] == 2
    assert report["buckets"][1]["types"] == {"DOMAIN": 2}
    assert report["buckets"][0]["evidences"] == 0
    assert report["collectors"] == {}
    assert report["bursts"] == []  # 2 sobre una media de 1.5 no es ráfaga


def test_build_detecta_rafagas_y_agrupa_por_hora(db):
    for index in range(12):
        _entity_at(db, "case-time", f"bulk-{index}.test", "2026-09-02T03:15:00+00:00")
    for day in (1, 3, 4, 5):
        _entity_at(db, "case-time", f"normal-{day}.test", f"2026-09-0{day}T09:00:00+00:00")

    timeline = CaseTimeline(db)
    por_dia = timeline.build("case-time")
    por_hora = timeline.build("case-time", bucket="hour")

    assert por_dia["bursts"] == [{"bucket": "2026-09-02", "count": 12, "ratio_vs_average": 3.75}]
    assert por_hora["buckets"][-1]["bucket"] == "2026-09-05T09"
    assert por_hora["total_events"] == 16
    assert len(por_hora["buckets"]) == 5
    # El umbral es configurable: con 4.0 la misma ráfaga deja de reportarse.
    assert timeline.build("case-time", burst_threshold=4.0)["bursts"] == []


def test_build_caso_vacio_y_bucket_invalido(db):
    report = CaseTimeline(db).build("case-time")

    assert report["total_events"] == 0
    assert report["events"] == [] and report["buckets"] == []
    assert report["first_activity"] is None and report["span_hours"] is None
    assert report["collectors"] == {}

    with pytest.raises(ValueError, match="Bucket inválido"):
        CaseTimeline(db).build("case-time", bucket="semana")


def test_span_hours_tolera_timestamps_invalidos():
    assert CaseTimeline._span_hours("no-es-fecha", "tampoco") is None

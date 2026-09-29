"""
Tests para Event Sourcing y Durable Event Replay.

Cubre:
- EventStore: publish, get_events, replay, get_all_events
- Integridad SHA-256 de eventos
- Replay de estado de casos
- Endpoints HTTP de eventos
"""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from specter import server as specter_server
from specter.osint_core.event_store import CaseEvent, EventStore
from specter.osint_core.event_types import EventType
from specter.osint_core.models import CaseMetadata

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture()
def event_store(engine_env: Path) -> EventStore:
    """EventStore aislado por test (BD limpia vía engine_env)."""
    from specter.osint_core.database import Database

    db = Database(engine_env)
    return EventStore(db)


@pytest.fixture()
def sample_case() -> CaseMetadata:
    """Caso de prueba con metadatos válidos."""
    return CaseMetadata(
        case_id="case-test-001",
        name="Caso de Prueba",
        description="Caso para tests de event sourcing",
        investigator="TestAnalyst",
    )


# ------------------------------------------------------------------
# Tests de EventStore - publish y get_events
# ------------------------------------------------------------------


class TestEventStorePublish:
    """Tests para la publicación de eventos."""

    def test_publish_creates_event_with_monotonic_seq(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """Cada evento publicado incrementa la secuencia monótonamente."""
        case_id = sample_case.case_id

        event1 = event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event2 = event_store.publish(case_id, EventType.COLLECTOR_RAN, {"collector": "dns"})
        event3 = event_store.publish(case_id, EventType.ENTITY_RESOLVED, {"value": "example.com"})

        assert event1.seq == 1
        assert event2.seq == 2
        assert event3.seq == 3

    def test_publish_generates_uuid_and_hash(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """Cada evento tiene un UUID único y hash SHA-256 calculado."""
        case_id = sample_case.case_id

        event = event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})

        assert event.id  # UUID no vacío
        assert len(event.sha256) == 64  # SHA-256 hex
        assert event.verify_integrity()

    def test_publish_stores_event_in_database(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El evento queda persistido en la tabla case_events."""
        case_id = sample_case.case_id

        event = event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})

        events = event_store.get_events(case_id)
        assert len(events) == 1
        assert events[0].id == event.id
        assert events[0].type == EventType.CASE_CREATED.value

    def test_publish_accepts_string_event_type(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El EventStore acepta EventType o string como tipo."""
        case_id = sample_case.case_id

        event = event_store.publish(case_id, "custom.event", {"key": "value"})

        assert event.type == "custom.event"

    def test_publish_preserves_data_payload(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El payload data se preserva íntegramente."""
        case_id = sample_case.case_id
        data = {
            "collector": "dns",
            "target": "example.com",
            "entities_found": 5,
            "nested": {"key": "value"},
        }

        event = event_store.publish(case_id, EventType.COLLECTOR_RAN, data)

        assert event.data == data


class TestEventStoreGetEvents:
    """Tests para la obtención de eventos."""

    def test_get_events_returns_empty_list_for_unknown_case(self, event_store: EventStore) -> None:
        """Un caso sin eventos devuelve lista vacía."""
        events = event_store.get_events("nonexistent-case")
        assert events == []

    def test_get_events_returns_events_in_seq_order(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """Los eventos se devuelven ordenados por secuencia."""
        case_id = sample_case.case_id

        for i in range(5):
            event_store.publish(case_id, EventType.COLLECTOR_RAN, {"index": i})

        events = event_store.get_events(case_id)
        assert len(events) == 5
        for i, event in enumerate(events):
            assert event.seq == i + 1

    def test_get_events_with_after_parameter(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El parámetro after filtra eventos por secuencia."""
        case_id = sample_case.case_id

        for i in range(5):
            event_store.publish(case_id, EventType.COLLECTOR_RAN, {"index": i})

        events = event_store.get_events(case_id, after=2)
        assert len(events) == 3
        assert events[0].seq == 3
        assert events[-1].seq == 5

    def test_get_events_isolated_per_aggregate(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """Los eventos de un aggregate no se mezclan con otros."""
        case_id = sample_case.case_id
        other_case_id = "case-other-002"

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(other_case_id, EventType.CASE_CREATED, {"name": "Other"})

        events = event_store.get_events(case_id)
        assert len(events) == 1
        assert events[0].aggregate_id == case_id


# ------------------------------------------------------------------
# Tests de integridad SHA-256
# ------------------------------------------------------------------


class TestEventIntegrity:
    """Tests para la verificación de integridad de eventos."""

    def test_event_hash_is_deterministic(self) -> None:
        """El hash de un evento es determinista (mismo contenido = mismo hash)."""
        event = CaseEvent(
            id="test-id",
            aggregate_id="case-1",
            seq=1,
            type=EventType.CASE_CREATED.value,
            data={"name": "Test"},
            timestamp="2024-01-01T00:00:00+00:00",
        )
        hash1 = event.compute_hash()
        hash2 = event.compute_hash()

        assert hash1 == hash2

    def test_event_hash_changes_with_content(self) -> None:
        """Cambiar el contenido del evento cambia su hash."""
        event1 = CaseEvent(
            id="test-id",
            aggregate_id="case-1",
            seq=1,
            type=EventType.CASE_CREATED.value,
            data={"name": "Test"},
            timestamp="2024-01-01T00:00:00+00:00",
        )
        event2 = CaseEvent(
            id="test-id",
            aggregate_id="case-1",
            seq=1,
            type=EventType.CASE_CREATED.value,
            data={"name": "Different"},
            timestamp="2024-01-01T00:00:00+00:00",
        )

        assert event1.compute_hash() != event2.compute_hash()

    def test_verify_integrity_detects_tampering(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """La verificación de integridad detecta eventos alterados."""
        case_id = sample_case.case_id

        event = event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        assert event.verify_integrity()

        # Simular alteración: modificar el hash
        tampered = event.model_copy(update={"sha256": "0" * 64})
        assert not tampered.verify_integrity()

    def test_verify_chain_integrity_valid_chain(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """Una cadena de eventos íntegra pasa la verificación."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(case_id, EventType.COLLECTOR_RAN, {"collector": "dns"})
        event_store.publish(case_id, EventType.ENTITY_RESOLVED, {"value": "example.com"})

        result = event_store.verify_chain_integrity(case_id)
        assert result["valid"] is True
        assert result["total_events"] == 3

    def test_verify_chain_integrity_detects_tampered_event(
        self, event_store: EventStore, sample_case: CaseMetadata, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """La verificación de cadena detecta un evento con hash alterado."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(case_id, EventType.COLLECTOR_RAN, {"collector": "dns"})

        # Alterar directamente en la BD el hash del primer evento
        with event_store.db.get_connection() as conn:
            conn.execute(
                "UPDATE case_events SET sha256 = ? WHERE aggregate_id = ? AND seq = 1",
                ("tampered" * 8, case_id),
            )

        result = event_store.verify_chain_integrity(case_id)
        assert result["valid"] is False
        assert "tampered_event_ids" in result


# ------------------------------------------------------------------
# Tests de replay de eventos
# ------------------------------------------------------------------


class TestEventReplay:
    """Tests para el replay de eventos y reconstrucción de estado."""

    def test_replay_empty_case(self, event_store: EventStore, sample_case: CaseMetadata) -> None:
        """Replay de un caso sin eventos devuelve estado vacío."""
        case_id = sample_case.case_id

        state = event_store.replay(case_id)

        assert state["case_id"] == case_id
        assert state["total_events"] == 0
        assert state["collectors_run"] == []
        assert state["entities_resolved"] == []

    def test_replay_reconstructs_collector_state(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay reconstruye el estado de colectores ejecutados."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(
            case_id,
            EventType.COLLECTOR_RAN,
            {"collector": "dns", "target": "example.com", "entities_found": 5},
        )
        event_store.publish(
            case_id,
            EventType.COLLECTOR_RAN,
            {"collector": "crtsh", "target": "example.com", "entities_found": 10},
        )

        state = event_store.replay(case_id)

        assert state["total_events"] == 3
        assert len(state["collectors_run"]) == 2
        assert state["collectors_run"][0]["collector"] == "dns"
        assert state["collectors_run"][1]["collector"] == "crtsh"

    def test_replay_reconstructs_entity_state(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay reconstruye las entidades resueltas."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(
            case_id,
            EventType.ENTITY_RESOLVED,
            {"entity_id": "domain:example.com", "entity_type": "DOMAIN", "value": "example.com"},
        )
        event_store.publish(
            case_id,
            EventType.ENTITY_RESOLVED,
            {"entity_id": "ip:1.2.3.4", "entity_type": "IP_ADDRESS", "value": "1.2.3.4"},
        )

        state = event_store.replay(case_id)

        assert len(state["entities_resolved"]) == 2
        assert state["entities_resolved"][0]["value"] == "example.com"
        assert state["entities_resolved"][1]["value"] == "1.2.3.4"

    def test_replay_reconstructs_correlation_state(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay reconstruye las correlaciones encontradas."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(
            case_id,
            EventType.CORRELATION_FOUND,
            {
                "source_id": "domain:example.com",
                "target_id": "ip:1.2.3.4",
                "relation_type": "RESOLVES_TO",
            },
        )

        state = event_store.replay(case_id)

        assert len(state["correlations_found"]) == 1
        assert state["correlations_found"][0]["relation_type"] == "RESOLVES_TO"

    def test_replay_reconstructs_graph_updates(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay reconstruye las actualizaciones del grafo."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(
            case_id,
            EventType.GRAPH_UPDATED,
            {"nodes_added": 5, "edges_added": 3},
        )

        state = event_store.replay(case_id)

        assert len(state["graph_updates"]) == 1
        assert state["graph_updates"][0]["nodes_added"] == 5

    def test_replay_reconstructs_case_lifecycle(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay reconstruye el ciclo de vida del caso."""
        case_id = sample_case.case_id

        event_store.publish(
            case_id,
            EventType.CASE_CREATED,
            {"case_id": case_id, "name": "Test", "investigator": "Analyst"},
        )
        event_store.publish(
            case_id, EventType.CASE_CLOSED, {"case_id": case_id, "reason": "Completado"}
        )

        state = event_store.replay(case_id)

        assert state["created"] is True
        assert state["closed"] is True
        assert state["name"] == "Test"
        assert state["investigator"] == "Analyst"
        assert state["close_reason"] == "Completado"

    def test_replay_reconstructs_permissions(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay reconstruye los permisos otorgados y denegados."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(
            case_id,
            EventType.PERMISSION_GRANTED,
            {"request_id": "req-1", "tool": "investigate_domain"},
        )
        event_store.publish(
            case_id,
            EventType.PERMISSION_DENIED,
            {"request_id": "req-2", "tool": "delete_case", "reason": "unauthorized"},
        )

        state = event_store.replay(case_id)

        assert len(state["permissions_granted"]) == 1
        assert len(state["permissions_denied"]) == 1
        assert state["permissions_granted"][0]["tool"] == "investigate_domain"
        assert state["permissions_denied"][0]["tool"] == "delete_case"

    def test_replay_with_after_parameter(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay con after reconstruye desde un punto dado."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(case_id, EventType.COLLECTOR_RAN, {"collector": "dns"})
        event_store.publish(case_id, EventType.COLLECTOR_RAN, {"collector": "crtsh"})

        state = event_store.replay(case_id, after=1)

        assert state["total_events"] == 2
        assert len(state["collectors_run"]) == 2

    def test_replay_includes_timestamps(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """El replay incluye timestamps del primer y último evento."""
        case_id = sample_case.case_id

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(case_id, EventType.COLLECTOR_RAN, {"collector": "dns"})

        state = event_store.replay(case_id)

        assert state["first_event_at"] is not None
        assert state["last_event_at"] is not None


# ------------------------------------------------------------------
# Tests de get_all_events (auditoría global)
# ------------------------------------------------------------------


class TestGetAllEvents:
    """Tests para la obtención de todos los eventos del sistema."""

    def test_get_all_events_empty(self, event_store: EventStore) -> None:
        """Sin eventos devuelve lista vacía."""
        events = event_store.get_all_events()
        assert events == []

    def test_get_all_events_returns_all_aggregates(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """Devuelve eventos de todos los aggregates."""
        case_id = sample_case.case_id
        other_case_id = "case-other-002"

        event_store.publish(case_id, EventType.CASE_CREATED, {"name": "Test"})
        event_store.publish(other_case_id, EventType.CASE_CREATED, {"name": "Other"})

        events = event_store.get_all_events()
        assert len(events) == 2

    def test_get_all_events_ordered_by_timestamp(
        self, event_store: EventStore, sample_case: CaseMetadata
    ) -> None:
        """Los eventos se devuelven ordenados por timestamp."""
        case_id = sample_case.case_id

        for i in range(3):
            event_store.publish(case_id, EventType.COLLECTOR_RAN, {"index": i})

        events = event_store.get_all_events()
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps)


# ------------------------------------------------------------------
# Tests de la API HTTP
# ------------------------------------------------------------------


class TestEventStoreAPI:
    """Tests para los endpoints HTTP de Event Sourcing."""

    @pytest.fixture()
    def http_engine(self, engine_env: Path):
        """App HTTP con BD aislada para tests ASGI."""
        import http_server

        http_server.db = specter_server.db
        return http_server

    async def test_get_case_events_endpoint(self, http_engine, sample_case: CaseMetadata) -> None:
        """GET /cases/{case_id}/events devuelve eventos del caso."""
        from specter.osint_core.database import Database

        db = Database(http_engine.db.db_path)
        db.create_case(sample_case)

        store = EventStore(db)
        store.publish(sample_case.case_id, EventType.CASE_CREATED, {"name": "Test"})

        transport = ASGITransport(app=http_engine.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                f"/cases/{sample_case.case_id}/events",
                headers={"Authorization": "Bearer test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["case_id"] == sample_case.case_id
        assert data["total_events"] == 1
        assert len(data["events"]) == 1

    async def test_get_case_events_replay_endpoint(
        self, http_engine, sample_case: CaseMetadata
    ) -> None:
        """GET /cases/{case_id}/events/replay devuelve estado reconstruido."""
        from specter.osint_core.database import Database

        db = Database(http_engine.db.db_path)
        db.create_case(sample_case)

        store = EventStore(db)
        store.publish(sample_case.case_id, EventType.CASE_CREATED, {"name": "Test"})
        store.publish(
            sample_case.case_id,
            EventType.COLLECTOR_RAN,
            {"collector": "dns", "target": "example.com", "entities_found": 5},
        )

        transport = ASGITransport(app=http_engine.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                f"/cases/{sample_case.case_id}/events/replay",
                headers={"Authorization": "Bearer test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["case_id"] == sample_case.case_id
        assert data["total_events"] == 2
        assert len(data["collectors_run"]) == 1

    async def test_get_all_events_endpoint(self, http_engine) -> None:
        """GET /events/audit devuelve todos los eventos del sistema."""
        transport = ASGITransport(app=http_engine.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/events/audit",
                headers={"Authorization": "Bearer test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert "total_events" in data
        assert "events" in data

    async def test_get_case_events_404_for_unknown_case(self, http_engine) -> None:
        """GET /cases/{case_id}/events devuelve 404 si el caso no existe."""
        transport = ASGITransport(app=http_engine.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(
                "/cases/nonexistent/events",
                headers={"Authorization": "Bearer test-token"},
            )

        assert response.status_code == 404

    async def test_get_case_events_requires_auth(self, http_engine) -> None:
        """Los endpoints de eventos requieren autenticación."""
        transport = ASGITransport(app=http_engine.app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/events/audit")

        assert response.status_code == 401


# ------------------------------------------------------------------
# Tests de modelo CaseEvent
# ------------------------------------------------------------------


class TestCaseEventModel:
    """Tests para el modelo Pydantic CaseEvent."""

    def test_case_event_creation_with_defaults(self) -> None:
        """CaseEvent se crea con valores por defecto correctos."""
        event = CaseEvent(
            aggregate_id="case-1",
            seq=1,
            type=EventType.CASE_CREATED.value,
            data={"name": "Test"},
        )

        assert event.id  # UUID generado
        assert event.timestamp  # timestamp generado
        assert event.sha256 == ""  # hash vacío hasta calcular

    def test_case_event_model_dump(self) -> None:
        """El modelo se serializa correctamente a dict."""
        event = CaseEvent(
            id="test-id",
            aggregate_id="case-1",
            seq=1,
            type=EventType.CASE_CREATED.value,
            data={"name": "Test"},
            timestamp="2024-01-01T00:00:00+00:00",
            sha256="abc123",
        )

        dumped = event.model_dump()
        assert dumped["id"] == "test-id"
        assert dumped["aggregate_id"] == "case-1"
        assert dumped["seq"] == 1
        assert dumped["type"] == "case.created"
        assert dumped["data"] == {"name": "Test"}

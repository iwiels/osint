"""
Contrato motor <-> UI: fija las formas exactas que consume el renderer.

Si el backend renombra/quita una clave que la UI usa, estos tests fallan
ANTES de que el bug llegue al canvas (el incidente del grafo negro fue
exactamente eso: aristas `source/target` vs `source_id/target_id`).

Regla: toda respuesta que pinte la UI tiene aquí su set de claves.
"""

from __future__ import annotations

import httpx
import pytest
from conftest import TEST_AUTH_HEADERS
from http_mock import MockRouter, json_sequence, patch_httpx

from engine import agent as agent_module

pytestmark = pytest.mark.asyncio


async def _seed(engine, client, name: str = "Caso contrato") -> str:
    from specter.osint_core.models import AgentSession, EntityNode, EntityType

    created = await client.post(
        "/cases", json={"name": name, "description": "d", "investigator": "pytest"}
    )
    assert created.status_code == 200
    body = created.json()
    assert set(body) == {"status", "case_id", "name", "investigator", "genesis_hash", "message"}
    case_id = body["case_id"]

    engine.db.upsert_entities(
        case_id,
        [EntityNode.create(EntityType.DOMAIN, "pacto.test")],
    )
    engine.db.create_agent_session(
        AgentSession(
            session_id="sess-pacto",
            case_id=case_id,
            provider="ollama",
            model="m",
            prompt="hola",
        )
    )
    engine.db.append_agent_message("sess-pacto", "user", "hola")
    engine.db.finish_agent_session("sess-pacto", "completed", 1, 0, 1, 1, "ok")
    return case_id


async def test_contrato_health_y_registry(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        health = (await client.get("/health")).json()
        assert set(health) == {
            "status",
            "engine",
            "version",
            "mcp_tools",
            "data_dir",
            "reports_dir",
            "build_hash",
            "started_at",
        }

        tools = (await client.get("/tools")).json()["tools"]
        names = {t["name"] for t in tools}
        for expected in (
            "create_case",
            "triage_entity",
            "investigate_identity",
            "hunt_documents_and_leaks",
            "query_graph",
            "web_search",
            "web_fetch",
            "parallel_search",
            "load_skill",
            "todowrite",
            "attest_case_ledger",
            "export_case_dossier",
        ):
            assert expected in names, f"tool {expected} desaparecida del contrato"
        # ask_analyst es nativa del agente (bus SSE), no del kernel MCP.
        assert "ask_analyst" not in names
        for tool in tools:
            assert set(tool) == {"name", "description", "schema"}


async def test_contrato_grafo_claves_de_arista(engine) -> None:
    """El incidente del canvas negro: las aristas SON source/target."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed(engine, client)
        await client.post(
            "/tools/link_entities/call",
            json={
                "arguments": {
                    "case_id": case_id,
                    "source_id": "domain:pacto.test",
                    "target_id": "domain:pacto.test",
                    "relation_type": "CORRELATED_WITH",
                }
            },
        )

        body = (await client.get(f"/cases/{case_id}/graph")).json()
        assert set(body) == {"nodes", "edges", "total_nodes", "total_edges"}
        assert body["total_nodes"] == 1 and body["total_edges"] == 1

        node = body["nodes"][0]
        assert {
            "id",
            "type",
            "value",
            "label",
            "attributes",
            "confidence",
            "first_seen",
            "last_seen",
        } <= set(node)

        edge = body["edges"][0]
        assert set(edge) == {
            "source",
            "target",
            "relation_type",
            "attributes",
            "confidence",
            "first_seen",
        }, "cambio la forma de arista: actualizar CaseView + dossier"


async def test_contrato_timeline(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed(engine, client)

        body = (await client.get(f"/cases/{case_id}/timeline")).json()
        assert set(body) == {
            "case_id",
            "bucket",
            "total_events",
            "first_activity",
            "last_activity",
            "span_hours",
            "buckets",
            "bursts",
            "collectors",
            "events",
        }
        assert set(body["buckets"][0]) == {
            "bucket",
            "count",
            "entities",
            "evidences",
            "ledger_blocks",
            "agent",
            "types",
        }

        kinds = {e["kind"] for e in body["events"]}
        assert {"entity", "ledger", "agent"} <= kinds
        agent_event = next(e for e in body["events"] if e["kind"] == "agent")
        assert {
            "timestamp",
            "kind",
            "artifact_id",
            "prompt",
            "provider",
            "model",
            "status",
            "iterations",
            "tools_used",
        } <= set(agent_event)


async def test_contrato_ledger_attestation_correlaciones(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed(engine, client)

        ledger = (await client.get(f"/cases/{case_id}/ledger")).json()
        assert set(ledger) == {"case_id", "blocks", "signature_status", "key_id", "valid"}
        assert {
            "case_id",
            "block_index",
            "timestamp",
            "collector",
            "action",
            "prev_hash",
            "block_hash",
        } <= set(ledger["blocks"][0])

        att = (await client.get(f"/cases/{case_id}/attestation")).json()
        assert set(att) == {
            "case_id",
            "sealed",
            "algorithm",
            "key_id",
            "chain_valid",
            "signature_status",
            "total_blocks",
            "head",
            "attestation",
        }
        assert set(att["head"]) == {
            "block_index",
            "block_hash",
            "signature",
            "action",
            "timestamp",
        }
        assert set(att["attestation"]) == {"payload", "signature"}

        corr = (await client.get(f"/cases/{case_id}/correlations")).json()
        assert set(corr) == {"case_id", "cross_case", "identity_candidates"}
        assert set(corr["cross_case"]) == {
            "anchor_case",
            "total_shared_entities",
            "cases_involved",
            "cases_involved_count",
            "by_type",
            "matches",
        }
        assert set(corr["identity_candidates"]) == {
            "case_id",
            "analyzed_entities",
            "total_candidates",
            "min_score",
            "candidates",
        }


async def test_contrato_sesiones(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed(engine, client)

        listed = (await client.get("/agent/sessions", params={"case_id": case_id})).json()
        assert set(listed) == {"sessions"}
        sess = listed["sessions"][0]
        assert set(sess) == {
            "session_id",
            "case_id",
            "provider",
            "model",
            "status",
            "started_at",
            "ended_at",
            "iterations",
            "tools_used",
            "input_tokens",
            "output_tokens",
            "prompt",
            "summary",
        }

        detail = (await client.get("/agent/sessions/sess-pacto")).json()
        assert set(detail) == {"session", "messages"}
        assert set(detail["messages"][0]) == {
            "id",
            "session_id",
            "seq",
            "role",
            "content",
            "tool",
            "call_id",
            "extra",
            "ts",
        }


async def test_contrato_agent_run_y_respuestas(engine, monkeypatch) -> None:
    # El run se invoca directo (como test_agent_e2e): el transporte HTTP del
    # test no puede compartir el mock del LLM. El contrato es la forma.
    patch_httpx(
        monkeypatch,
        MockRouter().add_responder(
            "POST",
            r"fake\.llm",
            json_sequence({"choices": [{"message": {"role": "assistant", "content": "fin"}}]}),
        ),
    )

    async def emit(kind: str, payload: dict) -> None:
        return None

    result = await agent_module.run_agent(
        message="hola",
        case_id=None,
        provider="ollama",
        model=None,
        api_key=None,
        base_url="https://fake.llm/v1",
        max_iterations=2,
        emit=emit,
        stream=False,
        plan_first=False,
    )
    assert set(result) == {
        "status",
        "provider",
        "model",
        "session_id",
        "iterations",
        "tools_used",
        "final_message",
        "usage",
    }
    assert set(result["usage"]) == {"input_tokens", "output_tokens"}

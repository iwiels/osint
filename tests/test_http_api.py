"""
Tests de la capa HTTP del engine (FastAPI) sin sockets reales.

Se usa httpx.ASGITransport contra la app: mismo contrato que consumirá
Electron, sin abrir puertos. Cubre: health, registry, ciclo de vida de caso,
call de tools y errores controlados (404).
"""

from __future__ import annotations

import hashlib

import httpx
import pytest
from conftest import TEST_AUTH_HEADERS

pytestmark = pytest.mark.asyncio


async def test_health_reports_engine_status(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        res = await client.get("/health")

    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["engine"] == "specter"
    assert body["mcp_tools"] >= 15


async def test_engine_rechaza_sin_token_y_acepta_salud_publica(engine) -> None:
    """C1: todo salvo /health exige Bearer; /health sigue público (sidecar)."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as anon:
        assert (await anon.get("/health")).status_code == 200
        assert (await anon.get("/tools")).status_code == 401
        assert (
            await anon.post("/cases", json={"name": "x", "description": "y"})
        ).status_code == 401
        wrong = await anon.get("/tools", headers={"Authorization": "Bearer token-malo"})
        assert wrong.status_code == 401


async def test_preflight_options_no_exige_token(engine) -> None:
    """El preflight CORS (OPTIONS, sin Authorization) debe pasar: si no, el
    navegador bloquea todo el renderer en dev (localhost:5173 -> :8787)."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as anon:
        pre = await anon.options(
            "/cases",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        assert pre.status_code == 200
        assert pre.headers.get("access-control-allow-origin") is not None


async def test_sesiones_se_borran_y_runs_se_cancelan(engine) -> None:
    """DELETE /agent/sessions/{id} + POST /agent/runs/cancel (botón Detener)."""
    from specter.osint_core.models import AgentSession

    engine.db.create_agent_session(
        AgentSession(
            session_id="sess-borrar",
            case_id=None,
            provider="opencode",
            model="space-bunny-free",
            prompt="hola",
        )
    )
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        assert (await client.get("/agent/sessions/sess-borrar")).status_code == 200
        gone = await client.delete("/agent/sessions/sess-borrar")
        assert gone.status_code == 200
        assert (await client.get("/agent/sessions/sess-borrar")).status_code == 404
        assert (await client.delete("/agent/sessions/sess-borrar")).status_code == 404

        idle = await client.post("/agent/runs/cancel", json={"session_id": None})
        assert idle.status_code == 200 and idle.json()["cancelled"] == 0


async def test_registry_lists_forensic_tools(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        res = await client.get("/tools")

    assert res.status_code == 200
    names = [t["name"] for t in res.json()["tools"]]
    for expected in ("create_case", "investigate_domain", "verify_case_integrity"):
        assert expected in names
    for tool in res.json()["tools"]:
        assert set(tool) == {"name", "description", "schema"}


async def test_case_lifecycle_over_http(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        created = await client.post(
            "/cases",
            json={"name": "Caso CI", "description": "verificacion", "investigator": "pytest"},
        )
        assert created.status_code == 200
        case_id = created.json()["case_id"]

        listed = await client.get("/cases")
        assert case_id in [c["case_id"] for c in listed.json()]

        ledger = await client.get(f"/cases/{case_id}/ledger")
        assert ledger.status_code == 200
        assert ledger.json()["blocks"][0]["action"]  # bloque génesis presente

        missing = await client.get("/cases/case-inexistente")
        assert missing.status_code == 404


async def test_tool_call_unknown_returns_404(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        res = await client.post("/tools/no_existe/call", json={"arguments": {}})

    assert res.status_code == 404


async def _seed_case(engine, client, name: str = "Caso API") -> str:
    """Caso con dos artefactos y una relación firmada en la cadena de custodia."""
    from specter.osint_core.models import EntityNode, EntityType

    created = await client.post(
        "/cases", json={"name": name, "description": "seed", "investigator": "pytest"}
    )
    case_id = created.json()["case_id"]
    engine.db.upsert_entities(
        case_id,
        [
            EntityNode.create(EntityType.DOMAIN, "shared.test"),
            EntityNode.create(EntityType.ALIAS, "alice"),
        ],
    )
    await client.post(
        "/tools/link_entities/call",
        json={
            "arguments": {
                "case_id": case_id,
                "source_id": "alias:alice",
                "target_id": "domain:shared.test",
                "relation_type": "CORRELATED_WITH",
            }
        },
    )
    return case_id


async def test_timeline_endpoint_expone_agregados(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client)

        res = await client.get(f"/cases/{case_id}/timeline")
        assert res.status_code == 200
        body = res.json()
        assert body["case_id"] == case_id
        assert body["bucket"] == "day"
        assert body["total_events"] >= 3  # 2 entidades + bloques genesis/link
        assert [e["kind"] for e in body["events"]].count("ledger") == 2
        assert body["first_activity"] <= body["last_activity"]

        hourly = await client.get(f"/cases/{case_id}/timeline", params={"bucket": "hour"})
        assert hourly.status_code == 200 and hourly.json()["bucket"] == "hour"

        bad = await client.get(f"/cases/{case_id}/timeline", params={"bucket": "semana"})
        assert bad.status_code == 400

        missing = await client.get("/cases/case-nada/timeline")
        assert missing.status_code == 404


async def test_ledger_endpoint_reporta_sellado(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client)

        res = await client.get(f"/cases/{case_id}/ledger")

    body = res.json()
    assert body["valid"] is True
    # Sin clave configurada el ledger es honesto: no dice que está sellado.
    assert body["signature_status"] == "KEY_UNAVAILABLE"
    assert body["key_id"] is None
    assert body["blocks"][-1]["signature"] is None
    assert body["blocks"][-1]["action"].startswith("MANUAL_LINK")


@pytest.fixture()
def ledger_key_env(monkeypatch) -> None:
    """Clave de firma disponible *antes* de arrancar el kernel del test."""
    monkeypatch.setenv("SPECTER_LEDGER_KEY", "0123456789abcdef" * 2)


async def test_ledger_endpoint_reporta_cadena_sellada(ledger_key_env, engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        created = await client.post(
            "/cases", json={"name": "Caso sellado", "description": "d", "investigator": "pytest"}
        )
        case_id = created.json()["case_id"]
        await client.post(
            "/tools/link_entities/call",
            json={
                "arguments": {
                    "case_id": case_id,
                    "source_id": "alias:alice",
                    "target_id": "domain:shared.test",
                    "relation_type": "CORRELATED_WITH",
                }
            },
        )

        ledger_res = await client.get(f"/cases/{case_id}/ledger")
        attestation_res = await client.get(f"/cases/{case_id}/attestation")

    ledger = ledger_res.json()
    assert ledger["valid"] is True
    assert ledger["signature_status"] == "SEALED"
    assert (
        ledger["key_id"] == hashlib.sha256(bytes.fromhex("0123456789abcdef" * 2)).hexdigest()[:16]
    )
    assert ledger["blocks"][0]["signature"] == ledger["blocks"][0]["signature"].lower()
    assert all(block["signature"] for block in ledger["blocks"])

    attestation = attestation_res.json()
    assert attestation["sealed"] is True
    assert attestation["signature_status"] == "SEALED"
    assert attestation["algorithm"] == "hmac-sha256-v1"
    assert attestation["attestation"]["signature"]
    assert attestation["head"]["signature"] == ledger["blocks"][-1]["signature"]


async def test_endpoint_correlaciones_cross_case(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_a = await _seed_case(engine, client, "Caso A")
        case_b = await _seed_case(engine, client, "Caso B")

        res = await client.get(f"/cases/{case_a}/correlations")
        assert res.status_code == 200
        body = res.json()
        assert body["cross_case"]["cases_involved"] == sorted([case_a, case_b])
        cross = {m["entity_id"]: m for m in body["cross_case"]["matches"]}
        assert set(cross) == {"domain:shared.test", "alias:alice"}
        assert cross["domain:shared.test"]["case_count"] == 2
        assert body["identity_candidates"]["total_candidates"] == 0

        global_view = await client.get("/intelligence/cross-case")
        assert global_view.status_code == 200
        assert global_view.json()["total_shared_entities"] == 2

        missing = await client.get("/cases/case-nada/correlations")
        assert missing.status_code == 404


async def test_endpoint_atestacion_sellada(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client)

        res = await client.get(f"/cases/{case_id}/attestation")
        missing = await client.get("/cases/case-nada/attestation")

    assert missing.status_code == 404
    body = res.json()
    assert body["case_id"] == case_id
    assert body["chain_valid"] is True
    assert body["total_blocks"] == 2
    assert body["head"]["action"].startswith("MANUAL_LINK")
    assert body["attestation"]["signature"] is None  # sin clave local no hay sello
    assert body["sealed"] is False


async def test_create_case_via_tool_call(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        res = await client.post(
            "/tools/create_case/call",
            json={"arguments": {"name": "Vía registry", "description": "d"}},
        )

    assert res.status_code == 200
    body = res.json()
    assert body["tool"] == "create_case"
    assert body["result"]["status"] == "CASE_CREATED"


async def test_case_graph_respeta_filtros(engine) -> None:
    """Los filtros entity_type/search_term se reenvían al kernel (antes se ignoraban)."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client)

        full = await client.get(f"/cases/{case_id}/graph")
        assert full.status_code == 200
        assert {n["id"] for n in full.json()["nodes"]} == {
            "domain:shared.test",
            "alias:alice",
        }

        by_type = await client.get(f"/cases/{case_id}/graph", params={"entity_type": "DOMAIN"})
        assert by_type.status_code == 200
        assert [n["id"] for n in by_type.json()["nodes"]] == ["domain:shared.test"]

        by_term = await client.get(f"/cases/{case_id}/graph", params={"search_term": "alice"})
        assert by_term.status_code == 200
        assert "alias:alice" in {n["id"] for n in by_term.json()["nodes"]}

        # Filtros sin coincidencia deben devolver grafo vacío, no todos los nodos
        no_match = await client.get(
            f"/cases/{case_id}/graph", params={"search_term": "no_existe_nada"}
        )
        assert no_match.status_code == 200
        assert no_match.json()["nodes"] == []
        assert no_match.json()["total_nodes"] == 0

        no_type = await client.get(f"/cases/{case_id}/graph", params={"entity_type": "PHONE"})
        assert no_type.status_code == 200
        assert no_type.json()["nodes"] == []
        assert no_type.json()["total_nodes"] == 0

        missing = await client.get("/cases/case-nada/graph")
        assert missing.status_code == 404


async def test_case_graph_synthesizes_valid_stubs_over_http(engine) -> None:
    from specter.osint_core.models import EntityNode, EntityType, RelationEdge, RelationType

    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        created = await client.post(
            "/cases", json={"name": "Caso Stubs", "description": "test", "investigator": "pytest"}
        )
        case_id = created.json()["case_id"]

        # Insertar entidad origen
        engine.db.upsert_entities(case_id, [EntityNode.create(EntityType.PERSON, "Carlos Mendoza")])

        # Insertar relación con target_id que NO está en entities
        # (uno con prefijo social_profile y otro con URL cruda)
        engine.db.upsert_relations(
            case_id,
            [
                RelationEdge(
                    source_id="person:carlos mendoza",
                    target_id="social_profile:https://facebook.com/mendozagarcia.carlosandres",
                    relation_type=RelationType.ASSOCIATED_WITH,
                ),
                RelationEdge(
                    source_id="person:carlos mendoza",
                    target_id="https://instagram.com/mendoza_raw",
                    relation_type=RelationType.ASSOCIATED_WITH,
                ),
            ],
        )

        # El endpoint HTTP /cases/{case_id}/graph debe responder 200
        # (sin 500 ResponseValidationError)
        res = await client.get(f"/cases/{case_id}/graph")
        assert res.status_code == 200
        body = res.json()
        assert body["total_nodes"] == 3
        assert body["total_edges"] == 2
        soc_node = next(
            n
            for n in body["nodes"]
            if n["id"] == "social_profile:https://facebook.com/mendozagarcia.carlosandres"
        )
        assert soc_node["type"] == "SOCIAL_PROFILE"
        assert soc_node["value"] == "https://facebook.com/mendozagarcia.carlosandres"
        assert soc_node["label"] is not None

        raw_url_node = next(
            n for n in body["nodes"] if n["id"] == "https://instagram.com/mendoza_raw"
        )
        assert raw_url_node["type"] == "SOCIAL_PROFILE"
        assert raw_url_node["value"] == "https://instagram.com/mendoza_raw"


async def test_questions_respond_404_y_flujo_ok(engine) -> None:
    from engine import agent as agent_module
    from engine.agent import PermissionRequest, QuestionRequest

    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        missing = await client.post(
            "/agent/questions/respond", json={"request_id": "q-nada", "answers": []}
        )
        assert missing.status_code == 404

        req = QuestionRequest(request_id="q-test", questions=[], session_id="s")
        agent_module._pending_questions["q-test"] = req
        try:
            ok = await client.post(
                "/agent/questions/respond",
                json={"request_id": "q-test", "answers": [["DNI"]]},
            )
            assert ok.status_code == 200
            assert set(ok.json()) == {"status", "answers"}
            assert ok.json()["answers"] == [["DNI"]]
        finally:
            agent_module._pending_questions.pop("q-test", None)

        preq = PermissionRequest(request_id="p-test", tool_name="t", arguments={}, session_id="s")
        agent_module._pending_permissions["p-test"] = preq
        try:
            pok = await client.post(
                "/agent/permissions/respond",
                json={"request_id": "p-test", "decision": "deny"},
            )
            assert pok.status_code == 200
            assert set(pok.json()) == {"status", "decision"}
        finally:
            agent_module._pending_permissions.pop("p-test", None)


async def test_load_skill_dni_ar(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        ok = await client.post("/tools/load_skill/call", json={"arguments": {"name": "dni-ar"}})
        assert ok.status_code == 200
        body = ok.json()["result"]
        assert body["status"] == "LOADED" and "CUIT" in body["playbook"]

        missing = await client.post(
            "/tools/load_skill/call", json={"arguments": {"name": "no-existe"}}
        )
        assert "dni-ar" in missing.json()["result"]["available"]


async def test_todowrite_reemplaza_y_valida(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client, name="Caso todos")
        res = await client.post(
            "/tools/todowrite/call",
            json={
                "arguments": {
                    "case_id": case_id,
                    "todos": [
                        {"content": "Fase 1", "status": "in_progress", "priority": "high"},
                        {"content": "Fase 2", "status": "raro", "priority": "rara"},
                        {"content": "   "},
                    ],
                }
            },
        )
        assert res.status_code == 200
        body = res.json()["result"]
        assert body["status"] == "UPDATED" and body["pending"] == 2
        assert [t["status"] for t in body["todos"]] == ["in_progress", "pending"]
        assert [t["priority"] for t in body["todos"]] == ["high", "medium"]


async def test_agent_sessions_endpoints(engine) -> None:
    from specter.osint_core.models import AgentSession

    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client, name="Caso sesiones")
        engine.db.create_agent_session(
            AgentSession(
                session_id="sess-x",
                case_id=case_id,
                provider="ollama",
                model="m",
                prompt="hola",
            )
        )
        engine.db.append_agent_message("sess-x", "user", "hola")
        engine.db.finish_agent_session("sess-x", "completed", 1, 0, 1, 1, "ok")

        listed = await client.get("/agent/sessions", params={"case_id": case_id})
        assert listed.status_code == 200
        assert [s["session_id"] for s in listed.json()["sessions"]] == ["sess-x"]

        detail = await client.get("/agent/sessions/sess-x")
        assert detail.status_code == 200
        assert detail.json()["session"]["status"] == "completed"
        assert [m["role"] for m in detail.json()["messages"]] == ["user"]

        missing = await client.get("/agent/sessions/sess-nada")
        assert missing.status_code == 404


async def test_caso_se_borra_en_cascada(engine) -> None:
    """DELETE /cases/{id}: caso + entidades + ledger + sesiones del caso.

    El borrado directo exige allow explícito del gate (deny por defecto):
    el test concede la regla exacta y la retira al terminar.
    """
    from specter.osint_core.models import AgentSession, EntityNode, EntityType
    from specter.osint_core.permission_gate import PermissionRule, permission_gate

    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client, name="Caso borrar")
        engine.db.upsert_entities(
            case_id, [EntityNode.create(EntityType.DOMAIN, "borrar.test", "x")]
        )
        engine.db.create_agent_session(
            AgentSession(
                session_id="sess-borrar",
                case_id=case_id,
                provider="ollama",
                model="m",
                prompt="hola",
            )
        )

        rule = permission_gate.add_rule(
            PermissionRule(action="delete", resource=f"case:{case_id}", effect="allow")
        )
        try:
            gone = await client.delete(f"/cases/{case_id}")
            assert gone.status_code == 200
            assert gone.json() == {"status": "ok", "case_id": case_id}
            assert (await client.get(f"/cases/{case_id}")).status_code == 404
            assert (await client.get(f"/cases/{case_id}/ledger")).status_code == 404
            assert (await client.delete(f"/cases/{case_id}")).status_code == 404
            assert engine.db.get_case_entities(case_id) == []
            assert engine.db.get_agent_session("sess-borrar") is None
        finally:
            permission_gate.remove_rule(rule.rule_id)


async def test_delete_case_directo_denegado_sin_allow(engine) -> None:
    """El borrado directo sin allow explícito → 403 y el caso sobrevive."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        case_id = await _seed_case(engine, client, name="Caso no borrar")

        res = await client.delete(f"/cases/{case_id}")
        assert res.status_code == 403
        assert "PERMISSION_DENIED" in res.json()["detail"]
        assert (await client.get(f"/cases/{case_id}")).status_code == 200


async def test_tool_sensible_directa_denegada_sin_regla(engine) -> None:
    """investigate_domain (sensible, sin regla allow) por vía directa → 403."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        res = await client.post(
            "/tools/investigate_domain/call",
            json={"arguments": {"case_id": "case-x", "target": "x.test"}},
        )
        assert res.status_code == 403
        assert "PERMISSION_REQUIRED" in res.json()["detail"]


async def test_agent_run_acepta_session_id(engine, monkeypatch) -> None:
    from engine import agent

    called_kwargs = {}

    async def mock_run_agent(**kwargs):
        called_kwargs.update(kwargs)
        return {
            "status": "COMPLETED",
            "provider": kwargs["provider"],
            "model": "test-model",
            "session_id": kwargs.get("session_id") or "sess-auto",
            "iterations": 1,
            "tools_used": [],
            "final_message": "Ok",
            "usage": {"input_tokens": 10, "output_tokens": 10},
        }

    monkeypatch.setattr(agent, "run_agent", mock_run_agent)

    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        res = await client.post(
            "/agent/run",
            json={
                "message": "continuar investigacion",
                "session_id": "sess-existente-123",
                "provider": "opencode",
            },
        )

    assert res.status_code == 200
    assert res.json()["session_id"] == "sess-existente-123"
    assert called_kwargs.get("session_id") == "sess-existente-123"

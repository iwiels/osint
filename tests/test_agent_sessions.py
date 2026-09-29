"""
Tests de la persistencia de conversaciones del agente (estilo opencode
sessions/messages): qué preguntó el analista y qué ejecutó cada run queda
en SQLite para el historial de la UI y la timeline del caso.
"""

from __future__ import annotations

import json

import httpx
import pytest
from http_mock import MockRouter, json_sequence, patch_httpx
from specter.osint_core.database import Database
from specter.osint_core.models import AgentSession
from specter.osint_core.timeline import CaseTimeline
from specter.server import reset_services

import engine.agent as agent_module

pytestmark = pytest.mark.asyncio


def _session(db: Database, case_id: str | None = "case-1") -> str:
    db.create_agent_session(
        AgentSession(
            session_id="sess-1",
            case_id=case_id,
            provider="opencode",
            model="space-bunny-free",
            prompt="investiga 99999999",
        )
    )
    db.append_agent_message("sess-1", "user", "investiga 99999999")
    db.append_agent_message(
        "sess-1",
        "tool",
        '{"status": "COMPLETED"}',
        tool="triage_entity",
        call_id="call-1",
        extra={"arguments": "{}"},
    )
    db.append_agent_message("sess-1", "assistant", "Sin atribución")
    db.finish_agent_session("sess-1", "completed", 2, 1, 11, 7, "Sin atribución")
    return "sess-1"


def test_db_roundtrip_sesion(tmp_path) -> None:
    db = Database(tmp_path / "s.db")
    _session(db)

    only = db.get_agent_session("sess-1")
    assert only is not None and only.status == "completed"
    assert only.prompt == "investiga 99999999" and only.summary == "Sin atribución"
    assert (only.input_tokens, only.output_tokens) == (11, 7)
    assert db.get_agent_session("nope") is None

    msgs = db.get_agent_session_messages("sess-1")
    assert [m.role for m in msgs] == ["user", "tool", "assistant"]
    assert [m.seq for m in msgs] == [0, 1, 2]
    assert msgs[1].tool == "triage_entity" and msgs[1].call_id == "call-1"
    assert msgs[1].extra == {"arguments": "{}"}

    assert [s.session_id for s in db.list_agent_sessions("case-1")] == ["sess-1"]
    assert db.list_agent_sessions("otro-caso") == []
    assert [s.session_id for s in db.list_agent_sessions()] == ["sess-1"]


def test_db_sesiones_orden_descendente(tmp_path) -> None:
    db = Database(tmp_path / "s.db")
    db.create_agent_session(AgentSession(session_id="old", started_at="2026-01-01T00:00:00+00:00"))
    db.create_agent_session(AgentSession(session_id="new", started_at="2026-06-01T00:00:00+00:00"))
    assert [s.session_id for s in db.list_agent_sessions()] == ["new", "old"]


def test_timeline_incluye_sesiones_del_agente(tmp_path) -> None:
    db = Database(tmp_path / "s.db")
    _session(db)

    events = CaseTimeline(db).events("case-1")
    agent_events = [e for e in events if e["kind"] == "agent"]
    assert len(agent_events) == 1
    assert agent_events[0]["prompt"] == "investiga 99999999"
    assert agent_events[0]["provider"] == "opencode"
    assert agent_events[0]["tools_used"] == 1

    report = CaseTimeline(db).build("case-1")
    assert report["total_events"] == 1
    assert report["events"][-1]["kind"] == "agent"


LLM_BASE = "https://fake.llm/v1"


def _tool_turn(name: str, arguments: dict, call_id: str = "call-1") -> dict:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(arguments)},
                        }
                    ],
                }
            }
        ]
    }


async def _run(monkeypatch, bodies: list[dict], db_path) -> dict:
    """Ejecuta run_agent contra un LLM falso con kernel en BD temporal."""
    db = reset_services(str(db_path))
    router = MockRouter().add_responder("POST", r"fake\.llm", json_sequence(*bodies))
    patch_httpx(monkeypatch, router)
    emitted: list[tuple[str, dict]] = []

    async def emit(kind: str, payload: dict) -> None:
        emitted.append((kind, payload))

    result = await agent_module.run_agent(
        message="hola",
        case_id=None,
        provider="ollama",
        model=None,
        api_key=None,
        base_url=LLM_BASE,
        max_iterations=5,
        emit=emit,
        stream=False,
        plan_first=False,
    )
    return {"result": result, "db": db, "emitted": emitted}


async def test_run_agent_persiste_transcripcion(tmp_path, monkeypatch) -> None:
    final = {"choices": [{"message": {"role": "assistant", "content": "Listo"}}]}
    out = await _run(
        monkeypatch,
        [_tool_turn("triage_entity", {"artifact": "x"}), final],
        tmp_path / "run.db",
    )
    result, db = out["result"], out["db"]

    assert result["status"] == "COMPLETED"
    run_id = result["session_id"]
    assert run_id.startswith("sess-")

    sess = db.get_agent_session(run_id)
    assert sess is not None
    assert sess.status == "completed" and sess.iterations == 2
    assert sess.tools_used == 1 and sess.provider == "ollama"
    assert sess.prompt == "hola" and sess.summary == "Listo"

    roles = [m.role for m in db.get_agent_session_messages(run_id)]
    assert roles == ["user", "tool", "assistant"]
    tool_msg = db.get_agent_session_messages(run_id)[1]
    assert tool_msg.tool == "triage_entity" and "artifact" in tool_msg.extra["arguments"]


async def test_run_agent_marca_error(tmp_path, monkeypatch) -> None:
    db = reset_services(str(tmp_path / "err.db"))
    router = MockRouter().add_responder(
        "POST",
        r"fake\.llm",
        lambda req: httpx.Response(status_code=400, text="bad", request=req),
    )
    patch_httpx(monkeypatch, router)

    async def emit(kind: str, payload: dict) -> None:
        return None

    with pytest.raises(httpx.HTTPStatusError):
        await agent_module.run_agent(
            message="hola",
            case_id=None,
            provider="ollama",
            model=None,
            api_key=None,
            base_url=LLM_BASE,
            max_iterations=2,
            emit=emit,
            stream=False,
            plan_first=False,
        )

    sessions = db.list_agent_sessions()
    assert len(sessions) == 1 and sessions[0].status == "error"
    assert db.get_agent_session_messages(sessions[0].session_id)[0].role == "user"


async def test_run_agent_reutiliza_session_id_multi_turn(tmp_path, monkeypatch) -> None:
    db = reset_services(str(tmp_path / "multi.db"))
    captured_requests: list[dict] = []

    def mock_handler(req: httpx.Request) -> httpx.Response:
        data = json.loads(req.content.decode("utf-8"))
        captured_requests.append(data)
        resp_msg = {"role": "assistant", "content": f"Respuesta a {len(captured_requests)}"}
        return httpx.Response(
            status_code=200,
            json={"choices": [{"message": resp_msg}]},
            request=req,
        )

    router = MockRouter().add_responder("POST", r"fake\.llm", mock_handler)
    patch_httpx(monkeypatch, router)

    async def emit(kind: str, payload: dict) -> None:
        return None

    # Primer turno: sin session_id explícito
    res1 = await agent_module.run_agent(
        message="primer prompt",
        case_id="case-1",
        provider="ollama",
        model=None,
        api_key=None,
        base_url=LLM_BASE,
        max_iterations=2,
        emit=emit,
        stream=False,
        plan_first=False,
    )
    sess_id = res1["session_id"]

    # Segundo turno: pasando el mismo session_id
    res2 = await agent_module.run_agent(
        message="segundo prompt",
        case_id="case-1",
        provider="ollama",
        model=None,
        api_key=None,
        base_url=LLM_BASE,
        max_iterations=2,
        emit=emit,
        stream=False,
        plan_first=False,
        session_id=sess_id,
    )

    assert res2["session_id"] == sess_id
    # Sólo 1 sesión registrada en la base de datos para este caso/chat
    sessions = db.list_agent_sessions("case-1")
    assert len(sessions) == 1
    assert sessions[0].session_id == sess_id

    # La transcripción debe contener ambos turnos en orden
    msgs = db.get_agent_session_messages(sess_id)
    roles = [m.role for m in msgs]
    assert roles == ["user", "assistant", "user", "assistant"]
    assert msgs[0].content == "primer prompt"
    assert msgs[2].content == "segundo prompt"

    # Y la segunda llamada al LLM debe haber recibido el contexto del turno anterior
    second_llm_messages = captured_requests[1]["messages"]
    roles_in_payload = [m["role"] for m in second_llm_messages]
    assert "user" in roles_in_payload and "assistant" in roles_in_payload
    contents = [m["content"] for m in second_llm_messages]
    assert "primer prompt" in contents
    assert "segundo prompt" in contents


def test_mensajes_con_limite_conserva_los_mas_recientes(tmp_path) -> None:
    """El límite debe cortar por el FINAL, no por el principio.

    Con `ORDER BY seq ASC LIMIT n` se quedaban los n mensajes MÁS ANTIGUOS: el
    agente reconstruía su contexto con la cola vieja de la conversación y en
    sesiones largas olvidaba todo lo reciente.
    """
    db = Database(tmp_path / "s.db")
    _session(db)
    for i in range(57):
        db.append_agent_message("sess-1", "user", f"turno {i}")

    msgs = db.get_agent_session_messages("sess-1", limit=50)
    assert len(msgs) == 50
    # Sigue en orden cronológico (ASC), pero cortado por el final: 60 totales,
    # se quedan los 50 últimos (seq 10..59), no los primeros (seq 0..49).
    assert [m.seq for m in msgs] == sorted(m.seq for m in msgs)
    assert msgs[0].seq == 10
    assert msgs[-1].seq == 59


async def test_cancel_pendiente_no_auto_cancela_el_siguiente_run(
    tmp_path, monkeypatch
) -> None:
    """Una cancel huérfana de un run anterior no puede detener el siguiente.

    `run_id == session_id`: si el Detener llegaba cuando el run ya había
    terminado, la marca quedaba en `_cancel_requests` y el PRIMER turno del
    siguiente run de esa sesión se detenía a sí mismo nada más empezar.
    """
    reset_services(str(tmp_path / "stale-cancel.db"))
    captured: list[dict] = []

    def mock_handler(req: httpx.Request) -> httpx.Response:
        captured.append(json.loads(req.content.decode("utf-8")))
        return httpx.Response(
            status_code=200,
            json={"choices": [{"message": {"role": "assistant", "content": "Respuesta viva"}}]},
            request=req,
        )

    router = MockRouter().add_responder("POST", r"fake\.llm", mock_handler)
    patch_httpx(monkeypatch, router)

    async def emit(kind: str, payload: dict) -> None:
        return None

    sess = "sess-stale-cancel"
    agent_module._cancel_requests.add(sess)  # residuo de un run que ya murió
    try:
        res = await agent_module.run_agent(
            message="hola de nuevo",
            case_id="case-1",
            provider="ollama",
            model=None,
            api_key=None,
            base_url=LLM_BASE,
            max_iterations=2,
            emit=emit,
            stream=False,
            plan_first=False,
            session_id=sess,
        )
        assert res["status"] == "COMPLETED"
        assert res["final_message"] == "Respuesta viva"
        assert len(captured) == 1  # sí llegó al LLM: no se autocanceló
        assert sess not in agent_module._cancel_requests
    finally:
        agent_module._cancel_requests.discard(sess)

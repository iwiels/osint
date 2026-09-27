"""
E2E del flujo agente -> kernel forense, con el LLM simulado en memoria.

Cubre el pendiente H2 del ADR-004: un run completo de `run_agent` contra un
provider OpenAI-compatible falso, verificando que las tools se ejecutan de
verdad (el caso queda en SQLite con su cadena de custodia), que el gate de
permisos emite sus eventos SSE y que los resultados vuelven al modelo en
formato de protocolo (role=tool / tool_call_id).

El bus se consume como lo haría el renderer: suscribiéndose a las colas de
`http_server.bus`. Las peticiones de permiso se responden desde el propio test
(equivalente a pulsar "Permitir" en la UI).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi import HTTPException
from http_mock import MockRouter, json_sequence, patch_httpx, sse_chat_stream
from http_server import AgentRunRequest, bus

from engine import agent as agent_module

pytestmark = pytest.mark.asyncio

LLM_BASE = "https://fake.llm/v1"


def _tool_payload(name: str, arguments: dict[str, Any], call_id: str = "call-1") -> dict[str, Any]:
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


def _final_payload(text: str) -> dict[str, Any]:
    return {"choices": [{"message": {"role": "assistant", "content": text}}]}


def _multi_tool_payload(calls: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    """Turno del modelo que pide varias herramientas a la vez (deben ir en paralelo)."""
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call-{index}",
                            "type": "function",
                            "function": {"name": name, "arguments": json.dumps(arguments)},
                        }
                        for index, (name, arguments) in enumerate(calls, start=1)
                    ],
                }
            }
        ]
    }


Turn = Callable[[list[dict[str, Any]]], dict[str, Any]]

PLAN_JSON = (
    '{"steps": [{"goal": "Listar los casos activos", "tools": ["list_cases"]}, '
    '{"goal": "Correlacionar artefactos con otros casos", "tools": ["correlate_cases"]}]}'
)


class _ScriptedLLM:
    """LLM falso que decide cada turno leyendo los resultados de tools previos.

    Es el mínimo para un E2E honesto: el agente debe poder leer el case_id que
    devolvió create_case y usarlo en las tools siguientes, igual que haría un
    modelo real. El turno se elige por número de mensajes role=tool recibidos;
    las peticiones del planificador (sin `tools`) reciben un plan JSON, y las
    peticiones normales responden en SSE cuando el agente pide streaming.
    """

    def __init__(self, turns: list[Turn], plan: str = PLAN_JSON) -> None:
        self.turns = turns
        self.plan = plan
        self.bodies: list[dict[str, Any]] = []
        self.requests: list[httpx.Request] = []
        self.streamed = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.bodies.append(body)
        self.requests.append(request)

        if not body.get("tools"):  # turno del planificador
            payload = {"choices": [{"message": {"role": "assistant", "content": self.plan}}]}
            return httpx.Response(status_code=200, json=payload, request=request)

        tool_messages = [m for m in body["messages"] if m["role"] == "tool"]
        turn = self.turns[min(len(tool_messages), len(self.turns) - 1)]
        payload = turn(tool_messages)
        if body.get("stream"):
            self.streamed += 1
            return httpx.Response(status_code=200, text=sse_chat_stream(payload), request=request)
        return httpx.Response(status_code=200, json=payload, request=request)


def _unwrap_dato(content: str) -> str:
    """El engine envuelve resultados como <dato-herramienta> (A3): el modelo
    simulado pela la envoltura igual que haría un modelo real."""
    start, end = "<dato-herramienta>", "</dato-herramienta>"
    s, e = content.find(start), content.rfind(end)
    if s != -1 and e > s:
        return content[s + len(start) : e].strip()
    return content


def _field_from_tool_results(tool_messages: list[dict[str, Any]], field: str) -> str | None:
    """Extrae un campo del último resultado de tool que lo contenga."""
    for message in reversed(tool_messages):
        try:
            payload = json.loads(_unwrap_dato(message["content"]))
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(payload, dict) and payload.get(field):
            return str(payload[field])
    return None


async def _run_agent(
    request: AgentRunRequest,
    policy: dict[str, str],
    *,
    max_events: int = 200,
    timeout: float = 10.0,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Ejecuta el agente consumiendo su bus como un cliente SSE.

    `policy` resuelve automáticamente cada petición de permiso
    ("allow" | "allow_session" | "deny"); lo no listado se deniega.
    Devuelve (resultado del run, eventos observados).
    """
    queue = bus.subscribe()
    events: list[dict[str, Any]] = []
    agent_module._pending_permissions.clear()
    agent_module._session_approvals.clear()

    async def pump() -> None:
        while len(events) < max_events:
            event = await queue.get()
            events.append(event)
            if event["type"] == "permission.request":
                payload = event["payload"]
                agent_module.respond_permission(
                    payload["request_id"], policy.get(payload["tool"], "deny")
                )
            if event["type"] in ("agent.completed", "agent.failed"):
                return

    async def emit(event_type: str, payload: dict[str, Any]) -> None:
        bus.publish(event_type, payload)

    task = asyncio.create_task(
        agent_module.run_agent(
            message=request.message,
            case_id=request.case_id,
            provider=request.provider,
            model=request.model,
            api_key=request.api_key,
            base_url=request.base_url,
            max_iterations=request.max_iterations,
            emit=emit,
            stream=request.stream,
            plan_first=request.plan_first,
        )
    )
    try:
        await asyncio.wait_for(pump(), timeout=timeout)
        return await task, events
    finally:
        bus.unsubscribe(queue)
        agent_module._session_approvals.clear()
        agent_module._pending_permissions.clear()


def _types(events: list[dict[str, Any]]) -> list[str]:
    return [e["type"] for e in events]


def _of_type(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [e["payload"] for e in events if e["type"] == event_type]


async def test_agent_e2e_crea_caso_y_registra_cadena_de_custodia(engine, monkeypatch) -> None:
    llm = _ScriptedLLM(
        [
            lambda _: _tool_payload(
                "create_case", {"name": "Operación E2E", "description": "prueba"}
            ),
            lambda msgs: _tool_payload(
                "link_entities",
                {
                    "case_id": _field_from_tool_results(msgs, "case_id"),
                    "source_id": "alias:alice",
                    "target_id": "email:alice@real.dev",
                    "relation_type": "CORRELATED_WITH",
                    "rationale": "correlación E2E",
                },
                call_id="call-2",
            ),
            lambda msgs: _tool_payload(
                "link_entities",
                {
                    "case_id": _field_from_tool_results(msgs, "case_id"),
                    "source_id": "alias:alice",
                    "target_id": "domain:alice.dev",
                    "relation_type": "CORRELATED_WITH",
                    "rationale": "segunda correlación",
                },
                call_id="call-3",
            ),
            lambda _: _final_payload("Investigación completada con 3 herramientas."),
        ]
    )
    router = patch_httpx(
        monkeypatch=monkeypatch,
        router=MockRouter().add_responder("POST", r"chat/completions", llm),
    )

    result, events = await _run_agent(
        AgentRunRequest(
            message="Investiga a alice", provider="openai", api_key="test", base_url=LLM_BASE
        ),
        policy={"create_case": "allow", "link_entities": "allow_session"},
    )

    # --- Resultado del loop ---
    assert result["status"] == "COMPLETED"
    assert result["iterations"] == 4
    assert [t["tool"] for t in result["tools_used"]] == [
        "create_case",
        "link_entities",
        "link_entities",
    ]
    assert result["final_message"] == "Investigación completada con 3 herramientas."

    # --- Eventos SSE (contrato con el renderer) ---
    types = _types(events)
    assert types[0] == "agent.started"
    assert types[-1] == "agent.completed"
    started = _of_type(events, "agent.started")[0]
    assert started["provider"] == "openai"
    assert started["streaming"] is True and started["max_iterations"] == 25
    assert types.count("tool.started") == 3
    assert types.count("tool.completed") == 3

    # --- Planificador: se publica por SSE y se le devuelve al modelo como contexto ---
    plan_events = _of_type(events, "agent.plan")
    assert len(plan_events) == 1
    assert plan_events[0]["source"] == "planner"
    assert plan_events[0]["total_steps"] == 2
    assert [s["goal"] for s in plan_events[0]["steps"]] == [
        "Listar los casos activos",
        "Correlacionar artefactos con otros casos",
    ]
    primer_turno = llm.bodies[1]["messages"]
    assert "Plan aprobado para esta investigación" in primer_turno[-1]["content"]
    assert "1. Listar los casos activos (herramientas: list_cases)" in primer_turno[-1]["content"]

    # --- Streaming: los tokens llegan fragmentados y reconstruyen el mensaje final ---
    assert "".join(t["delta"] for t in _of_type(events, "agent.token")) == (
        "Investigación completada con 3 herramientas."
    )
    assert "agent.stream_fallback" not in types

    # --- Consumo acumulado de los 4 turnos (usage del stream) ---
    assert _of_type(events, "agent.completed")[0]["usage"] == {
        "input_tokens": 44,
        "output_tokens": 28,
    }
    assert result["usage"] == {"input_tokens": 44, "output_tokens": 28}

    # --- Gate de permisos: allow_session pregunta una sola vez por tool ---
    requests = _of_type(events, "permission.request")
    assert [r["tool"] for r in requests] == ["create_case", "link_entities"]
    assert types.count("permission.granted") == 2

    # --- Efectos reales en el kernel forense ---
    cases = engine.db.list_cases()
    assert len(cases) == 1
    assert cases[0].name == "Operación E2E"
    case_id = cases[0].case_id

    created = json.loads(_of_type(events, "tool.completed")[0]["result"])
    assert created["status"] == "CASE_CREATED"
    assert created["case_id"] == case_id

    ledger_blocks = engine.db.get_case_ledger(case_id)
    assert [b.action.split(":")[0] for b in ledger_blocks] == [
        "GENESIS_CASE_INITIALIZED",
        "MANUAL_LINK",
        "MANUAL_LINK",
    ]
    assert ledger_blocks[0].block_hash == created["genesis_hash"]

    relations = engine.db.get_case_relations(case_id)
    assert {r.target_id for r in relations} == {"email:alice@real.dev", "domain:alice.dev"}
    assert {r.attributes["rationale"] for r in relations} == {
        "correlación E2E",
        "segunda correlación",
    }
    assert (await async_verify(engine, case_id))["valid"] is True

    # --- El resultado vuelve al modelo en formato de protocolo OpenAI ---
    assert router.count(r"chat/completions") == 5  # 1 planificador + 4 turnos
    assert llm.streamed == 4  # todos los turnos llegaron por streaming
    last_body = llm.bodies[-1]
    tool_messages = [m for m in last_body["messages"] if m["role"] == "tool"]
    assert len(tool_messages) == 3
    assert tool_messages[-1]["tool_call_id"] == "call-3"
    assert json.loads(_unwrap_dato(tool_messages[0]["content"]))["status"] == "CASE_CREATED"
    assert last_body["model"] == "gpt-4.1"
    assert llm.requests[-1].headers["authorization"] == "Bearer test"


async def async_verify(engine, case_id: str) -> dict[str, Any]:
    """Corre la tool de integridad por la ruta real del registry."""
    from engine.registry import call_tool_validated

    return json.loads(await call_tool_validated("verify_case_integrity", {"case_id": case_id}))


async def test_agente_ejecuta_en_paralelo_las_tools_del_mismo_turno(engine, monkeypatch) -> None:
    llm = _ScriptedLLM(
        [
            lambda _: _multi_tool_payload(
                [
                    ("list_cases", {}),
                    ("analyze_network_metrics", {"case_id": "case-x"}),
                    ("correlate_cases", {}),
                ]
            ),
            lambda _: _final_payload("Barrido inicial completo."),
        ]
    )
    patch_httpx(
        monkeypatch=monkeypatch,
        router=MockRouter().add_responder("POST", r"chat/completions", llm),
    )

    result, events = await _run_agent(
        AgentRunRequest(
            message="estado del repositorio",
            provider="openai",
            api_key="test",
            base_url=LLM_BASE,
            plan_first=False,
        ),
        policy={},
    )

    assert result["iterations"] == 2
    assert [t["tool"] for t in result["tools_used"]] == [
        "list_cases",
        "analyze_network_metrics",
        "correlate_cases",
    ]
    assert _of_type(events, "agent.tools_parallel") == [
        {"count": 3, "tools": ["list_cases", "analyze_network_metrics", "correlate_cases"]}
    ]
    assert _types(events).count("tool.started") == 3

    # Los resultados vuelven al modelo en el mismo orden en que se pidieron.
    final_body = llm.bodies[-1]
    assert [m["tool_call_id"] for m in final_body["messages"] if m["role"] == "tool"] == [
        "call-1",
        "call-2",
        "call-3",
    ]
    assert json.loads(result["tools_used"][1]["result"])["total_nodes"] == 0
    # Sin evidencia no hay plan: el planificador tampoco rompe el run al fallar.
    assert _of_type(events, "agent.plan") == []


async def test_agente_cae_a_modo_sin_stream_si_el_provider_lo_rechaza(engine, monkeypatch) -> None:
    served = {"count": 0}

    def rejects_stream(request: httpx.Request) -> httpx.Response:
        served["count"] += 1
        if served["count"] == 1:
            return httpx.Response(
                status_code=400, json={"error": "stream no soportado"}, request=request
            )
        return httpx.Response(
            status_code=200, json=_final_payload("Respondido sin streaming."), request=request
        )

    patch_httpx(
        monkeypatch=monkeypatch,
        router=MockRouter().add_responder("POST", r"chat/completions", rejects_stream),
    )

    result, events = await _run_agent(
        AgentRunRequest(
            message="hola",
            provider="openai",
            api_key="test",
            base_url=LLM_BASE,
            plan_first=False,
        ),
        policy={},
    )

    assert served["count"] == 2
    assert result["final_message"] == "Respondido sin streaming."
    assert _of_type(events, "agent.stream_fallback") == [{"status": 400}]
    assert result["usage"] == {"input_tokens": 0, "output_tokens": 0}


async def test_agente_deniega_tool_sensible_y_no_toca_el_kernel(engine, monkeypatch) -> None:
    patch_httpx(
        monkeypatch=monkeypatch,
        router=MockRouter().add_responder(
            "POST",
            r"chat/completions",
            json_sequence(
                _tool_payload("create_case", {"name": "No autorizado", "description": "x"}),
                _final_payload("No pude crear el caso."),
            ),
        ),
    )

    result, events = await _run_agent(
        AgentRunRequest(
            message="crea un caso",
            provider="openai",
            api_key="test",
            base_url=LLM_BASE,
            stream=False,
            plan_first=False,
        ),
        policy={"create_case": "deny"},
    )

    assert result["status"] == "COMPLETED"
    assert result["iterations"] == 2
    assert engine.db.list_cases() == []
    denied = json.loads(result["tools_used"][0]["result"])
    assert denied == {"error": "Permiso denegado por el analista", "tool": "create_case"}
    assert _of_type(events, "permission.granted") == []


async def test_agente_no_pregunta_permiso_para_tools_seguras(engine, monkeypatch) -> None:
    patch_httpx(
        monkeypatch=monkeypatch,
        router=MockRouter().add_responder(
            "POST",
            r"chat/completions",
            json_sequence(
                _tool_payload("list_cases", {}),
                _tool_payload("analyze_network_metrics", {"case_id": "case-x"}, call_id="call-2"),
                _final_payload("Sin casos activos."),
            ),
        ),
    )

    result, events = await _run_agent(
        AgentRunRequest(
            message="estado",
            provider="openai",
            api_key="test",
            base_url=LLM_BASE,
            stream=False,
            plan_first=False,
        ),
        policy={},
    )

    assert result["status"] == "COMPLETED"
    assert _of_type(events, "permission.request") == []
    assert json.loads(result["tools_used"][0]["result"]) == []
    assert json.loads(result["tools_used"][1]["result"])["total_nodes"] == 0


async def test_agente_reintenta_tras_rate_limit_y_avisa_por_sse(engine, monkeypatch) -> None:
    served = {"count": 0}

    def limited_once(request: httpx.Request) -> httpx.Response:
        served["count"] += 1
        if served["count"] == 1:
            return httpx.Response(
                status_code=429,
                headers={"retry-after": "0"},
                json={"error": "cuota agotada"},
                request=request,
            )
        return httpx.Response(
            status_code=200,
            text=sse_chat_stream(_final_payload("Reintento exitoso.")),
            request=request,
        )

    patch_httpx(
        monkeypatch=monkeypatch,
        router=MockRouter().add_responder("POST", r"chat/completions", limited_once),
    )

    result, events = await _run_agent(
        AgentRunRequest(
            message="hola",
            provider="opencode",
            api_key="test",
            base_url=LLM_BASE,
            plan_first=False,
        ),
        policy={},
    )

    assert result["status"] == "COMPLETED"
    assert result["final_message"] == "Reintento exitoso."
    assert served["count"] == 2
    assert _of_type(events, "agent.rate_limited") == [
        {"attempt": 1, "wait_seconds": 0.0, "status": 429}
    ]
    assert events[-1]["type"] == "agent.completed"


async def test_agente_tool_inexistente_no_rompe_el_run(engine, monkeypatch) -> None:
    patch_httpx(
        monkeypatch=monkeypatch,
        router=MockRouter().add_responder(
            "POST",
            r"chat/completions",
            json_sequence(
                _tool_payload("tool_fantasma", {"x": 1}),
                _final_payload("Herramienta no disponible."),
            ),
        ),
    )

    result, events = await _run_agent(
        AgentRunRequest(
            message="usa una tool rara",
            provider="openai",
            api_key="test",
            base_url=LLM_BASE,
            stream=False,
            plan_first=False,
        ),
        policy={},
    )

    assert result["status"] == "COMPLETED"
    assert "no existe" in json.loads(result["tools_used"][0]["result"])["error"]
    assert _of_type(events, "tool.completed")[0]["tool"] == "tool_fantasma"


async def test_endpoint_agent_run_valida_caso_y_provider(engine) -> None:
    with pytest.raises(HTTPException) as missing:
        await engine.agent_run(
            AgentRunRequest(message="x", provider="openai", api_key="k", case_id="case-inexistente")
        )
    assert missing.value.status_code == 404

    with pytest.raises(HTTPException) as bad_provider:
        await engine.agent_run(AgentRunRequest(message="x", provider="proveedor-raro"))
    assert bad_provider.value.status_code == 400
    assert "Provider desconocido" in bad_provider.value.detail

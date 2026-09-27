"""
Tests unitarios de las piezas de la fase C: parser del plan, nota de plan,
parser de SSE y acumulación de consumo.

El E2E del run completo vive en test_agent_e2e.py; aquí se ataca cada pieza por
separado, incluidos los casos sucios que un provider real sí produce (líneas
keepalive, JSON roto, tool_calls sin id, fragmentos fuera de orden).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from http_mock import MockRouter, patch_httpx

from engine.agent import (
    PLANNER_PROMPT,
    ProviderConfig,
    _accumulate_usage,
    _emit_plan,
    _openai_tools,
    _plan_note,
    _sse_chunks,
    _step_openai_compatible_stream,
    parse_plan,
)

CFG = ProviderConfig(
    name="openai", base_url="https://fake.llm/v1", api_key="test", default_model="gpt-4.1"
)
TOOLS = [
    {
        "name": "list_cases",
        "description": "Lista casos",
        "input_schema": {"type": "object", "properties": {}},
    }
]


# --- Planificador ---


@pytest.mark.parametrize(
    ("raw", "expected_goals"),
    [
        ('{"steps": [{"goal": "A", "tools": ["list_cases"]}]}', ["A"]),
        ('```json\n{"steps": [{"goal": "A"}, {"goal": "B"}]}\n```', ["A", "B"]),
        (
            'Claro, aquí va:\n{"steps": ["paso uno", "paso dos"]}\nEspero que sirva.',
            ["paso uno", "paso dos"],
        ),
        ('{"steps": [{"step": "algo"}]}', ["algo"]),
    ],
)
def test_parse_plan_extrae_pasos(raw, expected_goals):
    plan = parse_plan(raw)

    assert [p["goal"] for p in plan] == expected_goals
    assert [p["step"] for p in plan] == list(range(1, len(expected_goals) + 1))
    assert all(isinstance(p["tools"], list) for p in plan)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "sin json aquí",
        "{roto",
        '{"steps": "no es lista"}',
        '{"sin": "steps"}',
        "[]",
    ],
)
def test_parse_plan_tolera_respuestas_invalidas(raw):
    assert parse_plan(raw) == []


def test_parse_plan_normaliza_y_limita():
    steps = [{"goal": f"paso {i}", "tools": ["a", "b", "c", "d", "e", "f"]} for i in range(20)]

    plan = parse_plan(json.dumps({"steps": steps}))

    assert len(plan) == 12  # tope de seguridad
    assert plan[0]["tools"] == ["a", "b", "c", "d", "e"]  # 5 herramientas por paso
    assert plan[0]["goal"] == "paso 0"


def test_parse_plan_descarta_pasos_vacios():
    plan = parse_plan('{"steps": [{"goal": "  "}, {"tools": ["list_cases"]}, 42, {"goal": "ok"}]}')

    assert plan == [{"step": 1, "goal": "ok", "tools": []}]


def test_plan_note_formatea_herramientas():
    note = _plan_note(
        [
            {
                "step": 1,
                "goal": "Enumerar el dominio",
                "tools": ["investigate_domain", "case_timeline"],
            },
            {"step": 2, "goal": "Sellar custodia", "tools": []},
        ]
    )

    assert note.startswith("Plan aprobado para esta investigación:")
    assert "1. Enumerar el dominio (herramientas: investigate_domain, case_timeline)" in note
    assert note.endswith("2. Sellar custodia")


async def test_emit_plan_publica_y_avisa_si_falla(monkeypatch):
    router = MockRouter().add(
        "POST",
        r"chat/completions",
        json={"choices": [{"message": {"content": '{"steps": [{"goal": "Recon", "tools": []}]}'}}]},
    )
    patch_httpx(monkeypatch, router)
    events: list[tuple[str, dict[str, Any]]] = []

    async def emit(event_type: str, payload: dict[str, Any]) -> None:
        events.append((event_type, payload))

    async with httpx.AsyncClient() as client:
        plan = await _emit_plan(client, CFG, "gpt-4.1", "investiga a alice", emit)

    assert plan == [{"step": 1, "goal": "Recon", "tools": []}]
    assert events == [
        ("agent.plan", {"steps": plan, "total_steps": 1, "source": "planner"}),
    ]
    payload = json.loads(router.requests[0].content)
    assert payload["messages"][0]["content"] == PLANNER_PROMPT
    assert payload["messages"][1]["content"] == "investiga a alice"
    assert "tools" not in payload  # el planificador no ve el catálogo de herramientas


async def test_emit_plan_reporta_error_sin_romper(monkeypatch):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sin red", request=request)

    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"chat/completions", boom))
    events: list[tuple[str, dict[str, Any]]] = []

    async def emit(event_type: str, payload: dict[str, Any]) -> None:
        events.append((event_type, payload))

    async with httpx.AsyncClient() as client:
        plan = await _emit_plan(client, CFG, "gpt-4.1", "hola", emit)

    assert plan == []
    assert events[0][0] == "agent.plan"
    assert events[0][1]["steps"] == [] and "sin red" in events[0][1]["error"]


async def test_emit_plan_sin_pasos_validos(monkeypatch):
    patch_httpx(
        monkeypatch,
        MockRouter().add(
            "POST", r"chat/completions", json={"choices": [{"message": {"content": "no json"}}]}
        ),
    )
    events: list[tuple[str, dict[str, Any]]] = []

    async def emit(event_type: str, payload: dict[str, Any]) -> None:
        events.append((event_type, payload))

    async with httpx.AsyncClient() as client:
        plan = await _emit_plan(client, CFG, "gpt-4.1", "hola", emit)

    assert plan == []
    assert events == [("agent.plan", {"steps": [], "source": "planner"})]


# --- Streaming ---

STREAM_BODY = (
    ": keepalive\n\n"
    'data: {"choices": [{"delta": {"content": "Ana"}}]}\n\n'
    "event: ping\n"
    'data: {"choices": [{"delta": {"content": "lizando"}}]}\n\n'
    "data: {roto\n\n"
    'data: {"choices": [{"delta": {"tool_calls": ['
    '{"index": 0, "id": "call-a", "function": {"name": "list_cases", "arguments": "{}"}},'
    '{"index": 1, "function": {"name": "case_timeline", "arguments": "{\\"case_id\\": "}}'
    "]}}]}\n\n"
    'data: {"choices": [{"delta": {"tool_calls": ['
    '{"index": 1, "function": {"arguments": "\\"case-1\\"}"}}'
    "]}}]}\n\n"
    'data: {"choices": [], "usage": {"prompt_tokens": 30, "completion_tokens": 12}}\n\n'
    "data: [DONE]\n\n"
)


async def test_streaming_ensambla_tokens_y_tool_calls_fragmentados(monkeypatch):
    patch_httpx(monkeypatch, MockRouter().add("POST", r"chat/completions", text=STREAM_BODY))
    tokens: list[str] = []

    async def on_token(delta: str) -> None:
        tokens.append(delta)

    async with httpx.AsyncClient() as client:
        message, tool_calls = await _step_openai_compatible_stream(
            client, CFG, "gpt-4.1", "system", [{"role": "user", "content": "hola"}], TOOLS, on_token
        )

    assert tokens == ["Ana", "lizando"]
    assert message["content"] == "Analizando"
    assert message["_usage"] == {"prompt_tokens": 30, "completion_tokens": 12}
    assert [c["name"] for c in tool_calls] == ["list_cases", "case_timeline"]
    assert tool_calls[0] == {"id": "call-a", "name": "list_cases", "arguments": {}}
    # El segundo tool_call llega partido y sin id: se reconstruye y se acuña uno.
    assert tool_calls[1]["arguments"] == {"case_id": "case-1"}
    assert tool_calls[1]["id"] == "call-1"
    assert [c["function"]["arguments"] for c in message["tool_calls"]] == [
        "{}",
        '{"case_id": "case-1"}',
    ]


async def test_streaming_error_http_se_propaga_para_reintento(monkeypatch):
    patch_httpx(
        monkeypatch, MockRouter().add("POST", r"chat/completions", json={}, status_code=503)
    )

    async def on_token(delta: str) -> None:  # pragma: no cover - no llega a emitir
        raise AssertionError("no debería emitir tokens")

    with pytest.raises(httpx.HTTPStatusError) as exc:
        async with httpx.AsyncClient() as client:
            await _step_openai_compatible_stream(
                client, CFG, "gpt-4.1", "s", [{"role": "user", "content": "x"}], TOOLS, on_token
            )

    assert exc.value.response.status_code == 503


async def test_streaming_sin_tool_calls_ni_contenido(monkeypatch):
    patch_httpx(monkeypatch, MockRouter().add("POST", r"chat/completions", text="data: [DONE]\n\n"))
    tokens: list[str] = []

    async def on_token(delta: str) -> None:
        tokens.append(delta)

    async with httpx.AsyncClient() as client:
        message, tool_calls = await _step_openai_compatible_stream(
            client, CFG, "gpt-4.1", "s", [{"role": "user", "content": "x"}], TOOLS, on_token
        )

    assert (message, tool_calls, tokens) == ({"role": "assistant", "content": None}, [], [])


async def test_sse_chunks_ignora_lineas_no_data(monkeypatch):
    patch_httpx(
        monkeypatch, MockRouter().add("POST", r"chat", text='hola\n\ndata: {"a": 1}\n\n: x\n')
    )

    async with httpx.AsyncClient() as client:
        response = await client.post("https://fake.llm/chat", json={})
        assert [chunk async for chunk in _sse_chunks(response)] == [{"a": 1}]


# --- Consumo y formato de herramientas ---


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ({"prompt_tokens": 10, "completion_tokens": 4}, {"input_tokens": 10, "output_tokens": 4}),
        ({"input_tokens": 7, "output_tokens": 3}, {"input_tokens": 7, "output_tokens": 3}),
        ({}, {"input_tokens": 0, "output_tokens": 0}),
        (None, {"input_tokens": 0, "output_tokens": 0}),
        ("no es dict", {"input_tokens": 0, "output_tokens": 0}),
    ],
)
def test_accumulate_usage(raw, expected):
    total = {"input_tokens": 0, "output_tokens": 0}

    _accumulate_usage(total, raw)

    assert total == expected


def test_accumulate_usage_suma_entre_turnos():
    total = {"input_tokens": 0, "output_tokens": 0}

    _accumulate_usage(total, {"prompt_tokens": 10, "completion_tokens": 2})
    _accumulate_usage(total, {"prompt_tokens": 5, "completion_tokens": 1})

    assert total == {"input_tokens": 15, "output_tokens": 3}


def test_openai_tools_mapea_el_schema():
    assert _openai_tools(TOOLS) == [
        {
            "type": "function",
            "function": {
                "name": "list_cases",
                "description": "Lista casos",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]

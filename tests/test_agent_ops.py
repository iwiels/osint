"""
Tests de las operaciones del loop del agente (estilo opencode): reglas de
permiso, timeout de tools, truncado, guard anti-bucle, ask_analyst,
menciones @archivo. Sin LLM real.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from engine import agent as agent_module
from engine.agent import (
    _ask_analyst,
    _doom_key,
    _fit_for_model,
    _note_call,
    _permission_action,
    _resolve_mentions,
    reply_question,
)


def test_fit_for_model_pasa_texto_corto() -> None:
    assert _fit_for_model("hola") == "hola"


def test_fit_for_model_trunca_con_aviso(monkeypatch) -> None:
    monkeypatch.setattr(agent_module, "MAX_MODEL_CHARS", 10)
    out = _fit_for_model("1234567890ABCDEF")
    assert out.startswith("1234567890")
    assert "16 caracteres" in out


def test_note_call_detecta_tercera_identica() -> None:
    recent: list[tuple[str, str]] = []
    args = {"target": "x"}
    assert _note_call(recent, "web_search", args) is False
    assert _note_call(recent, "web_search", dict(args)) is False
    assert _note_call(recent, "web_search", args) is True


def test_note_call_ignora_intercaladas() -> None:
    recent: list[tuple[str, str]] = []
    _note_call(recent, "web_search", {"q": "a"})
    _note_call(recent, "web_search", {"q": "a"})
    assert _note_call(recent, "query_graph", {}) is False
    assert _note_call(recent, "web_search", {"q": "a"}) is False


def test_doom_key_canonica_orden() -> None:
    assert _doom_key("t", {"b": 1, "a": 2}) == _doom_key("t", {"a": 2, "b": 1})


def test_permission_action_reglas() -> None:
    assert _permission_action("triage_entity") == "allow"
    assert _permission_action("web_search") == "allow"
    assert _permission_action("parallel_search") == "allow"
    assert _permission_action("ask_analyst") == "allow"
    assert _permission_action("investigate_identity") == "ask"
    # web_fetch es lectura pura: pedirle permiso ahogó la sesión real en
    # timeouts de 300s (la ingesta en el caso la hacen los wrappers de
    # escritura, que sí preguntan).
    assert _permission_action("web_fetch") == "allow"
    assert _permission_action("tool_futura_desconocida") == "ask"


def test_permission_action_deny(monkeypatch) -> None:
    monkeypatch.setattr(agent_module, "DENY_TOOLS", {"triage_entity"})
    assert _permission_action("triage_entity") == "deny"
    monkeypatch.setattr(agent_module, "DENY_TOOLS", set())
    monkeypatch.setattr(agent_module, "DENY_PATTERNS", ("investigate_*",))
    assert _permission_action("investigate_identity") == "deny"
    assert _permission_action("triage_entity") == "allow"


def test_resolve_mentions_inyecta_archivo() -> None:
    out = _resolve_mentions("revisa @pyproject.toml por favor")
    assert '<archivo path="pyproject.toml">' in out
    assert "revisa @pyproject.toml" in out


def test_resolve_mentions_senala_ausentes_y_externos() -> None:
    out = _resolve_mentions("mira @no-existe-xyz.md y @../fuera.txt")
    assert "no existe" in out
    assert "fuera del proyecto" in out


def test_resolve_mentions_sin_menciones() -> None:
    assert _resolve_mentions("hola mundo") == "hola mundo"


async def test_ask_analyst_flujo_respuesta() -> None:
    emitted: list[tuple[str, dict]] = []

    async def emit(kind: str, payload: dict) -> None:
        emitted.append((kind, payload))

    task = asyncio.create_task(
        _ask_analyst(
            {"questions": [{"question": "¿Anclaje?", "options": [{"label": "DNI"}]}]},
            "s1",
            emit,
        )
    )
    await asyncio.sleep(0.05)
    assert emitted and emitted[0][0] == "question.asked"
    request_id = emitted[0][1]["request_id"]
    assert reply_question(request_id, [["DNI"]]) is True
    assert reply_question(request_id, [["DNI"]]) is False  # ya resuelta

    body = json.loads(await task)
    assert body["status"] == "ANSWERED"
    assert body["answers"] == [{"question": "¿Anclaje?", "answer": ["DNI"]}]


async def test_ask_analyst_timeout(monkeypatch) -> None:
    monkeypatch.setattr(agent_module, "QUESTION_TIMEOUT_SECONDS", 0.05)

    async def emit(kind: str, payload: dict) -> None:
        return None

    body = json.loads(await _ask_analyst({"questions": [{"question": "¿X?"}]}, "s1", emit))
    assert body["status"] == "UNANSWERED"


async def test_ask_analyst_rechaza_vacio() -> None:
    async def emit(kind: str, payload: dict) -> None:
        return None

    body = json.loads(await _ask_analyst({"questions": []}, "s1", emit))
    assert "error" in body


async def test_execute_tool_timeout(monkeypatch) -> None:
    async def lenta(name: str, arguments: dict) -> str:
        await asyncio.sleep(5)
        return "{}"

    monkeypatch.setattr(agent_module, "call_tool_validated", lenta)
    monkeypatch.setattr(agent_module, "TOOL_TIMEOUT_SECONDS", 0.05)

    async def emit(kind: str, payload: dict) -> None:
        return None

    out = await agent_module._execute_tool("triage_entity", {"artifact": "x"}, "s", emit)
    body = json.loads(out)
    assert "timeout" in body["error"]


async def test_execute_tool_deny(monkeypatch) -> None:
    monkeypatch.setattr(agent_module, "DENY_TOOLS", {"triage_entity"})

    async def emit(kind: str, payload: dict) -> None:
        return None

    out = await agent_module._execute_tool("triage_entity", {"artifact": "x"}, "s", emit)
    body = json.loads(out)
    assert "bloqueada" in body["error"]


async def test_execute_tool_desconocida_no_abre_dialogo() -> None:
    async def emit(kind: str, payload: dict) -> None:
        raise AssertionError("no debe emitir permisos para tools inexistentes")

    body = json.loads(await agent_module._execute_tool("no_existe_xyz", {}, "s", emit))
    assert "no existe" in body["error"]


def test_reply_question_desconocida() -> None:
    assert reply_question("q-inexistente", [["a"]]) is False


@pytest.mark.asyncio
async def test_registry_incluye_ask_analyst() -> None:
    names = [t["name"] for t in await agent_module._registry_tools()]
    assert "ask_analyst" in names
    assert "web_search" in names and "parallel_search" in names and "load_skill" in names

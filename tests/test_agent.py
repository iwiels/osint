"""
Tests del módulo de agente sin LLM real: solo el plano de permisos
(clasificación SAFE/SENSITIVE y resolución de peticiones), que es la lógica
con consecuencias de seguridad.
"""

from __future__ import annotations

import pytest
from specter.osint_core.permission_gate import SAFE_TOOLS, SENSITIVE_TOOLS

from engine.agent import (
    PermissionRequest,
    respond_permission,
)


def test_safe_and_sensitive_sets_are_disjoint() -> None:
    """Ninguna tool puede ser a la vez segura y sensible (invariante de seguridad)."""
    assert SAFE_TOOLS.isdisjoint(SENSITIVE_TOOLS)


def test_readonly_tools_are_classified_safe() -> None:
    for tool in ("list_cases", "query_graph", "analyze_network_metrics", "verify_case_integrity"):
        assert tool in SAFE_TOOLS
        assert tool not in SENSITIVE_TOOLS


def test_collectors_and_writes_require_permission() -> None:
    for tool in (
        "create_case",
        "investigate_domain",
        "investigate_identity",
        "export_case_dossier",
    ):
        assert tool in SENSITIVE_TOOLS


@pytest.mark.asyncio
async def test_execute_tool_emite_permission_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Al vencer la espera se publica `permission.timeout` con el request_id.

    Sin ese evento la UI conservaba el diálogo en pantalla: el analista creía
    estar autorizando mientras el motor ya había devuelto el error al modelo,
    y su clic respondía a un id caducado (404).
    """
    from engine import agent

    monkeypatch.setattr(agent, "PERMISSION_TIMEOUT_SECONDS", 0.05)
    events: list[tuple[str, dict]] = []

    async def emit(event_type: str, payload: dict) -> None:
        events.append((event_type, payload))

    session = "s-timeout-regression"
    try:
        result = await agent._execute_tool(
            "link_entities",
            {"case_id": "c1", "source_id": "a", "target_id": "b"},
            session,
            emit,
        )
    finally:
        agent._session_approvals.discard((session, "link_entities"))

    assert "sin respuesta del analista" in result
    timeouts = [payload for kind, payload in events if kind == "permission.timeout"]
    assert len(timeouts) == 1, "debe emitirse exactamente un permission.timeout"
    assert timeouts[0]["tool"] == "link_entities"
    # La petición caducada no puede quedarse registrada: reintentarla daría 404.
    assert timeouts[0]["request_id"] not in agent._pending_permissions


@pytest.mark.asyncio
async def test_respond_permission_allow() -> None:
    req = PermissionRequest(
        request_id="p1", tool_name="investigate_domain", arguments={}, session_id="s1"
    )
    from engine import agent

    agent._pending_permissions["p1"] = req
    try:
        assert await _resolve(req, "allow") == "allowed"
        assert ("s1", "investigate_domain") not in agent._session_approvals
    finally:
        agent._pending_permissions.pop("p1", None)


@pytest.mark.asyncio
async def test_respond_permission_allow_session_is_persistent() -> None:
    from engine import agent

    req = PermissionRequest(
        request_id="p2", tool_name="investigate_domain", arguments={}, session_id="s2"
    )
    agent._pending_permissions["p2"] = req
    try:
        assert await _resolve(req, "allow_session") == "allowed"
        assert ("s2", "investigate_domain") in agent._session_approvals
        agent._session_approvals.discard(("s2", "investigate_domain"))
    finally:
        agent._pending_permissions.pop("p2", None)


@pytest.mark.asyncio
async def test_respond_permission_deny() -> None:
    from engine import agent

    req = PermissionRequest(
        request_id="p3", tool_name="investigate_identity", arguments={}, session_id="s3"
    )
    agent._pending_permissions["p3"] = req
    try:
        assert await _resolve(req, "deny") == "denied"
    finally:
        agent._pending_permissions.pop("p3", None)


async def _resolve(req: PermissionRequest, decision: str) -> str:
    """Resuelve la petición y espera el future (mismo contrato que el endpoint HTTP)."""
    import asyncio

    loop = asyncio.get_running_loop()
    req.future = loop.create_future()
    assert respond_permission(req.request_id, decision) is True
    return await asyncio.wait_for(req.future, timeout=1)


@pytest.mark.asyncio
async def test_request_run_cancel_marca_runs_y_libera_permisos() -> None:
    """El botón Detener: marca el run y resuelve esperas de permiso como denegadas."""
    import asyncio

    from engine import agent

    loop = asyncio.get_running_loop()
    req = PermissionRequest(
        request_id="pc", tool_name="investigate_domain", arguments={}, session_id="sc"
    )
    req.future = loop.create_future()
    agent._pending_permissions["pc"] = req
    agent._active_runs["run-x"] = "sc"
    try:
        assert agent.request_run_cancel("sc") == 1
        assert "run-x" in agent._cancel_requests
        assert await asyncio.wait_for(req.future, timeout=1) == "denied"
        assert agent.request_run_cancel("otra-sesion") == 0
    finally:
        agent._pending_permissions.pop("pc", None)
        agent._active_runs.pop("run-x", None)
        agent._cancel_requests.discard("run-x")


@pytest.mark.asyncio
async def test_request_run_cancel_por_run_id_resuelve_preguntas() -> None:
    """Detener por `run_id` ancla el run exacto y libera la pregunta pendiente.

    Sin esto, una pregunta de `ask_analyst` dejaba el run colgado 300s tras el
    Detener y la UI seguía mostrando un diálogo cuya respuesta ya nadie leería.
    """
    import asyncio

    from engine import agent

    loop = asyncio.get_running_loop()
    q = agent.QuestionRequest(
        request_id="qc",
        questions=[{"question": "¿Seguimos con el pivote?", "header": "", "options": []}],
        session_id="global",
    )
    q.future = loop.create_future()
    agent._pending_questions["qc"] = q
    agent._active_runs["run-g"] = "global"
    agent._active_runs["run-otro"] = "case-9"
    try:
        assert agent.request_run_cancel(run_id="run-g") == 1
        assert "run-g" in agent._cancel_requests
        assert "run-otro" not in agent._cancel_requests  # sólo el run pedido
        assert q.status == "unanswered"
        assert await asyncio.wait_for(q.future, timeout=1) == "unanswered"
    finally:
        agent._pending_questions.pop("qc", None)
        agent._active_runs.pop("run-g", None)
        agent._active_runs.pop("run-otro", None)
        agent._cancel_requests.discard("run-g")


@pytest.mark.asyncio
async def test_request_run_cancel_por_case_sigue_funcionando() -> None:
    """Compatibilidad: la UI puede seguir enviando el case_id (ámbito)."""
    import asyncio

    from engine import agent

    loop = asyncio.get_running_loop()
    req = PermissionRequest(
        request_id="pc2", tool_name="link_entities", arguments={}, session_id="case-7"
    )
    req.future = loop.create_future()
    agent._pending_permissions["pc2"] = req
    agent._active_runs["run-c7"] = "case-7"
    try:
        assert agent.request_run_cancel("case-7") == 1
        assert "run-c7" in agent._cancel_requests
        assert await asyncio.wait_for(req.future, timeout=1) == "denied"
    finally:
        agent._pending_permissions.pop("pc2", None)
        agent._active_runs.pop("run-c7", None)
        agent._cancel_requests.discard("run-c7")


@pytest.mark.asyncio
async def test_ask_analyst_devuelve_unanswered_si_el_run_se_detiene() -> None:
    """Tras un Detener, `ask_analyst` devuelve UNANSWERED, no ANSWERED vacío.

    Devolver `ANSWERED` con lista de respuestas vacías haría creer al modelo
    que el analista respondió "nada" cuando en realidad nadie respondió.
    """
    import asyncio
    import json as _json

    from engine import agent

    events: list[tuple[str, dict]] = []

    async def emit(event_type: str, payload: dict) -> None:
        events.append((event_type, payload))

    agent._active_runs["run-q"] = "case-q"
    task = asyncio.create_task(
        agent._ask_analyst(
            {"questions": [{"question": "¿Vigilar el subdominio?"}]}, "case-q", emit
        )
    )
    try:
        for _ in range(200):
            if agent._pending_questions:
                break
            await asyncio.sleep(0.005)
        assert agent._pending_questions, "la pregunta debió registrarse"
        rid = next(iter(agent._pending_questions))

        assert agent.request_run_cancel(run_id="run-q") == 1
        result = _json.loads(await asyncio.wait_for(task, timeout=2))
        assert result["status"] == "UNANSWERED"
        assert rid not in agent._pending_questions
    finally:
        agent._active_runs.pop("run-q", None)
        agent._cancel_requests.discard("run-q")
        if not task.done():
            task.cancel()

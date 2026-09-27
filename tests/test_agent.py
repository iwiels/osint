"""
Tests del módulo de agente sin LLM real: solo el plano de permisos
(clasificación SAFE/SENSITIVE y resolución de peticiones), que es la lógica
con consecuencias de seguridad.
"""

from __future__ import annotations

import pytest

from engine.agent import (
    SAFE_TOOLS,
    SENSITIVE_TOOLS,
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

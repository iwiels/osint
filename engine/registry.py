"""
Acceso unificado al registro de tools del servidor MCP.

El MCP 2.2.0 expone list_tools() a nivel protocolo (sin fn ejecutable);
el registro interno _tool_manager contiene los objetos Tool completos
(fn, is_async, parameters). Esta capa aísla esa diferencia para que el
servidor HTTP y el agente usen un único contrato.
"""

from __future__ import annotations

from typing import Any

from specter.osint_core.permission_gate import _check_tool_permission, tool_resource
from specter.server import mcp_server


class ToolPermissionDenied(PermissionError):
    """El permission gate denegó la llamada directa (API/MCP)."""


async def get_registry_tools() -> dict[str, Any]:
    """Devuelve {name: Tool} desde el registro interno del MCPServer."""
    return dict(mcp_server._tool_manager._tools)


async def call_tool_validated(
    name: str, arguments: dict[str, Any], *, policy_checked: bool = False
) -> str:
    """Invoca una tool validando argumentos contra su schema pydantic.

    Usa la ruta oficial del MCP: fn_metadata.validate_arguments() + call_fn().
    call_fn ejecuta funciones sync en un worker thread (anyio).

    policy_checked=True: el llamador ya aplicó su propia política de permisos
    (el agente: SAFE/SENSITIVE + diálogo con el analista). Sin esa marca, el
    permission gate decide: allow explícito pasa; deny o ask sin regla fallan
    cerrado con ToolPermissionDenied (la API lo traduce a 403).
    """
    tools = await get_registry_tools()
    tool = tools.get(name)
    if tool is None:
        raise KeyError(name)

    if not policy_checked:
        allowed, msg = _check_tool_permission(name, tool_resource(name, arguments))
        if not allowed:
            raise ToolPermissionDenied(msg)

    validated = tool.fn_metadata.validate_arguments(arguments)
    result = await tool.fn_metadata.call_fn(tool.fn, tool.is_async, validated)
    return result if isinstance(result, str) else str(result)


async def get_tool_schemas() -> list[dict[str, Any]]:
    """Schemas JSON de las tools para exponer al agente y a la UI."""
    tools = await get_registry_tools()
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.parameters,
        }
        for t in tools.values()
    ]

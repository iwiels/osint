"""
Acceso unificado al registro de tools del servidor MCP.

El MCP 2.2.0 expone list_tools() a nivel protocolo (sin fn ejecutable);
el registro interno _tool_manager contiene los objetos Tool completos
(fn, is_async, parameters). Esta capa aísla esa diferencia para que el
servidor HTTP y el agente usen un único contrato.
"""

from __future__ import annotations

from typing import Any

from specter.server import mcp_server


async def get_registry_tools() -> dict[str, Any]:
    """Devuelve {name: Tool} desde el registro interno del MCPServer."""
    return dict(mcp_server._tool_manager._tools)


async def call_tool_validated(name: str, arguments: dict[str, Any]) -> str:
    """Invoca una tool validando argumentos contra su schema pydantic.

    Usa la ruta oficial del MCP: fn_metadata.validate_arguments() + call_fn().
    call_fn ejecuta funciones sync en un worker thread (anyio).
    """
    tools = await get_registry_tools()
    tool = tools.get(name)
    if tool is None:
        raise KeyError(name)

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

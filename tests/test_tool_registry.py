"""
Tests del Tool Registry: registro, materialización por permisos y schemas.
"""

from __future__ import annotations

import pytest
from specter.osint_core.tool_registry import (
    ToolCategory,
    ToolDefinition,
    ToolPermission,
    ToolRegistry,
    tool_registry,
)


@pytest.fixture()
def registry() -> ToolRegistry:
    return ToolRegistry()


def test_register_y_get(registry: ToolRegistry):
    tool = ToolDefinition(
        name="test_tool",
        description="Herramienta de prueba",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        permission=ToolPermission.READ,
        category=ToolCategory.AGENT,
    )

    registry.register(tool)

    assert "test_tool" in registry
    assert len(registry) == 1
    assert registry.get("test_tool") == tool


def test_unregister(registry: ToolRegistry):
    tool = ToolDefinition(
        name="temp_tool",
        description="Temporal",
        permission=None,
    )
    registry.register(tool)

    assert registry.unregister("temp_tool") is True
    assert registry.unregister("temp_tool") is False
    assert "temp_tool" not in registry


def test_get_desconocido_lanza_keyerror(registry: ToolRegistry):
    with pytest.raises(KeyError):
        registry.get("no_existe")


def test_list_tools_ordena_por_nombre(registry: ToolRegistry):
    registry.register(ToolDefinition(name="zeta", description="z"))
    registry.register(ToolDefinition(name="alpha", description="a"))
    registry.register(ToolDefinition(name="beta", description="b"))

    names = [t.name for t in registry.list_tools()]
    assert names == ["alpha", "beta", "zeta"]


def test_materialize_sin_permisos_solo_publicas(registry: ToolRegistry):
    registry.register(ToolDefinition(name="publica", description="p", permission=None))
    registry.register(
        ToolDefinition(name="privada", description="x", permission=ToolPermission.READ)
    )

    tools = registry.materialize()

    assert [t.name for t in tools] == ["publica"]


def test_materialize_con_permisos(registry: ToolRegistry):
    registry.register(ToolDefinition(name="publica", description="p", permission=None))
    registry.register(
        ToolDefinition(name="lectura", description="r", permission=ToolPermission.READ)
    )
    registry.register(
        ToolDefinition(name="escritura", description="w", permission=ToolPermission.WRITE)
    )
    registry.register(
        ToolDefinition(name="admin", description="a", permission=ToolPermission.ADMIN)
    )

    tools = registry.materialize({ToolPermission.READ, ToolPermission.WRITE})

    names = {t.name for t in tools}
    assert names == {"publica", "lectura", "escritura"}


def test_materialize_con_todos_los_permisos(registry: ToolRegistry):
    registry.register(ToolDefinition(name="publica", description="p", permission=None))
    registry.register(
        ToolDefinition(name="lectura", description="r", permission=ToolPermission.READ)
    )
    registry.register(
        ToolDefinition(name="admin", description="a", permission=ToolPermission.ADMIN)
    )

    tools = registry.materialize(
        {ToolPermission.READ, ToolPermission.WRITE, ToolPermission.EXECUTE, ToolPermission.ADMIN}
    )

    assert len(tools) == 3


def test_get_schema(registry: ToolRegistry):
    tool = ToolDefinition(
        name="schema_tool",
        description="Con schema",
        input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        output_schema={"type": "object", "properties": {"result": {"type": "string"}}},
        permission=ToolPermission.EXECUTE,
        category=ToolCategory.NETWORK,
    )
    registry.register(tool)

    schema = registry.get_schema("schema_tool")

    assert schema["name"] == "schema_tool"
    assert schema["permission"] == "execute"
    assert schema["category"] == "network"
    assert "properties" in schema["input_schema"]
    assert "properties" in schema["output_schema"]


def test_get_schema_desconocido_lanza_keyerror(registry: ToolRegistry):
    with pytest.raises(KeyError):
        registry.get_schema("no_existe")


def test_builtin_tools_registradas():
    """El registry global tiene las built-ins del motor registradas."""
    assert len(tool_registry) > 0
    assert "create_case" in tool_registry
    assert "investigate_domain" in tool_registry
    assert "web_search" in tool_registry


def test_builtin_web_search_es_publica():
    """web_search no requiere permiso (pública)."""
    tool = tool_registry.get("web_search")
    assert tool.permission is None


def test_builtin_investigate_domain_requiere_permiso():
    """investigate_domain requiere permiso de ejecución."""
    tool = tool_registry.get("investigate_domain")
    assert tool.permission == ToolPermission.EXECUTE


def test_builtin_materializacion_publica():
    """Sin permisos solo se ven las tools públicas."""
    tools = tool_registry.materialize()
    names = {t.name for t in tools}

    assert "web_search" in names
    assert "web_fetch" in names
    assert "list_collectors" in names
    assert "create_case" not in names
    assert "investigate_domain" not in names


def test_builtin_materializacion_con_permisos():
    """Con todos los permisos se ven todas las tools."""
    tools = tool_registry.materialize(
        {ToolPermission.READ, ToolPermission.WRITE, ToolPermission.EXECUTE, ToolPermission.ADMIN}
    )
    names = {t.name for t in tools}

    assert "create_case" in names
    assert "investigate_domain" in names
    assert "web_search" in names


def test_categorias_builtin():
    """Las built-ins cubren las categorías principales del motor."""
    categories = {t.category for t in tool_registry.list_tools()}

    assert ToolCategory.NETWORK in categories
    assert ToolCategory.IDENTITY in categories
    assert ToolCategory.FORENSICS in categories
    assert ToolCategory.CORRELATION in categories
    assert ToolCategory.REPORTING in categories
    assert ToolCategory.BROWSER in categories
    assert ToolCategory.AGENT in categories

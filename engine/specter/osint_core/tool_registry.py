"""
WraithOSINT - Tool Registry
Registro dinámico de herramientas con materialización por permisos.

Inspirado en OpenCode (packages/core/src/tool/): un catálogo de tools que
el agente puede descubrir y usar, con control de acceso basado en permisos.
A diferencia de OpenCode (TypeScript), aquí las tools son definiciones
declarativas (Pydantic) que el motor materializa según los permisos del
solicitante.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ToolPermission(StrEnum):
    """Permisos de acceso a herramientas del motor."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"


class ToolCategory(StrEnum):
    """Categorías de herramientas del motor."""

    NETWORK = "network"
    IDENTITY = "identity"
    THREAT_INTEL = "threat_intel"
    FORENSICS = "forensics"
    CORRELATION = "correlation"
    REPORTING = "reporting"
    BROWSER = "browser"
    AGENT = "agent"


class ToolDefinition(BaseModel):
    """Definición declarativa de una herramienta del motor.

    Similar a OpenCode's Tool: nombre, descripción, schema de entrada/salida,
    permiso requerido y categoría. El agente usa `input_schema` para validar
    argumentos y `output_schema` para interpretar resultados.
    """

    name: str = Field(description="Nombre único de la herramienta")
    description: str = Field(description="Descripción de qué hace la herramienta")
    input_schema: dict[str, Any] = Field(
        default_factory=dict, description="Schema JSON de argumentos de entrada"
    )
    output_schema: dict[str, Any] = Field(
        default_factory=dict, description="Schema JSON de salida esperada"
    )
    permission: ToolPermission | None = Field(
        default=None, description="Permiso requerido (None = pública)"
    )
    category: ToolCategory = Field(default=ToolCategory.AGENT, description="Categoría funcional")


@dataclass
class ToolRegistry:
    """Registro dinámico de herramientas con materialización por permisos.

    Las tools se registran con `register()` y se filtran por permisos con
    `materialize()`. El agente solo ve las tools para las que tiene permiso.
    """

    _tools: dict[str, ToolDefinition] = field(default_factory=dict)

    def register(self, definition: ToolDefinition) -> ToolDefinition:
        """Registra una herramienta en el catálogo.

        Si ya existe una tool con el mismo nombre, se sobrescribe.
        """
        self._tools[definition.name] = definition
        return definition

    def unregister(self, name: str) -> bool:
        """Desregistra una herramienta. True si existía."""
        return self._tools.pop(name, None) is not None

    def get(self, name: str) -> ToolDefinition:
        """Obtiene una herramienta por nombre. KeyError si no existe."""
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(name)
        return tool

    def list_tools(self) -> list[ToolDefinition]:
        """Lista todas las herramientas registradas (sin filtrar por permisos)."""
        return sorted(self._tools.values(), key=lambda t: t.name)

    def materialize(self, permissions: set[ToolPermission] | None = None) -> list[ToolDefinition]:
        """Lista herramientas filtradas por permisos del solicitante.

        - `permissions=None`: solo herramientas públicas (permission=None)
        - `permissions=set(...)`: públicas + las que requieren un permiso
          que el solicitante posee
        """
        if permissions is None:
            permissions = set()
        return sorted(
            (
                tool
                for tool in self._tools.values()
                if tool.permission is None or tool.permission in permissions
            ),
            key=lambda t: t.name,
        )

    def get_schema(self, name: str) -> dict[str, Any]:
        """Obtiene el schema completo de una herramienta (input + output)."""
        tool = self.get(name)
        return {
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
            "permission": tool.permission.value if tool.permission else None,
            "category": tool.category.value,
        }

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)


# Registry global del motor (singleton por módulo)
tool_registry = ToolRegistry()


def register_builtin_tools() -> None:
    """Registra las herramientas built-in del motor en el registry global.

    Estas son las tools que el agente puede descubrir y usar. Las tools
    MCP registradas vía `@mcp_server.tool()` se registran automáticamente
    en el servidor MCP; este registry es la capa de descubrimiento y
    control de acceso para el agente.
    """
    builtins: list[ToolDefinition] = [
        ToolDefinition(
            name="create_case",
            description="Crea un caso formal de investigación OSINT",
            input_schema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Nombre del caso"},
                    "description": {"type": "string", "description": "Descripción"},
                    "investigator": {"type": "string", "description": "Investigador"},
                },
                "required": ["name", "description"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "case_id": {"type": "string"},
                    "genesis_hash": {"type": "string"},
                },
            },
            permission=ToolPermission.WRITE,
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="investigate_domain",
            description="Investiga un dominio: DNS, TLS, reputación y historial",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "domain": {"type": "string"},
                },
                "required": ["case_id", "domain"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "domain": {"type": "string"},
                    "dns_entities_found": {"type": "integer"},
                    "tls_entities_found": {"type": "integer"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.NETWORK,
        ),
        ToolDefinition(
            name="investigate_ip",
            description="Investiga una IP: PTR, RDAP, exposición y reputación",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "ip": {"type": "string"},
                },
                "required": ["case_id", "ip"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "ip": {"type": "string"},
                    "entities_identified": {"type": "array", "items": {"type": "string"}},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.NETWORK,
        ),
        ToolDefinition(
            name="investigate_identity",
            description="Investiga un username en 700+ plataformas",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "username": {"type": "string"},
                },
                "required": ["case_id", "username"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "username": {"type": "string"},
                    "profiles_found": {"type": "integer"},
                    "profiles": {"type": "array", "items": {"type": "string"}},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.IDENTITY,
        ),
        ToolDefinition(
            name="investigate_person",
            description="Huella digital de un nombre completo",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "full_name": {"type": "string"},
                    "pivot_usernames": {"type": "boolean"},
                    "execute_search": {"type": "boolean"},
                    "context": {"type": "string"},
                },
                "required": ["case_id", "full_name"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "full_name": {"type": "string"},
                    "derived_usernames": {"type": "array", "items": {"type": "string"}},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.IDENTITY,
        ),
        ToolDefinition(
            name="investigate_email",
            description="Analiza un email: sintaxis, MX, filtraciones",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "email": {"type": "string"},
                },
                "required": ["case_id", "email"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "email": {"type": "string"},
                    "entities_created": {"type": "integer"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.IDENTITY,
        ),
        ToolDefinition(
            name="analyze_file_metadata",
            description="Extrae hashes y metadatos forenses de un archivo",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "target": {"type": "string"},
                },
                "required": ["case_id", "target"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "target": {"type": "string"},
                    "sha256": {"type": "string"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.FORENSICS,
        ),
        ToolDefinition(
            name="hunt_documents_and_leaks",
            description="Caza documentos y filtraciones asociadas al objetivo",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "target": {"type": "string"},
                    "context": {"type": "string"},
                },
                "required": ["case_id", "target"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "target": {"type": "string"},
                    "pdfs_analyzed": {"type": "integer"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.FORENSICS,
        ),
        ToolDefinition(
            name="deep_investigate_github",
            description="Minería forense de repositorios GitHub",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "username": {"type": "string"},
                },
                "required": ["case_id", "username"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "username": {"type": "string"},
                    "entities_created": {"type": "integer"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.FORENSICS,
        ),
        ToolDefinition(
            name="query_graph",
            description="Consulta el grafo del caso: subgrafos y vecinos",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "search_term": {"type": "string"},
                    "entity_type": {"type": "string"},
                    "center_id": {"type": "string"},
                    "max_depth": {"type": "integer"},
                },
                "required": ["case_id"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "nodes": {"type": "array"},
                    "edges": {"type": "array"},
                },
            },
            permission=ToolPermission.READ,
            category=ToolCategory.CORRELATION,
        ),
        ToolDefinition(
            name="link_entities",
            description="Vincula manualmente dos entidades del grafo",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "source_id": {"type": "string"},
                    "target_id": {"type": "string"},
                    "relation_type": {"type": "string"},
                    "confidence": {"type": "number"},
                    "rationale": {"type": "string"},
                },
                "required": ["case_id", "source_id", "target_id", "relation_type"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "edge_id": {"type": "string"},
                },
            },
            permission=ToolPermission.WRITE,
            category=ToolCategory.CORRELATION,
        ),
        ToolDefinition(
            name="correlate_cases",
            description="Correlaciona artefactos entre casos",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "entity_types": {"type": "array", "items": {"type": "string"}},
                },
            },
            output_schema={
                "type": "object",
                "properties": {
                    "matches": {"type": "array"},
                },
            },
            permission=ToolPermission.READ,
            category=ToolCategory.CORRELATION,
        ),
        ToolDefinition(
            name="case_timeline",
            description="Línea temporal del caso",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "bucket": {"type": "string", "enum": ["day", "hour"]},
                },
                "required": ["case_id"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "total_events": {"type": "integer"},
                    "buckets": {"type": "array"},
                },
            },
            permission=ToolPermission.READ,
            category=ToolCategory.REPORTING,
        ),
        ToolDefinition(
            name="export_case_dossier",
            description="Genera un informe forense formal (HTML/MD)",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "format": {"type": "string", "enum": ["html", "executive", "md"]},
                },
                "required": ["case_id"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "file_path": {"type": "string"},
                },
            },
            permission=ToolPermission.READ,
            category=ToolCategory.REPORTING,
        ),
        ToolDefinition(
            name="web_search",
            description="Búsqueda web pasiva (DuckDuckGo)",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "top_k": {"type": "integer"},
                },
                "required": ["query"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "results": {"type": "array"},
                },
            },
            permission=None,  # pública: no requiere permiso
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="web_fetch",
            description="Descarga y extrae texto de una URL",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "max_chars": {"type": "integer"},
                    "timeout": {"type": "integer"},
                },
                "required": ["url"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "text": {"type": "string"},
                },
            },
            permission=None,  # pública
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="browser_snapshot",
            description="Navega con Chromium sigiloso y extrae contenido",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "case_id": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["url"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "text": {"type": "string"},
                    "links": {"type": "array"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.BROWSER,
        ),
        ToolDefinition(
            name="browser_screenshot",
            description="Captura PNG de una página (evidencia visual)",
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "case_id": {"type": "string"},
                    "full_page": {"type": "boolean"},
                    "timeout": {"type": "integer"},
                },
                "required": ["url"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "screenshot_base64": {"type": "string"},
                    "hash": {"type": "string"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.BROWSER,
        ),
        ToolDefinition(
            name="run_collector",
            description="Ejecuta cualquier colector del catálogo",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "collector": {"type": "string"},
                    "target": {"type": "string"},
                    "options": {"type": "object"},
                },
                "required": ["case_id", "collector", "target"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "entities_found": {"type": "integer"},
                    "relations_found": {"type": "integer"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="list_collectors",
            description="Lista el catálogo de colectores disponibles",
            input_schema={"type": "object", "properties": {}},
            output_schema={
                "type": "object",
                "properties": {
                    "total": {"type": "integer"},
                    "collectors": {"type": "array"},
                },
            },
            permission=None,  # pública
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="triage_entity",
            description="Clasifica un artefacto y recomienda una tool",
            input_schema={
                "type": "object",
                "properties": {
                    "artifact": {"type": "string"},
                },
                "required": ["artifact"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "entity_type": {"type": "string"},
                    "recommended_tool": {"type": "string"},
                    "arguments": {"type": "object"},
                },
            },
            permission=None,  # pública
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="deep_research",
            description="Investiga un objetivo en varios índices y páginas",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "target": {"type": "string"},
                    "target_type": {"type": "string"},
                    "max_queries": {"type": "integer"},
                    "max_pages": {"type": "integer"},
                    "max_depth": {"type": "integer"},
                    "context": {"type": "string"},
                },
                "required": ["case_id", "target"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "entities_ingested": {"type": "integer"},
                },
            },
            permission=ToolPermission.EXECUTE,
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="parallel_search",
            description="Barrido concurrente de varias consultas web",
            input_schema={
                "type": "object",
                "properties": {
                    "queries": {"type": "array", "items": {"type": "string"}},
                    "top_k": {"type": "integer"},
                },
                "required": ["queries"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "results": {"type": "object"},
                },
            },
            permission=None,  # pública
            category=ToolCategory.AGENT,
        ),
        ToolDefinition(
            name="verify_case_integrity",
            description="Audita la cadena de custodia criptográfica",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                },
                "required": ["case_id"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "valid": {"type": "boolean"},
                    "blocks_verified": {"type": "integer"},
                },
            },
            permission=ToolPermission.READ,
            category=ToolCategory.FORENSICS,
        ),
        ToolDefinition(
            name="attest_case_ledger",
            description="Emite una atestación HMAC-SHA256 del ledger",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                },
                "required": ["case_id"],
            },
            output_schema={
                "type": "object",
                "properties": {
                    "signature": {"type": "string"},
                    "block_hash": {"type": "string"},
                },
            },
            permission=ToolPermission.READ,
            category=ToolCategory.FORENSICS,
        ),
    ]

    for tool_def in builtins:
        tool_registry.register(tool_def)


# Registrar built-ins al importar el módulo
register_builtin_tools()


def generate_evidence_id() -> str:
    """Genera un identificador único para evidencia compactada."""
    return f"compact-{uuid.uuid4().hex[:12]}"

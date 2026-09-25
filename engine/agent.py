"""
Specter Engine - Agent Module
Loop de agente multi-provider (estilo opencode): el LLM orquesta las tools
forenses del registry MCP como function-calling, con sistema de permisos
para herramientas sensibles (Permission.ask pattern).

Providers soportados:
  - anthropic  (Anthropic Messages API)
  - openai     (OpenAI Chat Completions / cualquier endpoint compatible)
  - ollama     (local, vía endpoint OpenAI-compatible)

El motor es provider-agnóstico: solo HTTP + JSON, sin SDKs pesados.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from engine.registry import call_tool_validated, get_tool_schemas

EmitFn = Callable[[str, dict[str, Any]], Awaitable[None]]

# ------------------------------------------------------------------
# Permisos (Permission.ask de opencode): tools sensibles requieren
# aprobación del usuario antes de ejecutarse. La petición viaja por el
# event bus (SSE) y la respuesta entra por POST /agent/permissions/respond.
# ------------------------------------------------------------------

# Tools que el agente puede ejecutar sin preguntar (lecturas pasivas).
SAFE_TOOLS = {
    "list_cases",
    "query_graph",
    "analyze_network_metrics",
    "verify_case_integrity",
}

# Tools que disparan recolección activa / escritura en el caso.
SENSITIVE_TOOLS = {
    "create_case",
    "investigate_domain",
    "enumerate_subdomains",
    "investigate_ip",
    "investigate_identity",
    "investigate_email",
    "hunt_documents_and_leaks",
    "deep_investigate_github",
    "analyze_file_metadata",
    "link_entities",
    "export_case_dossier",
}


@dataclass
class PermissionRequest:
    request_id: str
    tool_name: str
    arguments: dict[str, Any]
    session_id: str
    status: str = "pending"  # pending | allowed | denied
    decision: str | None = None
    future: Any = field(default=None, repr=False)


_pending_permissions: dict[str, PermissionRequest] = {}
_session_approvals: set[tuple[str, str]] = set()  # (session_id, tool_name)


def respond_permission(request_id: str, decision: str) -> bool:
    """Resuelve una petición de permiso pendiente (llamado desde el endpoint HTTP)."""
    req = _pending_permissions.get(request_id)
    if not req or req.status != "pending":
        return False
    req.decision = decision
    req.status = "allowed" if decision in ("allow", "allow_session") else "denied"
    if decision == "allow_session":
        _session_approvals.add((req.session_id, req.tool_name))
    if req.future is not None:
        req.future.set_result(req.status)
    return True


# ------------------------------------------------------------------
# System prompt (inspirado en el diseño de prompts por-provider de opencode)
# ------------------------------------------------------------------

SYSTEM_PROMPT = """Eres Specter, un agente de inteligencia OSINT y análisis forense digital.

Operas dentro de SpecterOSINT, una plataforma forense con cadena de custodia
criptográfica: cada recolección queda registrada en un ledger inmutable (SHA-256)
y las entidades descubiertas se insertan en un grafo de conocimiento por caso.

## Reglas operativas
1. SIEMPRE trabajas dentro de un caso. Si el usuario no indica uno, lista los casos
   disponibles con list_cases y pide confirmación, o crea uno con create_case si
   la petición lo implica claramente.
2. Usa las herramientas forenses para responder. No inventes datos: todo hallazgo
   debe provenir de una ejecución de tool real.
3. Prefiere recolección pasiva. Ejecuta herramientas de enumeración solo cuando
   aporten valor a la investigación en curso.
4. Correlaciona: tras recolectar, usa query_graph y analyze_network_metrics para
   conectar hallazgos nuevos con entidades existentes del caso.
5. Al cerrar una fase de investigación, ofrece export_case_dossier para generar
   el informe forense formal.

## Estilo
- Respuestas concisas y técnicas, en el idioma del usuario.
- Estructura los hallazgos con listas cortas; destaca hashes de evidencia.
- Señala explícitamente la confianza de las correlaciones cuando aplique.
"""


# ------------------------------------------------------------------
# Providers (abstracción mínima estilo provider-agnostic de opencode)
# ------------------------------------------------------------------


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    api_key: str | None
    default_model: str


PROVIDERS: dict[str, ProviderConfig] = {
    "anthropic": ProviderConfig(
        name="anthropic",
        base_url="https://api.anthropic.com/v1",
        api_key=None,
        default_model="claude-sonnet-4-5",
    ),
    "openai": ProviderConfig(
        name="openai",
        base_url="https://api.openai.com/v1",
        api_key=None,
        default_model="gpt-4.1",
    ),
    "ollama": ProviderConfig(
        name="ollama",
        base_url="http://127.0.0.1:11434/v1",
        api_key="ollama",
        default_model="llama3.1",
    ),
}


def _resolve_provider(
    provider: str, model: str | None, api_key: str | None, base_url: str | None
) -> tuple[ProviderConfig, str]:
    cfg = PROVIDERS.get(provider.lower())
    if cfg is None:
        raise RuntimeError(f"Provider desconocido: {provider}. Disponibles: {list(PROVIDERS)}")
    key = api_key or cfg.api_key
    if provider == "anthropic":
        key = key or os.environ.get("ANTHROPIC_API_KEY")
    elif provider == "openai":
        key = key or os.environ.get("OPENAI_API_KEY")
    if cfg.name in ("anthropic", "openai") and not key:
        raise RuntimeError(
            f"Falta API key para '{provider}'. "
            "Pásala en la petición o define la variable de entorno."
        )
    if base_url:
        cfg = ProviderConfig(cfg.name, base_url.rstrip("/"), key, cfg.default_model)
    else:
        cfg = ProviderConfig(cfg.name, cfg.base_url, key, cfg.default_model)
    return cfg, model or cfg.default_model


# ------------------------------------------------------------------
# Tools -> formato function-calling por provider
# ------------------------------------------------------------------


async def _registry_tools() -> list[dict[str, Any]]:
    return await get_tool_schemas()


async def _execute_tool(name: str, arguments: dict[str, Any], session_id: str, emit: EmitFn) -> str:
    """Ejecuta una tool del registry aplicando el gate de permisos."""
    from engine.registry import get_registry_tools

    tools = await get_registry_tools()
    if name not in tools:
        return json.dumps({"error": f"Tool '{name}' no existe"})

    if name in SENSITIVE_TOOLS and (session_id, name) not in _session_approvals:
        # Permission.ask: publicar petición por SSE y esperar decisión del usuario.
        import asyncio
        import uuid

        req = PermissionRequest(
            request_id=f"perm-{uuid.uuid4().hex[:10]}",
            tool_name=name,
            arguments=arguments,
            session_id=session_id,
        )
        loop = asyncio.get_running_loop()
        req.future = loop.create_future()
        _pending_permissions[req.request_id] = req

        await emit(
            "permission.request",
            {
                "request_id": req.request_id,
                "tool": name,
                "arguments": arguments,
                "session_id": session_id,
            },
        )
        status = await asyncio.wait_for(req.future, timeout=300)
        _pending_permissions.pop(req.request_id, None)
        if status != "allowed":
            return json.dumps({"error": "Permiso denegado por el analista", "tool": name})
        await emit("permission.granted", {"request_id": req.request_id, "tool": name})

    # Invocación validada vía el registry unificado.
    return await call_tool_validated(name, arguments)


# ------------------------------------------------------------------
# Bucle principal del agente
# ------------------------------------------------------------------


async def run_agent(
    message: str,
    case_id: str | None,
    provider: str,
    model: str | None,
    api_key: str | None,
    base_url: str | None,
    max_iterations: int,
    emit: EmitFn,
) -> dict[str, Any]:
    cfg, model_id = _resolve_provider(provider, model, api_key, base_url)
    tools_schema = await _registry_tools()

    session_id = case_id or "global"
    context_note = (
        f"Caso activo: {case_id}. Todas las tools que requieren case_id deben recibir ese valor."
        if case_id
        else "No hay caso activo aún; crea o selecciona uno si la tarea lo requiere."
    )
    system = f"{SYSTEM_PROMPT}\n\n## Contexto\n{context_note}"

    messages: list[dict[str, Any]] = [{"role": "user", "content": message}]
    tool_results: list[dict[str, Any]] = []
    iterations = 0

    await emit("agent.started", {"provider": cfg.name, "model": model_id, "case_id": case_id})

    async with httpx.AsyncClient(timeout=120.0) as client:
        while iterations < max_iterations:
            iterations += 1

            if cfg.name == "anthropic":
                assistant_msg, tool_calls = await _step_anthropic(
                    client, cfg, model_id, system, messages, tools_schema
                )
            else:  # openai-compatible (openai, ollama, lmstudio, vllm...)
                assistant_msg, tool_calls = await _step_openai_compatible(
                    client, cfg, model_id, system, messages, tools_schema
                )

            messages.append(assistant_msg)
            await emit(
                "agent.message", {"role": "assistant", "content": assistant_msg.get("content")}
            )

            if not tool_calls:
                break  # respuesta final del modelo

            for call in tool_calls:
                await emit(
                    "tool.started",
                    {"call_id": call["id"], "tool": call["name"], "arguments": call["arguments"]},
                )
                try:
                    result = await _execute_tool(call["name"], call["arguments"], session_id, emit)
                except Exception as exc:
                    result = json.dumps({"error": str(exc), "tool": call["name"]})
                await emit(
                    "tool.completed",
                    {"call_id": call["id"], "tool": call["name"], "result": result[:2000]},
                )
                tool_results.append({"call_id": call["id"], "tool": call["name"], "result": result})

                # Devolver el resultado al modelo en su formato.
                if cfg.name == "anthropic":
                    messages.append(
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": call["id"],
                                    "content": result[:8000],
                                }
                            ],
                        }
                    )
                else:
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": result[:8000],
                        }
                    )

    await emit("agent.completed", {"iterations": iterations, "tools_used": len(tool_results)})

    final_text = next(
        (
            m.get("content")
            for m in reversed(messages)
            if m["role"] == "assistant" and m.get("content")
        ),
        "",
    )
    return {
        "status": "COMPLETED",
        "provider": cfg.name,
        "model": model_id,
        "iterations": iterations,
        "tools_used": tool_results,
        "final_message": final_text,
    }


# ------------------------------------------------------------------
# Steps por provider
# ------------------------------------------------------------------


async def _step_anthropic(
    client: httpx.AsyncClient,
    cfg: ProviderConfig,
    model: str,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    resp = await client.post(
        f"{cfg.base_url}/messages",
        headers={
            "x-api-key": cfg.api_key or "",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 4096,
            "system": system,
            "messages": messages,
            "tools": tools,
        },
    )
    resp.raise_for_status()
    data = resp.json()

    text_parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    tool_calls = [
        {
            "id": b["id"],
            "name": b["name"],
            "arguments": b.get("input", {}),
        }
        for b in data.get("content", [])
        if b.get("type") == "tool_use"
    ]
    content = "\n".join(text_parts) if text_parts else None
    msg = (
        {"role": "assistant", "content": content}
        if not tool_calls
        else {
            "role": "assistant",
            "content": data.get("content", []),
        }
    )
    return msg, tool_calls


async def _step_openai_compatible(
    client: httpx.AsyncClient,
    cfg: ProviderConfig,
    model: str,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    oai_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]
    payload_messages = [{"role": "system", "content": system}, *messages]
    resp = await client.post(
        f"{cfg.base_url}/chat/completions",
        headers={"Authorization": f"Bearer {cfg.api_key or 'none'}"},
        json={
            "model": model,
            "messages": payload_messages,
            "tools": oai_tools,
        },
    )
    resp.raise_for_status()
    data = resp.json()
    choice = data["choices"][0]
    msg = choice["message"]

    tool_calls = []
    for call in msg.get("tool_calls") or []:
        fn = call["function"]
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {}
        tool_calls.append({"id": call["id"], "name": fn["name"], "arguments": args})

    return {
        "role": "assistant",
        "content": msg.get("content"),
        "tool_calls": msg.get("tool_calls"),
    }, tool_calls

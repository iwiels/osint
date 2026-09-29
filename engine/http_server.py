"""
Specter Engine - HTTP Server
Motor forense OSINT expuesto como servicio HTTP local (REST + SSE) con mount
transparente de las herramientas MCP existentes.

Arquitectura inspirada en opencode (sst/opencode): motor headless <-> clientes.
Cualquier cliente (Electron, CLI, web) habla con este motor por HTTP tipado.

Arranque:
    python -m engine.http_server            # REST+SSE en 127.0.0.1:8787
    python -m engine.http_server --port 9000
    (El servidor MCP stdio original sigue disponible: python -m specter.server)
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import suppress
from pathlib import Path
from typing import Any

# Silenciar logging excesivo de solicitudes HTTP individuales de httpx (ej. barridos WhatsMyName)
logging.getLogger("httpx").setLevel(logging.WARNING)

# --- Resolución de rutas base (dev y ejecutable empaquetado) ---
if getattr(sys, "frozen", False):  # PyInstaller
    BASE_DIR = Path(sys.executable).resolve().parent
    # En onefile, los datos embebidos viven en sys._MEIPASS
    _BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", BASE_DIR))
    if str(_BUNDLE_DIR) not in sys.path:
        sys.path.insert(0, str(_BUNDLE_DIR))
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# El kernel 'specter' vive dentro de engine/; al ejecutar como
# 'python -m engine.http_server' desde la raíz del repo, engine/ debe
# estar en sys.path para que 'import specter' resuelva.
_ENGINE_SRC = BASE_DIR / "engine"
if _ENGINE_SRC.is_dir() and str(_ENGINE_SRC) not in sys.path:
    sys.path.insert(0, str(_ENGINE_SRC))

DATA_DIR = Path(os.environ.get("SPECTER_DATA_DIR", BASE_DIR / "data"))
REPORTS_DIR = Path(os.environ.get("SPECTER_REPORTS_DIR", BASE_DIR / "reports"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from specter.osint_core.database import Database
from specter.osint_core.models import (
    AgentRunResult,
    CaseCreatedOut,
    CollectorResult,
    GraphSubgraph,
    HealthOut,
    SessionDetailOut,
    SessionsOut,
    TimelineReport,
    current_utc_iso,
)
from specter.osint_core.permission_gate import _check_tool_permission

from engine import ENGINE_VERSION
from engine.registry import (
    ToolPermissionDenied,
    call_tool_validated,
    get_registry_tools,
    get_tool_schemas,
)

# ------------------------------------------------------------------
# Estado central del motor (instancia única, como opencode hace con
# sus servicios de sesión: un solo proceso dueño de la verdad).
# ------------------------------------------------------------------

db = Database(DATA_DIR / "specter_osint.db")

app = FastAPI(
    title="Specter Engine",
    description="Motor forense OSINT headless (REST + SSE + MCP)",
    version=ENGINE_VERSION,
)

# CORS cerrado a orígenes locales: el renderer vive en localhost (dev) o file://
# (prod, sin header Origin). Un sitio público no debe poder ni prefligir contra
# el motor; la autenticación real sigue siendo el Bearer token (C1).
_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    # Sin allow_private_network: una web pública no debe pivotar al engine
    # aunque el token la frene; el renderer Electron desactiva PNA en su lado.
)


def _engine_token() -> str:
    """Token Bearer del motor (leído por request: los tests lo rotan por env)."""
    return os.environ.get("SPECTER_ENGINE_TOKEN", "")


# Rutas públicas: solo salud y esquema (sin datos). Todo lo demás exige token.
_PUBLIC_PATHS = {"/health", "/openapi.json", "/docs", "/redoc"}


@app.middleware("http")
async def _require_engine_token(request: Request, call_next):  # type: ignore[no-untyped-def]
    """C1: el engine solo obedece a quien presente el token del sidecar.

    Sin `SPECTER_ENGINE_TOKEN` configurado las rutas de datos fallan cerradas;
    el sidecar genera uno aleatorio y la API standalone requiere configurarlo.
    El stream SSE (EventSource no manda headers) puede traerlo como `?token=`.

    Los preflight CORS (OPTIONS) nunca traen Authorization: se dejan pasar
    para que CORSMiddleware responda; el GET/POST real sí exige el token.
    """
    if request.method != "OPTIONS" and request.url.path not in _PUBLIC_PATHS:
        token = _engine_token()
        if not token:
            return JSONResponse(
                {"detail": "Engine sin configurar: define SPECTER_ENGINE_TOKEN y reinicia."},
                status_code=503,
                headers={
                    "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
                    "Access-Control-Allow-Headers": "authorization, content-type",
                },
            )
        auth = request.headers.get("authorization", "")
        query_token = request.query_params.get("token", "")
        expected = f"Bearer {token}"
        sse_by_query = request.url.path == "/events" and query_token == token
        if auth != expected and not sse_by_query:
            # Este 401 sale sin pasar por CORSMiddleware (este middleware es
            # externo): se le ponen los headers CORS para que el renderer vea
            # el 401 en vez de un opaco "Failed to fetch".
            return JSONResponse(
                {"detail": "Falta o es inválido el token del engine (Bearer)."},
                status_code=401,
                headers={
                    "Access-Control-Allow-Origin": request.headers.get("origin", "*"),
                    "Access-Control-Allow-Headers": "authorization, content-type",
                },
            )
    return await call_next(request)


# ------------------------------------------------------------------
# Event bus en memoria: cualquier componente publica eventos tipados y
# los clientes los consumen por SSE (equivalente al bus de opencode).
# ------------------------------------------------------------------


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._seq = 0

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        self._seq += 1
        event = {"seq": self._seq, "type": event_type, "payload": payload, "ts": current_utc_iso()}
        for q in list(self._subscribers):
            with suppress(asyncio.QueueFull):
                q.put_nowait(event)


bus = EventBus()


def _git_hash() -> str | None:
    """Hash vivo del checkout (solo dev): HEAD corto + sufijo -dirty."""
    import subprocess

    if not (BASE_DIR / ".git").is_dir():
        return None
    try:
        head = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=BASE_DIR,
        )
        if head.returncode != 0 or not head.stdout.strip():
            return None
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=BASE_DIR,
        )
        suffix = "-dirty" if dirty.stdout.strip() else ""
        return f"{head.stdout.strip()}{suffix}"
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _baked_hash() -> str | None:
    """Hash sellado en el build (solo existe en el ejecutable empaquetado)."""
    try:
        from engine import _build_info  # generado por scripts/build-engine.py

        return _build_info.BUILD_HASH or None
    except (ImportError, AttributeError):
        return None


_BUILD_HASH: str | None = None


def _build_hash() -> str:
    """Hash del código que sirve este proceso (calculado una vez).

    En checkout dev manda el git vivo (el fichero sellado puede ser resto
    de un build local); en el ejecutable manda el sellado; si no hay
    ninguno, "unknown". La UI lo muestra para detectar staleness.
    """
    global _BUILD_HASH
    if _BUILD_HASH is None:
        _BUILD_HASH = _git_hash() or _baked_hash() or "unknown"
    return _BUILD_HASH


STARTED_AT = current_utc_iso()


# ------------------------------------------------------------------
# Modelos de API
# ------------------------------------------------------------------


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    investigator: str = "Analista_Specter"


class AgentRunRequest(BaseModel):
    case_id: str | None = None
    session_id: str | None = None
    message: str = Field(min_length=1, max_length=20000)
    provider: str = "opencode"
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    max_iterations: int = Field(default=25, ge=1, le=100)
    stream: bool = True
    plan_first: bool = True
    # C4: el gate de permisos es opt-out, no opt-in. La UI lo activa
    # explícitamente para demos; los tests E2E responden el diálogo.
    auto_approve: bool = False


class AgentPermission(BaseModel):
    request_id: str
    decision: str  # "allow" | "allow_session" | "deny"


class RunsCancelRequest(BaseModel):
    session_id: str | None = None
    # Ancla exacta del Stop (la UI la saca de `agent.started`); si va, manda
    # sobre session_id.
    run_id: str | None = None


class AgentQuestionReply(BaseModel):
    request_id: str
    answers: list[list[str]] = Field(default_factory=list)


class SecretUpsert(BaseModel):
    value: str = Field(min_length=1, max_length=500)


# ------------------------------------------------------------------
# Salud e introspección
# ------------------------------------------------------------------


@app.get("/health", response_model=HealthOut)
async def health() -> dict[str, Any]:
    """Salud del engine (pública: el sidecar la sondea antes del token).

    No expone rutas del filesystem al navegador: son información de host local
    que una web abierta en el mismo equipo no debería poder leer sin token.
    """
    return {
        "status": "ok",
        "engine": "specter",
        "version": ENGINE_VERSION,
        "mcp_tools": len(await get_registry_tools()),
        "data_dir": "",  # rutas del host solo vía endpoints autenticados
        "reports_dir": "",  # idem
        "build_hash": _build_hash(),
        "started_at": STARTED_AT,
    }


# ------------------------------------------------------------------
# Tools: contrato MCP (superficie pública que consumen SDK y UI)
# ------------------------------------------------------------------


@app.get("/tools")
async def list_tools() -> dict[str, Any]:
    """Registry unificado: tools MCP expuestas con su schema JSON.

    Este es el contrato estable: lo consumen `WraithClient.listTools()` del
    SDK y la vista de ajustes. El Tool Registry (permisos/categorías) vive
    bajo `/tool-registry/` para no mezclarse con este.
    """
    return {
        "tools": [
            {
                "name": t["name"],
                "description": t["description"].strip().splitlines()[0],
                "schema": t["input_schema"],
            }
            for t in await get_tool_schemas()
        ]
    }


# ------------------------------------------------------------------
# Tool Registry: descubrimiento y materialización por permisos
# (endpoints propios, bajo /tool-registry para no chocar con /tools)
# ------------------------------------------------------------------


@app.get("/tool-registry/tools")
async def list_tool_registry() -> dict[str, Any]:
    """Lista todas las tools registradas en el Tool Registry."""
    from specter.osint_core.tool_registry import tool_registry

    tools = tool_registry.list_tools()
    return {
        "total": len(tools),
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "permission": t.permission.value if t.permission else None,
                "category": t.category.value,
            }
            for t in tools
        ],
    }


@app.get("/tool-registry/tools/{tool_name}")
async def get_tool(tool_name: str) -> dict[str, Any]:
    """Obtiene una tool específica del Tool Registry."""
    from specter.osint_core.tool_registry import tool_registry

    try:
        return tool_registry.get_schema(tool_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' no existe") from exc


class MaterializeRequest(BaseModel):
    permissions: list[str] = Field(default_factory=list)


@app.post("/tool-registry/materialize")
async def materialize_tools(body: MaterializeRequest) -> dict[str, Any]:
    """Materializa tools filtradas por permisos del solicitante."""
    from specter.osint_core.tool_registry import ToolPermission, tool_registry

    try:
        perms = {ToolPermission(p) for p in body.permissions}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Permiso inválido: {exc}") from exc

    tools = tool_registry.materialize(perms)
    return {
        "total": len(tools),
        "permissions": [p.value for p in perms],
        "tools": [
            {
                "name": t.name,
                "description": t.description,
                "permission": t.permission.value if t.permission else None,
                "category": t.category.value,
            }
            for t in tools
        ],
    }


# ------------------------------------------------------------------
# Compaction: compactación de resultados de colectores
# ------------------------------------------------------------------


@app.post("/compact")
async def compact_result(body: CollectorResult) -> dict[str, Any]:
    """Compacta un resultado de colector para reducir el tamaño del contexto.

    Preserva hallazgos clave, guarda evidencia completa en disco y crea
    referencias URI para recuperar la información original.
    """
    from specter.osint_core.compaction import compaction_service

    if not compaction_service.should_compact(body):
        return {
            "compacted": False,
            "reason": "Resultado por debajo del umbral de compactación",
            "entities": len(body.entities),
            "relations": len(body.relations),
        }

    compacted = compaction_service.compact_collector_result(body)
    return {
        "compacted": True,
        "collector_name": compacted.collector_name,
        "source_target": compacted.source_target,
        "entities_count": len(compacted.entities),
        "relations_count": len(compacted.relations),
        "raw_payload_ref": compacted.raw_payload_ref,
        "summary": compacted.summary,
        "original_size_bytes": compacted.original_size_bytes,
        "compacted_size_bytes": compacted.compacted_size_bytes,
        "compression_ratio": round(
            compacted.compacted_size_bytes / max(compacted.original_size_bytes, 1), 2
        ),
    }


# ------------------------------------------------------------------
# Casos
# ------------------------------------------------------------------


@app.post("/cases", response_model=CaseCreatedOut)
async def create_case_endpoint(body: CaseCreate) -> dict[str, Any]:
    try:
        raw = await call_tool_validated(
            "create_case",
            {"name": body.name, "description": body.description, "investigator": body.investigator},
        )
    except ToolPermissionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    result = json.loads(raw)
    if result.get("status") != "CASE_CREATED":
        raise HTTPException(status_code=500, detail=result)
    bus.publish("case.created", {"case_id": result["case_id"], "name": body.name})
    return result


@app.get("/cases")
async def list_cases_endpoint() -> list[dict[str, Any]]:
    return [c.model_dump() for c in db.list_cases()]


@app.get("/cases/{case_id}")
async def get_case_endpoint(case_id: str) -> dict[str, Any]:
    case = db.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    return case.model_dump()


@app.delete("/cases/{case_id}")
async def delete_case_endpoint(case_id: str) -> dict[str, Any]:
    """Borra un caso con sus entidades, ledger y sesiones (limpieza del legajo).

    El permission gate lo deniega por defecto (regla `delete/case:*`): hace
    falta un allow explícito vía `add_permission_rule`.
    """
    allowed, msg = _check_tool_permission("delete_case", f"case:{case_id}")
    if not allowed:
        raise HTTPException(status_code=403, detail=msg)
    if not db.delete_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    return {"status": "ok", "case_id": case_id}


# ------------------------------------------------------------------
# Ejecución de tools MCP (contracto único para UI y agente)
# ------------------------------------------------------------------


class ToolCallRequest(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)


@app.post("/tools/{tool_name}/call")
async def call_tool_endpoint(tool_name: str, body: ToolCallRequest) -> dict[str, Any]:
    tools = await get_registry_tools()
    if tool_name not in tools:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' no existe")
    try:
        raw = await call_tool_validated(tool_name, body.arguments)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' no existe") from exc
    except ToolPermissionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:  # superficie de error controlada
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    bus.publish("tool.called", {"tool": tool_name, "arguments": body.arguments})
    try:
        return {"tool": tool_name, "result": json.loads(raw)}
    except (TypeError, json.JSONDecodeError):
        return {"tool": tool_name, "result": raw}


# ------------------------------------------------------------------
# Consultas de grafo / ledger (lecturas directas para la UI)
# ------------------------------------------------------------------


@app.get("/cases/{case_id}/graph", response_model=GraphSubgraph)
async def case_graph(
    case_id: str,
    max_depth: int = 2,
    center_id: str | None = None,
    search_term: str | None = None,
    entity_type: str | None = None,
) -> dict[str, Any]:
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.graph import OSINTGraph
    from specter.osint_core.models import sanitize_edge_dict, sanitize_node_dict

    graph = OSINTGraph(db)
    subgraph = graph.query_subgraph(
        case_id=case_id,
        entity_type=entity_type,
        search_term=search_term,
        center_id=center_id,
        max_depth=max_depth,
    )
    subgraph["nodes"] = [sanitize_node_dict(n) for n in subgraph.get("nodes", [])]
    subgraph["edges"] = [sanitize_edge_dict(e) for e in subgraph.get("edges", [])]
    subgraph["total_nodes"] = len(subgraph["nodes"])
    subgraph["total_edges"] = len(subgraph["edges"])
    return subgraph


@app.get("/cases/{case_id}/ledger")
async def case_ledger(case_id: str) -> dict[str, Any]:
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.ledger import ForensicLedger

    blocks = db.get_case_ledger(case_id)
    audit = ForensicLedger(db).verify_case_integrity(case_id)
    return {
        "case_id": case_id,
        "blocks": [b.model_dump() for b in blocks],
        "signature_status": audit.get("signature_status"),
        "key_id": audit.get("key_id"),
        "valid": audit.get("valid"),
    }


@app.get("/cases/{case_id}/timeline", response_model=TimelineReport)
async def case_timeline(case_id: str, bucket: str = "day") -> dict[str, Any]:
    """Línea temporal del caso (agregados por día/hora + eventos, para la UI)."""
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.timeline import CaseTimeline

    try:
        return CaseTimeline(db).build(case_id, bucket=bucket)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/cases/{case_id}/correlations")
async def case_correlations(case_id: str) -> dict[str, Any]:
    """Vínculos del caso con el resto del repositorio + candidatos de identidad."""
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.correlation import CorrelationEngine

    engine = CorrelationEngine(db)
    return {
        "case_id": case_id,
        "cross_case": engine.cross_case_matches(case_id=case_id),
        "identity_candidates": engine.identity_candidates(case_id),
    }


@app.get("/cases/{case_id}/attestation")
async def case_attestation(case_id: str) -> dict[str, Any]:
    """Atestación firmada del estado de la cadena de custodia."""
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.ledger import ForensicLedger

    return ForensicLedger(db).attest_case(case_id)


@app.post("/cases/{case_id}/ledger/reseal")
async def reseal_case_ledger(case_id: str) -> dict[str, Any]:
    """Migración de cadenas v1: reescribe hashes/firmas/cabeza al formato vigente.

    Sólo re-sella cadenas que validaban antes (v1 o formato actual); una cadena
    adulterada se rechaza con `code=CHAIN_INVALID_FOR_RESEAL`.
    """
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.ledger import ForensicLedger

    return ForensicLedger(db).reseal_case_chain(case_id)


# ------------------------------------------------------------------
# Event Sourcing: eventos inmutables y replay de estado
# ------------------------------------------------------------------


@app.get("/cases/{case_id}/events")
async def case_events(case_id: str, after: int | None = None) -> dict[str, Any]:
    """Eventos de un caso (ordenados por secuencia).

    Args:
        case_id: ID del caso
        after: Secuencia desde la cual obtener eventos (exclusivo)
    """
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.event_store import EventStore

    store = EventStore(db)
    events = store.get_events(case_id, after=after)
    return {
        "case_id": case_id,
        "total_events": len(events),
        "events": [e.model_dump() for e in events],
    }


@app.get("/cases/{case_id}/events/replay")
async def case_events_replay(case_id: str, after: int | None = None) -> dict[str, Any]:
    """Replay de eventos para reconstruir el estado de un caso.

    Reproduce la secuencia ordenada de eventos y devuelve el estado actual
    del caso basado en los eventos ocurridos.

    Args:
        case_id: ID del caso
        after: Secuencia desde la cual hacer replay (exclusivo)
    """
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.event_store import EventStore

    store = EventStore(db)
    return store.replay(case_id, after=after)


@app.get("/events/audit")
async def all_events() -> dict[str, Any]:
    """Todos los eventos del sistema (auditoría global).

    Ruta separada de `/events` a propósito: ese path lo ocupa el stream SSE
    del bus (`text/event-stream`). Si ambos compartieran path, ganaría el
    primero registrado y el EventSource recibiría JSON, no el stream.
    """
    from specter.osint_core.event_store import EventStore

    store = EventStore(db)
    events = store.get_all_events()
    return {
        "total_events": len(events),
        "events": [e.model_dump() for e in events],
    }


# ------------------------------------------------------------------
# Historial de conversaciones del agente (sesiones propias del engine)
# ------------------------------------------------------------------


@app.get("/agent/sessions", response_model=SessionsOut)
async def agent_sessions(case_id: str | None = None, limit: int = 50) -> dict[str, Any]:
    """Sesiones del agente, más recientes primero (opcionalmente de un caso)."""
    return {
        "sessions": [s.model_dump() for s in db.list_agent_sessions(case_id, limit)],
    }


@app.get("/agent/sessions/{session_id}", response_model=SessionDetailOut)
async def agent_session(session_id: str) -> dict[str, Any]:
    """Transcripción completa de una sesión del agente."""
    session = db.get_agent_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Sesión {session_id} no existe")
    return {
        "session": session.model_dump(),
        "messages": [m.model_dump() for m in db.get_agent_session_messages(session_id)],
    }


@app.delete("/agent/sessions/{session_id}")
async def agent_session_delete(session_id: str) -> dict[str, Any]:
    """Borra una sesión del historial y su transcripción."""
    if not db.delete_agent_session(session_id):
        raise HTTPException(status_code=404, detail=f"Sesión {session_id} no existe")
    return {"status": "ok", "session_id": session_id}


@app.post("/agent/runs/cancel")
async def agent_runs_cancel(body: RunsCancelRequest) -> dict[str, Any]:
    """Detiene runs en vuelo (botón Detener de la UI). Cooperativo."""
    from engine import agent

    cancelled = agent.request_run_cancel(body.session_id, run_id=body.run_id)
    return {"status": "ok", "cancelled": cancelled}


@app.get("/settings/secrets")
async def list_secrets_endpoint() -> dict[str, Any]:
    """Estado de la bóveda local: nombres admitidos y claves enmascaradas."""
    from specter import config as specter_config
    from specter import secrets

    return {"secrets": secrets.list_secrets(), "path": str(specter_config.secrets_path())}


@app.put("/settings/secrets/{name}")
async def set_secret_endpoint(name: str, body: SecretUpsert) -> dict[str, Any]:
    from specter import secrets

    try:
        secrets.set_secret(name, body.value)
    except secrets.SecretError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "secrets": secrets.list_secrets()}


@app.delete("/settings/secrets/{name}")
async def delete_secret_endpoint(name: str) -> dict[str, Any]:
    from specter import secrets

    try:
        removed = secrets.delete_secret(name)
    except secrets.SecretError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "removed": removed, "secrets": secrets.list_secrets()}


@app.get("/intelligence/cross-case")
async def intelligence_cross_case() -> dict[str, Any]:
    """Correlación global: artefactos compartidos por dos o más casos."""
    from specter.osint_core.correlation import CorrelationEngine

    return CorrelationEngine(db).cross_case_matches()


# ------------------------------------------------------------------
# SSE: stream de eventos del bus
# ------------------------------------------------------------------


@app.get("/events")
async def events_stream() -> StreamingResponse:
    queue = bus.subscribe()
    return StreamingResponse(event_stream(queue), media_type="text/event-stream")


async def event_stream(queue: asyncio.Queue) -> AsyncIterator[bytes]:
    """Serializa la cola del bus al formato SSE (extraído para testeo directo)."""
    try:
        yield b": specter-engine-sse\n\n"
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
                data = json.dumps(event, ensure_ascii=False)
                yield f"event: {event['type']}\ndata: {data}\n\n".encode()
            except TimeoutError:
                yield b": keepalive\n\n"
    finally:
        bus.unsubscribe(queue)


# ------------------------------------------------------------------
# Agente IA (se registra como router para mantener este archivo legible)
# ------------------------------------------------------------------


@app.post("/agent/permissions/respond")
async def agent_permission_respond(body: AgentPermission) -> dict[str, Any]:
    from engine import agent

    ok = agent.respond_permission(body.request_id, body.decision)
    if not ok:
        raise HTTPException(
            status_code=404, detail=f"Permission request {body.request_id} no existe"
        )
    return {"status": "ok", "decision": body.decision}


@app.post("/agent/questions/respond")
async def agent_question_respond(body: AgentQuestionReply) -> dict[str, Any]:
    from engine import agent

    ok = agent.reply_question(body.request_id, body.answers)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Question request {body.request_id} no existe")
    return {"status": "ok", "answers": body.answers}


@app.post("/agent/run", response_model=AgentRunResult)
async def agent_run(body: AgentRunRequest) -> dict[str, Any]:
    """Ejecuta el loop del agente y devuelve la transcripción completa de mensajes."""
    from engine import agent  # import perezoso: evita dependencia dura sin clave API

    case = None
    if body.case_id:
        case = db.get_case(body.case_id)
        if not case:
            raise HTTPException(status_code=404, detail=f"Caso {body.case_id} no existe")

    async def emit(event_type: str, payload: dict[str, Any]) -> None:
        bus.publish(event_type, payload)

    try:
        result = await agent.run_agent(
            message=body.message,
            case_id=body.case_id,
            provider=body.provider,
            model=body.model,
            api_key=body.api_key,
            base_url=body.base_url,
            max_iterations=body.max_iterations,
            emit=emit,
            stream=body.stream,
            plan_first=body.plan_first,
            auto_approve=body.auto_approve,
            session_id=body.session_id,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


# ------------------------------------------------------------------
# Run Coordinator: gestión de runs coordinados por sesión
# ------------------------------------------------------------------

from specter.osint_core.run_coordinator import coordinator as run_coordinator


@app.get("/runs")
async def list_runs(case_id: str | None = None) -> dict[str, Any]:
    """Lista runs activos del coordinador."""
    runs = run_coordinator.list_runs(case_id)
    return {
        "runs": [
            {
                "key": r.key,
                "case_id": r.case_id,
                "status": r.status.value,
                "priority": r.priority.value,
                "created_at": r.created_at,
                "started_at": r.started_at,
                "ended_at": r.ended_at,
                "error": r.error,
            }
            for r in runs
        ]
    }


@app.post("/runs/{key}/interrupt")
async def interrupt_run(key: str) -> dict[str, Any]:
    """Interrumpe un run en vuelo."""
    result = await run_coordinator.interrupt(key)
    if not result:
        raise HTTPException(status_code=404, detail=f"Run {key} no existe o no está activo")
    return {"status": "ok", "key": key, "cancelled": True}


# ------------------------------------------------------------------
# Snapshots: captura, diff y revert del grafo forense
# ------------------------------------------------------------------

from specter.osint_core.snapshot import SnapshotService

snapshot_service = SnapshotService(db)


@app.get("/cases/{case_id}/snapshots")
async def list_snapshots(case_id: str) -> dict[str, Any]:
    """Lista los snapshots de un caso."""
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    snapshots = snapshot_service.list_snapshots(case_id)
    return {
        "case_id": case_id,
        "snapshots": [s.model_dump() for s in snapshots],
    }


@app.post("/cases/{case_id}/snapshots")
async def capture_snapshot(
    case_id: str, description: str = "", tags: list[str] | None = None
) -> dict[str, Any]:
    """Captura un snapshot del estado actual del grafo."""
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    snapshot = snapshot_service.capture(case_id, description=description, tags=tags)
    return {
        "status": "CAPTURED",
        "snapshot_id": snapshot.metadata.snapshot_id,
        "case_id": case_id,
        "entity_count": snapshot.metadata.entity_count,
        "relation_count": snapshot.metadata.relation_count,
    }


@app.post("/cases/{case_id}/revert")
async def revert_snapshot(case_id: str, snapshot_id: str) -> dict[str, Any]:
    """Revierte el grafo de un caso a un snapshot anterior."""
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    snapshot = snapshot_service.load(snapshot_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} no existe")
    result = snapshot_service.revert(case_id, snapshot)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Specter Engine HTTP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Reinicio automático al cambiar el código (solo dev: hace "
        "imposible el engine desactualizado)",
    )
    args = parser.parse_args()
    if not _engine_token():
        parser.error("define SPECTER_ENGINE_TOKEN antes de iniciar el motor HTTP")
    host = args.host.strip("[]").lower()
    try:
        is_loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback and not _engine_token():
        parser.error("--host no loopback requiere SPECTER_ENGINE_TOKEN configurado")

    # El motor en producción firma su cadena de custodia: si no hay clave local,
    # se genera aquí (0600) y el servicio nace sellando la evidencia.
    from specter import config as specter_config

    specter_config.ensure_ledger_key()
    from specter.server import collectors

    collectors.load_entry_points()

    import uvicorn

    # El log de acceso de uvicorn se silencia a propósito: la UI consulta
    # /health y /cases cada 3,5s para detectar caídas del motor, y con
    # `access_log=True` eso generaba cientos de líneas que tapaban los avisos
    # que importan (colectores, correlaciones, errores del agente). Los
    # errores y avisos del motor siguen saliendo: eso va por stderr.
    if args.reload:
        # Con import string para que el reloader observe el paquete.
        uvicorn.run(
            "engine.http_server:app",
            host=args.host,
            port=args.port,
            log_level="info",
            reload=True,
            reload_dirs=[str(_ENGINE_SRC)],
            access_log=False,
        )
    else:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info", access_log=False)


if __name__ == "__main__":
    main()

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
import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import suppress
from pathlib import Path
from typing import Any

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

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from specter.osint_core.database import Database
from specter.osint_core.models import current_utc_iso

from engine.registry import call_tool_validated, get_registry_tools, get_tool_schemas

# ------------------------------------------------------------------
# Estado central del motor (instancia única, como opencode hace con
# sus servicios de sesión: un solo proceso dueño de la verdad).
# ------------------------------------------------------------------

db = Database(DATA_DIR / "specter_osint.db")

app = FastAPI(
    title="Specter Engine",
    description="Motor forense OSINT headless (REST + SSE + MCP)",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # motor local; el renderer Electron sirve origen propio
    allow_methods=["*"],
    allow_headers=["*"],
)

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


# ------------------------------------------------------------------
# Modelos de API
# ------------------------------------------------------------------


class CaseCreate(BaseModel):
    name: str
    description: str
    investigator: str = "Analista_Specter"


class AgentRunRequest(BaseModel):
    case_id: str | None = None
    message: str
    provider: str = "anthropic"
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    max_iterations: int = Field(default=25, ge=1, le=100)


class AgentPermission(BaseModel):
    request_id: str
    decision: str  # "allow" | "allow_session" | "deny"


# ------------------------------------------------------------------
# Salud e introspección
# ------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "engine": "specter",
        "version": "0.2.0",
        "mcp_tools": len(await get_registry_tools()),
        "data_dir": str(DATA_DIR),
        "reports_dir": str(REPORTS_DIR),
    }


@app.get("/tools")
async def list_tools() -> dict[str, Any]:
    """Registry unificado: tools MCP expuestas con su schema JSON."""
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
# Casos
# ------------------------------------------------------------------


@app.post("/cases")
async def create_case_endpoint(body: CaseCreate) -> dict[str, Any]:
    raw = await call_tool_validated(
        "create_case",
        {"name": body.name, "description": body.description, "investigator": body.investigator},
    )
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


@app.get("/cases/{case_id}/graph")
async def case_graph(
    case_id: str, max_depth: int = 2, center_id: str | None = None
) -> dict[str, Any]:
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    from specter.osint_core.graph import OSINTGraph

    graph = OSINTGraph(db)
    return graph.query_subgraph(case_id=case_id, center_id=center_id, max_depth=max_depth)


@app.get("/cases/{case_id}/ledger")
async def case_ledger(case_id: str) -> dict[str, Any]:
    if not db.get_case(case_id):
        raise HTTPException(status_code=404, detail=f"Caso {case_id} no existe")
    blocks = db.get_case_ledger(case_id)
    return {"case_id": case_id, "blocks": [b.model_dump() for b in blocks]}


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


@app.post("/agent/run")
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
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Specter Engine HTTP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

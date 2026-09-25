"""
Smoke test del engine HTTP: uvicorn en thread + cliente httpx.
Valida /health, /tools, creacion de caso y consultas de grafo/ledger.
"""
import threading
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

import httpx
import uvicorn

import http_server

PORT = 8793
BASE = f"http://127.0.0.1:{PORT}"


def serve() -> None:
    uvicorn.run(http_server.app, host="127.0.0.1", port=PORT, log_level="error")


def main() -> None:
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(3)

    with httpx.Client(base_url=BASE, timeout=30) as c:
        health = c.get("/health").json()
        assert health["status"] == "ok", health
        print("health OK:", health["version"], "| tools MCP:", health["mcp_tools"])

        tools = c.get("/tools").json()
        names = [t["name"] for t in tools["tools"]]
        assert "create_case" in names and "investigate_domain" in names
        print(f"registry OK: {len(names)} tools ->", names[:4], "...")

        created = c.post(
            "/cases",
            json={"name": "Smoke API", "description": "verificacion de plataforma"},
        ).json()
        assert created["status"] == "CASE_CREATED", created
        case_id = created["case_id"]
        print("case OK:", case_id, "| genesis:", created["genesis_hash"][:16], "...")

        ledger = c.get(f"/cases/{case_id}/ledger").json()
        assert len(ledger["blocks"]) >= 1
        print(f"ledger OK: {len(ledger['blocks'])} bloque(s)")

        graph = c.get(f"/cases/{case_id}/graph").json()
        assert "total_nodes" in graph
        print(f"graph OK: {graph['total_nodes']} nodos, {graph['total_edges']} aristas")

        # Stream SSE: conectar y recibir el evento keepalive/comment inicial
        with c.stream("GET", "/events") as r:
            assert r.status_code == 200
            print("SSE OK: stream abierto")

    print("\nSMOKE TEST COMPLETO: engine HTTP operativo")


if __name__ == "__main__":
    main()

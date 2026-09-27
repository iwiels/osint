"""
Smoke test del engine HTTP (y del binario empaquetado): uvicorn en thread + httpx.

Recorre el contrato completo que consume Electron —health, registry, casos,
custodia, timeline, correlaciones, sellado, bóveda y SSE— y falla a la primera
inconsistencia. Es la puerta de una release: `npm run smoke:engine`.
"""

import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

import http_server
import httpx
import uvicorn
from specter.osint_core.models import EntityNode, EntityType

# C1: el engine exige Bearer en todo salvo /health. El smoke fija el suyo
# (el middleware lee el env por request, así que el orden no importa).
os.environ.setdefault("SPECTER_ENGINE_TOKEN", "smoke-token")
_AUTH = {"Authorization": "Bearer smoke-token"}

PORT = 8793
BASE = f"http://127.0.0.1:{PORT}"

# Tools que debe exponer el registry tras las fases B y D.
EXPECTED_TOOLS = (
    "create_case",
    "investigate_domain",
    "query_graph",
    "verify_case_integrity",
    "correlate_cases",
    "case_timeline",
    "attest_case_ledger",
    "list_collectors",
    "run_collector",
)


def serve() -> None:
    uvicorn.run(http_server.app, host="127.0.0.1", port=PORT, log_level="error")


def main() -> int:
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    time.sleep(3)

    with httpx.Client(base_url=BASE, timeout=30, headers=_AUTH) as client:
        health = client.get("/health").json()
        assert health["status"] == "ok", health
        print(f"health OK: {health['version']} | tools MCP: {health['mcp_tools']}")

        names = [tool["name"] for tool in client.get("/tools").json()["tools"]]
        missing = [name for name in EXPECTED_TOOLS if name not in names]
        assert not missing, f"tools ausentes en el registry: {missing}"
        print(f"registry OK: {len(names)} tools (esperadas >= {len(EXPECTED_TOOLS)})")

        catalog = client.post("/tools/list_collectors/call", json={"arguments": {}}).json()
        collectors = catalog["result"]["collectors"]
        assert len(collectors) >= 9 and catalog["result"]["errors"] == [], catalog
        print(f"collectors OK: {len(collectors)} en el catálogo (builtins + plugins)")

        created = client.post(
            "/cases", json={"name": "Smoke API", "description": "verificacion de plataforma"}
        ).json()
        assert created["status"] == "CASE_CREATED", created
        case_id = created["case_id"]
        print(f"case OK: {case_id} | genesis: {created['genesis_hash'][:16]}...")

        # Dos entidades + una relación: alimentan timeline y correlación.
        for entity_type, value in ((EntityType.ALIAS, "smoke"), (EntityType.DOMAIN, "smoke.test")):
            http_server.db.upsert_entities(case_id, [EntityNode.create(entity_type, value)])
        linked = client.post(
            "/tools/link_entities/call",
            json={
                "arguments": {
                    "case_id": case_id,
                    "source_id": "alias:smoke",
                    "target_id": "domain:smoke.test",
                    "relation_type": "CORRELATED_WITH",
                }
            },
        ).json()
        assert linked["result"]["status"] == "LINK_CREATED", linked

        ledger = client.get(f"/cases/{case_id}/ledger").json()
        assert len(ledger["blocks"]) >= 2, ledger
        assert ledger["valid"] is True
        assert ledger["signature_status"] in {"SEALED", "UNSIGNED", "KEY_UNAVAILABLE"}, ledger
        print(f"ledger OK: {len(ledger['blocks'])} bloques | sellado: {ledger['signature_status']}")

        attestation = client.get(f"/cases/{case_id}/attestation").json()
        assert attestation["chain_valid"] is True
        assert attestation["head"]["block_index"] == len(ledger["blocks"]) - 1
        print(f"atestación OK: sealed={attestation['sealed']} key_id={attestation['key_id']}")

        timeline = client.get(f"/cases/{case_id}/timeline", params={"bucket": "hour"}).json()
        assert timeline["total_events"] >= 4, timeline
        assert timeline["buckets"], timeline
        buckets = len(timeline["buckets"])
        print(f"timeline OK: {timeline['total_events']} eventos en {buckets} ventanas")

        correlations = client.get(f"/cases/{case_id}/correlations").json()
        assert correlations["cross_case"]["anchor_case"] == case_id
        assert correlations["identity_candidates"]["analyzed_entities"] >= 1
        print(
            "correlaciones OK: "
            f"{correlations['cross_case']['total_shared_entities']} compartidos, "
            f"{correlations['identity_candidates']['total_candidates']} candidatos de identidad"
        )

        global_view = client.get("/intelligence/cross-case").json()
        assert "cases_involved_count" in global_view
        print(f"barrido global OK: {global_view['cases_involved_count']} casos implicados")

        vault = client.get("/settings/secrets").json()
        assert len(vault["secrets"]) == 8 and "path" in vault
        assert all("masked" in entry for entry in vault["secrets"])
        print(f"bóveda OK: {len(vault['secrets'])} claves admitidas (valores enmascarados)")

        graph = client.get(f"/cases/{case_id}/graph").json()
        assert graph["total_nodes"] >= 2, graph
        print(f"graph OK: {graph['total_nodes']} nodos, {graph['total_edges']} aristas")

        with client.stream("GET", "/events") as response:
            assert response.status_code == 200
            print("SSE OK: stream abierto")

    print("\nSMOKE TEST COMPLETO: engine HTTP operativo\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

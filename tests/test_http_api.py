"""
Tests de la capa HTTP del engine (FastAPI) sin sockets reales.

Se usa httpx.ASGITransport contra la app: mismo contrato que consumirá
Electron, sin abrir puertos. Cubre: health, registry, ciclo de vida de caso,
call de tools y errores controlados (404).
"""

from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_health_reports_engine_status(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")

    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["engine"] == "specter"
    assert body["mcp_tools"] >= 15


async def test_registry_lists_forensic_tools(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/tools")

    assert res.status_code == 200
    names = [t["name"] for t in res.json()["tools"]]
    for expected in ("create_case", "investigate_domain", "verify_case_integrity"):
        assert expected in names
    for tool in res.json()["tools"]:
        assert set(tool) == {"name", "description", "schema"}


async def test_case_lifecycle_over_http(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/cases",
            json={"name": "Caso CI", "description": "verificacion", "investigator": "pytest"},
        )
        assert created.status_code == 200
        case_id = created.json()["case_id"]

        listed = await client.get("/cases")
        assert case_id in [c["case_id"] for c in listed.json()]

        ledger = await client.get(f"/cases/{case_id}/ledger")
        assert ledger.status_code == 200
        assert ledger.json()["blocks"][0]["action"]  # bloque génesis presente

        missing = await client.get("/cases/case-inexistente")
        assert missing.status_code == 404


async def test_tool_call_unknown_returns_404(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/tools/no_existe/call", json={"arguments": {}})

    assert res.status_code == 404


async def test_create_case_via_tool_call(engine) -> None:
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/tools/create_case/call",
            json={"arguments": {"name": "Vía registry", "description": "d"}},
        )

    assert res.status_code == 200
    body = res.json()
    assert body["tool"] == "create_case"
    assert body["result"]["status"] == "CASE_CREATED"

"""
Tests de resolución de providers (lógica pura del agente) y del stream SSE.
Sin red: solo contrato y errores controlados.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

pytestmark = pytest.mark.asyncio


def test_resolve_provider_rejects_unknown() -> None:
    from engine.agent import _resolve_provider

    with pytest.raises(RuntimeError, match="Provider desconocido"):
        _resolve_provider("noexiste", None, None, None)


def test_resolve_provider_requires_key_for_cloud() -> None:
    from engine.agent import _resolve_provider

    with pytest.raises(RuntimeError, match="API key"):
        _resolve_provider("anthropic", None, None, None)


def test_resolve_provider_defaults_and_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    from engine.agent import PROVIDERS, _resolve_provider

    cfg, model = _resolve_provider("ollama", None, None, None)
    assert cfg.name == "ollama"
    assert model == PROVIDERS["ollama"].default_model

    # base_url override y api_key explícita no tocan el entorno
    cfg2, model2 = _resolve_provider("openai", "gpt-x", "sk-test", "http://127.0.0.1:9999/v1")
    assert cfg2.base_url == "http://127.0.0.1:9999/v1"
    assert cfg2.api_key == "sk-test"
    assert model2 == "gpt-x"


async def test_events_stream_emits_published_event(engine) -> None:
    """Bus → stream SSE: publicar tras suscribir entrega el evento serializado.

    Se prueba event_stream() directamente (extraído del endpoint para eso):
    determinista, sin depend del transporte ASGI ni de keepalives infinitos.
    """
    queue = engine.bus.subscribe()
    received: list[bytes] = []

    async def consume() -> None:
        async for chunk in engine.event_stream(queue):
            received.append(chunk)
            if b"case.created" in chunk:
                return

    task = asyncio.create_task(consume())
    await asyncio.sleep(0)  # cede el control: el generador emite el comentario inicial
    engine.bus.publish("case.created", {"case_id": "case-x", "name": "n"})
    await asyncio.wait_for(task, timeout=5)

    assert any(b"specter-engine-sse" in c for c in received)
    assert any(b"case-x" in c for c in received)


async def test_agent_run_rejects_unknown_provider(engine) -> None:
    """Error de provider se traduce en 400 controlado, no en 500."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/agent/run",
            json={"message": "hola", "provider": "noexiste"},
        )
    assert res.status_code == 400
    assert "Provider" in res.json()["detail"]

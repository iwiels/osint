"""
Tests de resolución de providers (lógica pura del agente) y del stream SSE.
Sin red: solo contrato y errores controlados. El retry de rate limit se prueba
con respuestas httpx sintéticas (sin tocar el gateway Zen).
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from conftest import TEST_AUTH_HEADERS

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

    assert any(b"wraith-engine-sse" in c for c in received)
    assert any(b"case-x" in c for c in received)


async def test_agent_run_rejects_unknown_provider(engine) -> None:
    """Error de provider se traduce en 400 controlado, no en 500."""
    transport = httpx.ASGITransport(app=engine.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=TEST_AUTH_HEADERS
    ) as client:
        res = await client.post(
            "/agent/run",
            json={"message": "hola", "provider": "noexiste"},
        )
    assert res.status_code == 400
    assert "Provider" in res.json()["detail"]


# ------------------------------------------------------------------
# Gateway Zen (HTTP) — resolución de credenciales (sin auth.json ni CLI)
# ------------------------------------------------------------------


def test_resolve_provider_opencode_usa_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sin key explícita, se usa env OPENCODE_API_KEY."""
    from engine.agent import PROVIDERS, _resolve_provider

    monkeypatch.setenv("OPENCODE_API_KEY", "zen-key-env")

    cfg, model = _resolve_provider("opencode", None, None, None)
    assert cfg.base_url == "https://opencode.ai/zen/v1"
    assert cfg.api_key == "zen-key-env"
    assert model == PROVIDERS["opencode"].default_model


def test_resolve_provider_opencode_key_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Key explícita > env OPENCODE_API_KEY."""
    from engine.agent import _resolve_provider

    monkeypatch.setenv("OPENCODE_API_KEY", "key-de-env")

    cfg1, m1 = _resolve_provider("opencode", None, "key-explicita", None)
    cfg2, _ = _resolve_provider("opencode", None, None, None)
    assert cfg1.api_key == "key-explicita"
    assert cfg2.api_key == "key-de-env"
    assert m1 == "space-bunny-free"


def test_resolve_provider_opencode_missing_key_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Modelo de pago sin key -> error; modelo FREE -> se permite con placeholder 'public'."""
    from engine.agent import _resolve_provider

    monkeypatch.delenv("OPENCODE_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="Falta API key"):
        _resolve_provider("opencode", "glm-5.3", None, None)

    # Los free anónimos usan el placeholder 'public' (mismo truco que el cliente oficial)
    cfg_free, model_free = _resolve_provider("opencode", "big-pickle", None, None)
    assert cfg_free.api_key == "public"
    assert model_free == "big-pickle"

    cfg_default, _ = _resolve_provider("opencode", None, None, None)
    assert cfg_default.api_key == "public"  # default = space-bunny-free (free anónimo)


def test_default_zen_model_is_free() -> None:
    """El modelo por defecto de Zen debe estar en la lista de modelos free."""
    from engine.agent import FREE_ZEN_MODELS, PROVIDERS

    assert PROVIDERS["opencode"].default_model in FREE_ZEN_MODELS


# ------------------------------------------------------------------
# Rate limit: retry-after + backoff exponencial + evento SSE
# ------------------------------------------------------------------


def _http_error(status: int, retry_after: str | None = None) -> httpx.HTTPStatusError:
    headers = {"retry-after": retry_after} if retry_after else {}
    request = httpx.Request("POST", "http://zen.test/chat/completions")
    response = httpx.Response(status, headers=headers, request=request)
    return httpx.HTTPStatusError("err", request=request, response=response)


def test_retry_wait_honors_retry_after_header() -> None:
    from engine.agent import _retry_wait_seconds

    assert _retry_wait_seconds(_http_error(429, "7").response, 0) == 7.0


async def test_zen_free_tier_403_is_translated() -> None:
    """El 403 FreeTierError del gateway se traduce a un mensaje accionable."""
    from engine.agent import _raise_zen_error

    request = httpx.Request("POST", "https://opencode.ai/zen/v1/chat/completions")
    response = httpx.Response(
        403,
        request=request,
        json={
            "type": "error",
            "error": {
                "type": "FreeTierError",
                "message": "OpenCode's free tier can only be used from within OpenCode",
            },
        },
    )
    with pytest.raises(RuntimeError, match="FreeTierError"):
        await _raise_zen_error(response)


async def test_zen_other_403_uses_raise_for_status() -> None:
    """Un 403 que no es FreeTierError sigue siendo HTTPStatusError."""
    from engine.agent import _raise_zen_error

    request = httpx.Request("POST", "https://opencode.ai/zen/v1/chat/completions")
    response = httpx.Response(403, request=request, json={"error": {"type": "AuthError"}})
    with pytest.raises(httpx.HTTPStatusError):
        await _raise_zen_error(response)


def test_retry_wait_backoff_exponential_and_capped() -> None:
    from engine.agent import BACKOFF_CAP_SECONDS, _retry_wait_seconds

    assert _retry_wait_seconds(_http_error(429).response, 0) == pytest.approx(1.5)
    assert _retry_wait_seconds(_http_error(429).response, 1) == pytest.approx(3.0)
    assert _retry_wait_seconds(_http_error(429).response, 9) == BACKOFF_CAP_SECONDS


async def test_call_step_with_retry_emits_rate_limited_events() -> None:
    """429 → emite agent.rate_limited por SSE y reintenta hasta el máximo."""
    from engine.agent import _call_step_with_retry

    events: list[tuple[str, dict]] = []

    async def emit(event_type: str, payload: dict) -> None:
        events.append((event_type, payload))

    ok = ({"role": "assistant", "content": "ok"}, [])
    calls = {"n": 0}

    async def flaky_step():
        calls["n"] += 1
        if calls["n"] <= 2:
            raise _http_error(429, "0")  # espera 0s: test rápido
        return ok

    result = await _call_step_with_retry(emit, flaky_step)
    assert result == ok
    assert calls["n"] == 3
    assert [t for t, _ in events] == ["agent.rate_limited", "agent.rate_limited"]


async def test_call_step_with_retry_gives_up_after_max() -> None:
    from engine.agent import MAX_RETRIES, _call_step_with_retry

    events: list[tuple[str, dict]] = []

    async def emit(event_type: str, payload: dict) -> None:
        events.append((event_type, payload))

    async def always_429():
        raise _http_error(429, "0")

    with pytest.raises(httpx.HTTPStatusError):
        await _call_step_with_retry(emit, always_429)
    assert len(events) == MAX_RETRIES  # un evento por reintento agotado


async def test_call_step_with_retry_does_not_touch_client_errors() -> None:
    """401/400 no se reintentan: falla de inmediato, sin eventos de rate limit."""
    from engine.agent import _call_step_with_retry

    events: list[tuple[str, dict]] = []

    async def emit(event_type: str, payload: dict) -> None:
        events.append((event_type, payload))

    async def unauthorized():
        raise _http_error(401)

    with pytest.raises(httpx.HTTPStatusError):
        await _call_step_with_retry(emit, unauthorized)
    assert events == []

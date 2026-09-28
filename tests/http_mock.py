"""
Arnés de red para la suite: transporte HTTP en memoria + zona DNS falsa.

Los colectores construyen `httpx.AsyncClient()` internamente y resuelven DNS
vía `dns.resolver`; en lugar de refactorizar el kernel para inyectar
dependencias, los tests sustituyen esas fábricas por versiones en memoria:

    router = MockRouter()
    router.add("GET", r"/users/alice$", json={"login": "alice"})
    patch_network(monkeypatch, router, zone={"example.com/A": ["1.2.3.4"]})

Cero red real y cero dependencias nuevas: `httpx.MockTransport` viene dentro de
httpx. Las rutas no registradas devuelven 599 para que un test que olvide
mockear una URL falle con un mensaje claro en vez de golpear internet.

NOTA (fase C): el mismo arnés mockea el endpoint del LLM, así que `run_agent`
puede ejecutarse de punta a punta con un provider falso.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import dns.resolver
import httpx

Responder = Callable[[httpx.Request], httpx.Response]

# Consumo simulado que los gateways OpenAI-compatible devuelven en el stream.
USAGE = {"prompt_tokens": 11, "completion_tokens": 7}


@dataclass
class Route:
    method: str
    pattern: re.Pattern[str]
    responder: Responder
    hits: int = 0


@dataclass
class MockRouter:
    """Tabla de rutas (método + regex sobre la URL) → respuesta HTTP."""

    _routes: list[Route] = field(default_factory=list)
    requests: list[httpx.Request] = field(default_factory=list)

    def add(
        self,
        method: str,
        url_pattern: str,
        *,
        json: Any = None,
        text: str | None = None,
        content: bytes | None = None,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> MockRouter:
        def responder(request: httpx.Request) -> httpx.Response:
            kwargs: dict[str, Any] = {"status_code": status_code, "headers": headers}
            if json is not None:
                kwargs["json"] = json
            elif text is not None:
                kwargs["text"] = text
            elif content is not None:
                kwargs["content"] = content
            return httpx.Response(request=request, **kwargs)

        return self.add_responder(method, url_pattern, responder)

    def add_responder(self, method: str, url_pattern: str, responder: Responder) -> MockRouter:
        self._routes.append(
            Route(method=method.upper(), pattern=re.compile(url_pattern), responder=responder)
        )
        return self

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        for route in self._routes:
            if route.method == request.method and route.pattern.search(str(request.url)):
                route.hits += 1
                return route.responder(request)
        return httpx.Response(
            status_code=599,
            json={"error": "URL no mockeada", "method": request.method, "url": str(request.url)},
            request=request,
        )

    def urls(self) -> list[str]:
        return [str(r.url) for r in self.requests]

    def count(self, url_pattern: str) -> int:
        pattern = re.compile(url_pattern)
        return sum(1 for r in self.requests if pattern.search(str(r.url)))


def _delta(delta: dict[str, Any]) -> str:
    return f"data: {json.dumps({'choices': [{'index': 0, 'delta': delta}]})}\n\n"


def sse_chat_stream(payload: dict[str, Any]) -> str:
    """Convierte una respuesta de chat-completions en el stream SSE equivalente.

    Reparte el contenido en dos deltas y **fragmenta** cada tool_call en dos
    trozos con su índice, que es exactamente lo que hace un provider real: así
    el test ejercita el ensamblado por índice del parser de streaming.
    """
    message = payload["choices"][0]["message"]
    body = ""
    content = message.get("content")
    if content:
        half = max(1, len(content) // 2)
        body += _delta({"content": content[:half]})
        body += _delta({"content": content[half:]})

    for index, call in enumerate(message.get("tool_calls") or []):
        function = call["function"]
        arguments = function.get("arguments") or ""
        split = max(1, len(arguments) // 2)
        body += _delta(
            {
                "tool_calls": [
                    {
                        "index": index,
                        "id": call["id"],
                        "type": "function",
                        "function": {
                            "name": function["name"],
                            "arguments": arguments[:split],
                        },
                    }
                ]
            }
        )
        body += _delta(
            {"tool_calls": [{"index": index, "function": {"arguments": arguments[split:]}}]}
        )

    body += f"data: {json.dumps({'choices': [], 'usage': USAGE})}\n\n"
    return body + "data: [DONE]\n\n"


def json_sequence(*payloads: dict[str, Any], status_code: int = 200) -> Responder:
    """Responder que entrega payloads en orden; el último se repite.

    Es la forma de simular turnos de un LLM: primer turno pide una tool, el
    segundo responde con el mensaje final.
    """
    pending = list(payloads)

    def responder(request: httpx.Request) -> httpx.Response:
        payload = pending.pop(0) if len(pending) > 1 else pending[0]
        return httpx.Response(status_code=status_code, json=payload, request=request)

    return responder


class _FakeName:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text

    def __str__(self) -> str:
        return self._text


class _FakeAnswer:
    """Respuesta DNS mínima: `.to_text()` y `.exchange` (registros MX)."""

    def __init__(self, text: str) -> None:
        self._text = text
        self.exchange = _FakeName(text)

    def to_text(self) -> str:
        return self._text

    def __str__(self) -> str:
        return self._text


class FakeDNS:
    """Zona DNS en memoria con el contrato de `dns.resolver.Resolver`.

    Claves con formato "name/TYPE"; el valor es una lista de respuestas o una
    excepción a lanzar (p. ej. `dns.resolver.NoAnswer()`).
    """

    def __init__(self, zone: dict[str, Any] | None = None) -> None:
        self.zone = {k.rstrip(".").lower(): v for k, v in (zone or {}).items()}
        self.queries: list[str] = []

    def resolve(self, name: Any, rdtype: str = "A", **_: Any) -> list[_FakeAnswer]:
        key = f"{str(name).rstrip('.').lower()}/{str(rdtype).lower()}"
        self.queries.append(key)
        if key not in self.zone:
            raise dns.resolver.NoAnswer()
        value = self.zone[key]
        if isinstance(value, Exception):
            raise value
        return [_FakeAnswer(str(v)) for v in value]


def patch_httpx(monkeypatch: Any, router: MockRouter) -> MockRouter:
    """Sustituye httpx.AsyncClient/Client y curl_cffi.AsyncSession por mocks.

    El transporte del kernel (`specter.httpx_transport`) habla curl_cffi con
    impersonación TLS: el arnés intercepta esa sesión con la MISMA tabla de
    rutas del router, así que un colector migre o no migre, la suite sigue
    sin tocar internet real.
    """
    transport = httpx.MockTransport(router.handler)
    real_async, real_sync = httpx.AsyncClient, httpx.Client

    def async_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return real_async(*args, transport=transport, **kwargs)

    def sync_client(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs.pop("transport", None)
        return real_sync(*args, transport=transport, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", async_client)
    monkeypatch.setattr(httpx, "Client", sync_client)
    _patch_curl_session(monkeypatch, router)
    return router


class _MockCurlResponse:
    """Superficie de respuesta curl_cffi (status/headers/content/text/history)."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> Any:
        return self._response.headers

    @property
    def content(self) -> bytes:
        return self._response.content

    @property
    def text(self) -> str:
        return self._response.text

    @property
    def history(self) -> list:
        return list(self._response.history)

    @property
    def url(self) -> str:
        return str(self._response.request.url)

    def json(self, **kwargs: Any) -> Any:
        return self._response.json(**kwargs)

    def raise_for_status(self) -> None:
        self._response.raise_for_status()


def _patch_curl_session(monkeypatch: Any, router: MockRouter) -> None:
    """Sustituye curl_cffi AsyncSession por una sesión en memoria del router."""

    class _FakeAsyncSession:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._proxy = kwargs.get("proxy")
            self._impersonate = kwargs.get("impersonate")

        async def __aenter__(self) -> _FakeAsyncSession:
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        def _request(self, method: str, url: str, **kwargs: Any) -> Any:
            content = kwargs.get("content")
            data = kwargs.get("data")
            if data is not None and content is None:
                if isinstance(data, dict):
                    content = urlencode(data).encode()
                elif isinstance(data, str):
                    content = data.encode()
                else:
                    content = data
            request = httpx.Request(
                method, url, content=content, headers=kwargs.get("headers") or {}
            )
            return _MockCurlResponse(router.handler(request))

        async def get(self, url: str, **kwargs: Any) -> Any:
            kwargs.pop("stream", None)
            kwargs.pop("allow_redirects", None)
            return self._request("GET", url, **kwargs)

        async def post(self, url: str, **kwargs: Any) -> Any:
            return self._request("POST", url, **kwargs)

        async def request(self, method: str, url: str, **kwargs: Any) -> Any:
            return self._request(method, url, **kwargs)

    try:
        import curl_cffi.requests as curl_requests

        monkeypatch.setattr(curl_requests, "AsyncSession", _FakeAsyncSession)
    except ImportError:  # pragma: no cover - curl_cffi siempre presente en dev
        pass
    # El kernel importa el nombre directamente (`from curl_cffi.requests import
    # AsyncSession`): parchear también el módulo que lo consume.
    try:
        import specter.httpx_transport as transport_module

        monkeypatch.setattr(transport_module, "AsyncSession", _FakeAsyncSession)
    except ImportError:  # pragma: no cover
        pass


def patch_dns(monkeypatch: Any, zone: dict[str, Any] | None = None) -> FakeDNS:
    """Sustituye `dns.resolver.Resolver` por una zona en memoria."""
    fake = FakeDNS(zone)

    class _FakeResolver:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.timeout = 3.0
            self.lifetime = 3.0

        def resolve(self, name: Any, rdtype: str = "A", **kwargs: Any) -> list[_FakeAnswer]:
            return fake.resolve(name, rdtype, **kwargs)

    monkeypatch.setattr(dns.resolver, "Resolver", _FakeResolver)
    return fake


def patch_network(
    monkeypatch: Any, router: MockRouter | None = None, zone: dict[str, Any] | None = None
) -> tuple[MockRouter, FakeDNS]:
    """Aísla ambos canales de red (HTTP y DNS) de una vez."""
    router = router or MockRouter()
    return patch_httpx(monkeypatch, router), patch_dns(monkeypatch, zone)

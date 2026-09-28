"""
SpecterOSINT - Transporte HTTP con impersonación TLS (P0 anti-fingerprinting).

Problema: httpx sobre OpenSSL produce un ClientHello (huella JA4/JA3) de
Python, delatado en milisegundos por Cloudflare/DataDome/Akamai aunque las
cabeceras digan "Chrome". Solución: `curl_cffi`, que replica byte a byte el
handshake TLS y los frames HTTP/2 de navegadores reales (BoringSSL).

Todos los colectores del kernel importan `http_get`/`http_stream` de aquí.
En tests (`tests/http_mock.py`) `curl_cffi.AsyncSession` se parchea con el
arnés en memoria, así que la suite sigue sin red real.

La impersonación es una técnica defensiva de igualación de huellas para
recolección en fuentes abiertas: el tráfico sigue siendo el de un cliente
HTTP normal, sólo deja de mentir sobre su pila criptográfica real.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import random
from collections.abc import AsyncIterator
from typing import Any

from curl_cffi import CurlError
from curl_cffi.requests import AsyncSession

logger = logging.getLogger("specter.transport")

# Chrome estable cuyas suites TLS/ALPN/frames soporta curl_cffi 0.16+.
IMPERSONATE_TARGET = "chrome131"

_TIMEOUT_DEFAULT = 12.0
_RETRIES = 2


class TransportError(RuntimeError):
    """Fallo de transporte HTTP tras reintentos (red, DNS, TLS, timeouts)."""


def _proxy() -> str | None:
    """Egress para esta petición: pool rotativo (P2) → env individual → None.

    El pool (SPECTER_PROXY_POOL) reparte la campaña entre salidas distintas
    (idealmente residenciales/móviles) y pone en cuarentena las que fallan;
    sin pool, cae al proxy único del entorno o a la salida directa.
    """
    from specter.osint_core.tempo import next_proxy

    pooled = next_proxy()
    if pooled:
        return pooled
    for var in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"):
        value = os.environ.get(var)
        if value:
            return value
    return None


async def http_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = _TIMEOUT_DEFAULT,
    follow_redirects: bool = True,
    impersonate: str | None = IMPERSONATE_TARGET,
) -> Any:
    """GET con huella TLS de Chrome y reintentos exponenciales con jitter.

    El objeto de respuesta imita la superficie de httpx usada por el kernel
    (status_code, headers, content, text, history, json(), raise_for_status()).
    """
    proxy = _proxy()
    delays = [0.0, 0.7, 1.8][: _RETRIES + 1]
    last: Exception | None = None
    for attempt, base_delay in enumerate(delays):
        if base_delay:
            await asyncio.sleep(base_delay + random.uniform(0.0, 0.4))
        try:
            async with AsyncSession(impersonate=impersonate, proxy=proxy) as session:
                return await session.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=follow_redirects,
                )
        except CurlError as exc:
            last = exc
            logger.debug("transport: intento %d falló para %s: %s", attempt + 1, url, exc)
    raise TransportError(f"GET {url}: {last}") from last


async def http_post(
    url: str,
    *,
    data: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = _TIMEOUT_DEFAULT,
    impersonate: str | None = IMPERSONATE_TARGET,
) -> Any:
    """POST form/JSON con impersonación TLS (DDG HTML, webhooks, oráculos)."""
    proxy = _proxy()
    try:
        async with AsyncSession(impersonate=impersonate, proxy=proxy) as session:
            return await session.post(url, data=data, headers=headers, timeout=timeout)
    except CurlError as exc:
        raise TransportError(f"POST {url}: {exc}") from exc


async def http_stream(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    max_bytes: int = 25 * 1024 * 1024,
    impersonate: str | None = IMPERSONATE_TARGET,
) -> AsyncIterator[bytes]:
    """Streaming por chunks con impersonación TLS (medios, descargas grandes)."""
    proxy = _proxy()
    try:
        session = AsyncSession(impersonate=impersonate, proxy=proxy)
    except CurlError as exc:
        raise TransportError(f"stream {url}: {exc}") from exc
    received = 0
    try:
        response = await session.get(url, headers=headers, timeout=timeout, stream=True)
        response.raise_for_status()
        async for chunk in response.aiter_content():
            received += len(chunk)
            if received > max_bytes:
                raise TransportError(f"stream {url}: superado el límite de {max_bytes} bytes")
            yield chunk
    except CurlError as exc:
        raise TransportError(f"stream {url}: {exc}") from exc
    finally:
        with _closing(session):
            pass


class _closing:
    """contextlib.suppress-style para el cierre del session de curl_cffi."""

    def __init__(self, session: Any) -> None:
        self._session = session

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: Any) -> None:
        with contextlib.suppress(Exception):  # cierre best-effort
            self._session.close()

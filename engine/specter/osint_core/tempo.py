"""
SpecterOSINT - Ritmo de recolección (jitter anti-bloqueo + proxies).

- jitter_sleep: pausas gaussianas entre ráfagas (nada de intervalos fijos,
  que delatan automatización ante WAF/rate-limits).
- proxy_configured: httpx ya respeta HTTP(S)_PROXY/ALL_PROXY por defecto
  (trust_env); aquí se documenta y verifica, para aislar la egress del
  analista (residencial/móvil) sin tocar el código de cada colector.
- ProxyRotator: pool rotativo round-robin con cuarentena de fallos. El pool
  se define con SPECTER_PROXY_POOL (lista separada por comas de URLs de
  proxy http/socks5); sin pool, el egress cae al proxy individual del
  entorno (si existe) o a la salida directa del analista.
"""

from __future__ import annotations

import asyncio
import os
import random
import time


async def jitter_sleep(base_seconds: float, spread: float = 0.5) -> float:
    """Duerme un lapso gaussiano ~N(base, spread), mínimo 0.1s. Devuelve el lapso."""
    delay = max(0.1, random.gauss(base_seconds, spread))
    await asyncio.sleep(delay)
    return delay


def proxy_configured() -> dict[str, str]:
    """Proxies de egress detectados en el entorno (httpx los aplica solo)."""
    found = {}
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        value = os.environ.get(var)
        if value:
            found[var] = value
    return found


# --------------------------------------------------------------------------- #
# Pool rotativo de proxies (P2)                                               #
# --------------------------------------------------------------------------- #

PROXY_POOL_ENV = "SPECTER_PROXY_POOL"
QUARANTINE_SECONDS = 300.0
MAX_FAILURES_BEFORE_QUARANTINE = 3


class ProxyRotator:
    """Round-robin con cuarentena temporal de proxies que fallan.

    Los WAF bloquean por reputación de ASN: rotar la salida (idealmente
    residencial o móvil CGNAT) evita que un solo IP cargue toda la campaña.
    Los proxies en cuarentena vuelven tras QUARANTINE_SECONDS (el fallo pudo
    ser transitorio). Estado en memoria del proceso: al reiniciar el engine,
    todos los proxies vuelven a estar habilitados.
    """

    def __init__(self, pool: list[str] | None = None) -> None:
        self._pool = list(pool or [])
        self._index = 0
        self._failures: dict[str, int] = {}
        self._quarantined_until: dict[str, float] = {}

    @staticmethod
    def from_env() -> ProxyRotator:
        raw = os.environ.get(PROXY_POOL_ENV, "")
        pool = [item.strip() for item in raw.split(",") if item.strip()]
        return ProxyRotator(pool)

    def __len__(self) -> int:
        return len(self._pool)

    @property
    def pool(self) -> list[str]:
        return list(self._pool)

    def _available(self) -> list[str]:
        now = time.monotonic()
        return [proxy for proxy in self._pool if self._quarantined_until.get(proxy, 0.0) <= now]

    def next(self) -> str | None:
        """Siguiente proxy disponible (round-robin); None si no hay pool."""
        available = self._available()
        if not available:
            # Pool vacío o todo en cuarentena: si TODO está penado, lo
            # reintentamos (mejor un proxy penado que salida directa expuesta).
            if self._pool and not self._available():
                self._quarantined_until.clear()
                available = list(self._pool)
            else:
                return None
        proxy = available[self._index % len(available)]
        self._index += 1
        return proxy

    def mark_failure(self, proxy: str) -> None:
        self._failures[proxy] = self._failures.get(proxy, 0) + 1
        if self._failures[proxy] >= MAX_FAILURES_BEFORE_QUARANTINE:
            self._quarantined_until[proxy] = time.monotonic() + QUARANTINE_SECONDS

    def mark_success(self, proxy: str) -> None:
        self._failures[proxy] = 0
        self._quarantined_until.pop(proxy, None)

    def status(self) -> dict[str, object]:
        now = time.monotonic()
        return {
            "pool_size": len(self._pool),
            "available": len(self._available()),
            "quarantined": sorted(
                proxy for proxy, until in self._quarantined_until.items() if until > now
            ),
            "failures": dict(self._failures),
        }


_rotator: ProxyRotator | None = None


def get_proxy_rotator() -> ProxyRotator:
    """Rotador del proceso (se relee el env en cada creación de tests)."""
    global _rotator
    if _rotator is None:
        _rotator = ProxyRotator.from_env()
    return _rotator


def reset_proxy_rotator() -> None:
    global _rotator
    _rotator = None


def next_proxy() -> str | None:
    """Proxy de salida para esta petición: pool rotativo → env individual → None."""
    return get_proxy_rotator().next()

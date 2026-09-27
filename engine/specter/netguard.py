"""
SpecterOSINT - NetGuard: validador SSRF central para salidas a red.

Todo colector que descargue una URL controlada por el analista/LLM debe pasar
por `check_public_http_url` antes de tocar la red. Bloquea loopback, red
privada, link-local (169.254.x.x: metadatos cloud), multicast, reservadas y
URLs con credenciales embebidas.

Fail-closed: si el DNS no resuelve, se deniega (TOCTOU de DNS-rebinding
documentado como riesgo residual aceptado para una estación local).

`SPECTER_SSRF_ENFORCE=0` lo desactiva (solo tests con red mockeada; en
producción siempre va a "1").
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


def ssrf_enforce() -> bool:
    """¿Aplica el guard? Env `SPECTER_SSRF_ENFORCE`, "1" por defecto."""
    return os.environ.get("SPECTER_SSRF_ENFORCE", "1") == "1"


def _resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"No se pudo resolver {host!r}: {exc}") from exc
    return sorted({info[4][0] for info in infos})


def check_public_http_url(url: str) -> str | None:
    """Valida una URL de salida. Devuelve None si es segura, o el motivo.

    No toca la red salvo la resolución DNS (necesaria para pillar
    dominios que apuntan a IPs privadas).
    """
    url = (url or "").strip()
    try:
        parts = urlparse(url)
    except ValueError as exc:
        return f"URL inválida: {exc}"
    if parts.scheme.lower() not in ("http", "https"):
        return "Sólo se permite http(s)"
    if not parts.hostname:
        return "Sin host"
    if parts.username or parts.password:
        return "Credenciales embebidas en la URL"
    host = parts.hostname
    try:
        ip = ipaddress.ip_address(host)
        ips = [str(ip)]
    except ValueError:
        try:
            ips = _resolve_ips(host)
        except ValueError as exc:
            return str(exc)
    for ip_str in ips:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return f"IP irresoluble: {ip_str}"
        if not addr.is_global:
            return f"Host no público ({host} -> {ip_str})"
    return None


def assert_public_http_url(url: str) -> None:
    """Versión que lanza ValueError (para navegadores que usan excepciones)."""
    if not ssrf_enforce():
        return
    reason = check_public_http_url(url)
    if reason is not None:
        raise ValueError(f"URL bloqueada por NetGuard: {reason}: {url}")

"""
WraithOSINT - Capa OSINT sobre el navegador sigiloso.

Convierte las operaciones del navegador (`stealth_browser`) en herramientas
forenses de primera clase. Lo que la CLI de DevTools de Google (chrome-devtools
mcp) hace por debugging genérico, aquí se hace orientado a investigación:

  1. CADA captura se registra en el ledger por caso con hash y, si hay clave,
     HMAC. El verificador necesita la clave compartida; esto no es una firma
     pública ni certifica por sí solo la admisibilidad de la evidencia.
  2. El contenido extraído pasa por el parser de entidades del kernel: los
     datos no solo vuelven al agente, entran al grafo del caso.
  3. La capa anti-bot es explícita y consultable: detección de bloqueo
     (CAPTCHA/WAF), rotación de huella y navegación con ritmo humano.

Las tools MCP se exponen en `server.py` vía las funciones públicas de este
módulo, manteniendo ese archivo como catálogo y éste como implementación.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from specter.osint_core.ledger import ForensicLedger
from specter.osint_core.models import RawEvidence
from specter.stealth_browser import get_browser as _get_browser

# Alias de módulo: permite mockear `browser_osint.get_browser` en tests.
get_browser = _get_browser

logger = logging.getLogger("specter.browser_osint")

# Acciones de interacción permitidas (whitelist: el agente no inventa verbos).
_ALLOWED_ACTIONS = {"click", "fill", "press", "wait", "scroll"}


def _ledger() -> ForensicLedger:
    """Ledger del proceso (import perezoso para no tocar DB al importar)."""
    from specter.server import ledger

    return ledger


def _seal_evidence(
    case_id: str | None,
    collector: str,
    action: str,
    source_url: str,
    payload: dict[str, Any],
) -> str | None:
    """Sella el payload como evidencia en el ledger del caso.

    Devuelve el hash del bloque creado, o None si no hay caso (las tools son
    utilizables sin caso: devuelven datos sin custodia, avisando en metadata).
    """
    if not case_id:
        return None
    try:
        ledger = _ledger()
        if not ledger.db.get_case(case_id):
            logger.warning("browser-osint: caso %s no existe; evidencia sin sello", case_id)
            return None
        ev = RawEvidence(
            id=f"ev-web-{uuid.uuid4().hex[:8]}",
            case_id=case_id,
            collector=collector,
            source_url=source_url,
            raw_payload=json.dumps(payload, ensure_ascii=False),
            payload_hash="auto",  # record_evidence_action computa SHA-256 real
            metadata={"sealed_by": "browser_osint"},
        )
        block = ledger.record_evidence_action(case_id, collector, action, ev)
        return block.block_hash
    except Exception as exc:
        # La extracción ya ocurrió: el sello fallido no tumba la respuesta,
        # pero queda registrado para que el analista lo sepa.
        logger.error("browser-osint: no se pudo sellar evidencia (%s): %s", action, exc)
        return None


def _validate_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Valida la whitelist de acciones antes de tocar el navegador."""
    for step in actions or []:
        act = step.get("action")
        if act not in _ALLOWED_ACTIONS:
            raise ValueError(f"Acción {act!r} no permitida. Válidas: {sorted(_ALLOWED_ACTIONS)}")
        if act in {"click", "fill"} and not step.get("selector"):
            raise ValueError(f"Acción {act!r} requiere 'selector'")
        if act == "fill" and "text" not in step:
            raise ValueError("Acción 'fill' requiere 'text'")
    return actions or []


# --------------------------------------------------------------------------
# Funciones expuestas como tools MCP (envueltas en server.py)
# --------------------------------------------------------------------------


async def osint_snapshot(
    url: str,
    case_id: str | None = None,
    timeout: int = 30,
) -> str:
    """Navega a la URL con Chromium sigiloso y extrae título + texto + links.

    Con `case_id`, la captura se sella en la cadena de custodia (bloque HMAC).
    Devuelve también `blocked` si el sitio activó anti-bot, para que el agente
    decida rotar identidad o abandonar.
    """
    browser = await get_browser()
    snap = await browser.navigate_and_snapshot(url, timeout_s=float(timeout))
    block_hash = _seal_evidence(case_id, "browser_osint", f"WEB_SNAPSHOT: {url}", url, snap)
    snap["evidence"] = {"sealed": bool(block_hash), "block_hash": block_hash}
    return json.dumps(snap, indent=2, ensure_ascii=False)


async def osint_screenshot(
    url: str,
    case_id: str | None = None,
    full_page: bool = False,
    timeout: int = 30,
) -> str:
    """Captura PNG de la página (evidencia visual del estado real del sitio).

    Con `case_id`, el PNG se sella en el ledger: el hash SHA-256 del payload
    (imagen incluida) queda en la cadena de custodia. El agente recibe el
    base64 y el hash; la UI puede reproducirlo y un tercero verificarlo.
    """
    browser = await get_browser()
    shot = await browser.screenshot(url=url, full_page=full_page, timeout_s=float(timeout))
    meta = {k: shot[k] for k in ("title", "url", "captured_at", "mime")}
    block_hash = _seal_evidence(
        case_id, "browser_osint", f"WEB_SCREENSHOT: {shot['url']}", shot["url"], meta
    )
    shot["evidence"] = {"sealed": bool(block_hash), "block_hash": block_hash}
    return json.dumps(shot, indent=2, ensure_ascii=False)


async def osint_interact(
    url: str,
    actions: list[dict[str, Any]],
    case_id: str | None = None,
    timeout: int = 30,
) -> str:
    """Ejecuta una secuencia de interacción humana (click/fill/press/wait/scroll)
    y extrae el resultado final.

    Ejemplo de login/búsqueda profunda:
      actions=[
        {"action": "fill", "selector": "input[name=q]", "text": "consulta"},
        {"action": "press", "key": "Enter"},
        {"action": "wait", "ms": 2000}
      ]

    Los pasos se validan contra una whitelist (sin JS arbitrario, sin
    navegaciones anidadas). La extracción final se sella en el ledger si hay caso.
    """
    _validate_actions(actions)
    browser = await get_browser()
    snap = await browser.interact(url, actions, timeout_s=float(timeout))
    block_hash = _seal_evidence(case_id, "browser_osint", f"WEB_INTERACT: {url}", url, snap)
    snap["evidence"] = {"sealed": bool(block_hash), "block_hash": block_hash}
    return json.dumps(snap, indent=2, ensure_ascii=False)


async def osint_rotate_identity() -> str:
    """Rota la identidad del navegador (fingerprint TLS/JS + cookies limpias).

    Úsalo tras un bloqueo detectado (`blocked` en snapshot/screenshot) o entre
    sujetos de investigación que no deben correlationarse por cookies. La nueva
    huella se aplica en la próxima navegación.
    """
    browser = await get_browser()
    fp = browser.rotate_fingerprint()
    await browser.recycle_context()
    return json.dumps(
        {
            "status": "IDENTITY_ROTATED",
            "next_fingerprint": {"locale": fp["locale"], "tz": fp["tz"]},
            "message": "Nueva identidad aplicada: el próximo arranque usará otra huella "
            "de navegador y el contexto (cookies/storage) arranca limpio.",
        },
        indent=2,
    )


async def osint_capture_warc(
    url: str,
    case_id: str | None = None,
    max_resources: int = 80,
    max_body_mb: int = 3,
    timeout: int = 40,
) -> str:
    """Guarda en WARC las solicitudes y respuestas HTTP que Chromium expuso.

    No es captura de paquetes; algunos cuerpos faltan o se truncan y quedan
    indicados en el manifiesto. WARC facilita el replay, pero no certifica la
    cadena de custodia. Con `case_id`, el hash del archivo se registra en el
    ledger local.
    """
    from specter.collectors.warc_capture import capture_warc

    result = await capture_warc(
        url,
        case_id=case_id,
        max_resources=max_resources,
        max_body_bytes=int(max_body_mb * 1024 * 1024),
        timeout_s=float(timeout),
    )
    return json.dumps(result, indent=2, ensure_ascii=False)


async def osint_browser_status() -> str:
    """Estado del navegador sigiloso: huella activa, driver anti-detección y disponibilidad."""
    browser = await get_browser()
    fp = browser.fingerprint
    return json.dumps(
        {
            "engine": "patchright-chromium",
            "anti_detection": {
                "driver": "patchright (CDP-leak free)",
                "fingerprint": fp["label"],
                "user_agent": fp["ua"][:80] + "…",
                "sec_ch_ua": fp["sec_ch_ua"],
                "platform": fp["sec_ch_ua_platform"],
                "locale": fp["locale"],
                "timezone": fp["tz"],
                "viewport": f"{fp['viewport']['width']}x{fp['viewport']['height']}",
                "accept_language": fp["accept_language"],
            },
            "fingerprint_index": browser.fingerprint_index,
            "restarts_recent": len(browser.restart_times),
            "ready": browser.is_ready,
        },
        indent=2,
    )

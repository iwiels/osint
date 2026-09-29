"""
WraithOSINT - Cosechador WARC (archivo web reproducible, ISO 28500).

Una captura WARC conserva las solicitudes y respuestas HTTP observadas por
Chromium para su posterior replay en ReplayWeb.page o pywb. Es un archivo de
preservación útil, pero no equivale a una captura de paquetes: Chromium puede
no exponer ciertos cuerpos, y el manifiesto marca esos recursos incompletos.
El formato WARC no certifica por sí mismo la cadena de custodia ni la
admisibilidad legal; Specter registra el hash del archivo en su ledger local.

Mecánica (sin dependencias nuevas de navegador):
  1. Suscripción a los eventos CDP de red de la página de Playwright/
     patchright (Network.requestWillBeSent / responseReceived /
     loadingFinished / loadingFailed) ANTES de navegar. Los callbacks CDP
     son síncronos: sólo registran metadatos.
  2. Tras la navegación, el cuerpo de cada respuesta se recupera con
     `Network.getResponseBody` (base64 si es binario) desde el contexto async.
  3. Cada par request/response se escribe como registro WARC `response`
     (más `request` con `warc_concurrent_to`) usando `warcio`.
  4. El archivo termina en data_dir/warc/<case>/ y su SHA-256, tamaño y
     conteo de registros se anotan en el ledger local.

Límites operativos (controlan coste y memoria):
  - `max_resources`: nº máximo de recursos capturados (por defecto 80).
  - `max_body_bytes`: cuerpo máximo por recurso (por defecto 3 MiB); los
    cuerpos mayores se registran sin payload (`truncated` en la respuesta).
  - Los cuerpos que CDP no pudo recuperar se marcan como no capturados en el
    registro WARC y se cuentan en el manifiesto.
  - Los esquemas data:/blob: y las peticiones canceladas no se capturan.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import logging
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from specter import config as specter_config
from specter.netguard import assert_public_http_url

logger = logging.getLogger("specter.warc_capture")

DEFAULT_MAX_RESOURCES = 80
DEFAULT_MAX_BODY_BYTES = 3 * 1024 * 1024
HTTP_RECORD_CT = "application/http; msgtype=response"


def _now_warc() -> str:
    """Timestamp WARC (ISO 8601 UTC, 'Z')."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_headers(raw: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in (raw or {}).items()}


class _Resource:
    """Recurso de red observado por CDP (petición + respuesta + cuerpo)."""

    __slots__ = (
        "request_id",
        "url",
        "method",
        "resource_type",
        "request_headers",
        "status",
        "response_headers",
        "mime",
        "body",
        "body_too_large",
        "finished",
        "request_body",
        "redirect",
    )

    def __init__(
        self,
        request_id: str,
        url: str,
        method: str,
        resource_type: str,
        request_headers: dict[str, str],
    ) -> None:
        self.request_id = request_id
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.request_headers = request_headers
        self.status = 0
        self.response_headers: dict[str, str] = {}
        self.mime = ""
        self.body: bytes | None = None
        self.body_too_large = False
        self.finished = False
        self.request_body: str | None = None
        self.redirect = False


class _suppress:
    """contextlib.suppress(Exception) minimal (cierre best-effort)."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: Any) -> None:
        return None


class WarcCapture:
    """Cosecha el tráfico de red de UNA navegación como archivo WARC (ISO 28500).

    Uso:
        capture = WarcCapture(page)
        await capture.attach()
        await page.goto(url)
        await capture.fetch_bodies()
        result = capture.finalize()  # bytes del WARC + manifiesto
    """

    def __init__(
        self,
        page: Any,
        max_resources: int = DEFAULT_MAX_RESOURCES,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ) -> None:
        self._page = page
        self._max_resources = max(1, int(max_resources))
        self._max_body_bytes = max(1024, int(max_body_bytes))
        self._resources: dict[str, _Resource] = {}
        self._order: list[str] = []
        self._current_resource: dict[str, str] = {}
        self._redirect_counts: dict[str, int] = {}
        self._failed: list[dict[str, str]] = []
        self._cdp: Any = None
        self._subscriptions: list[tuple[str, Any]] = []

    # ------------------------------------------------------------------ CDP
    async def attach(self) -> None:
        """Suscribe los eventos de red ANTES de navegar (nada se pierde)."""
        cdp = await self._page.context.new_cdp_session(self._page)
        self._cdp = cdp
        await cdp.send("Network.enable", {"maxPostDataSize": 1_000_000})
        self._subscriptions = [
            ("Network.requestWillBeSent", self._on_request),
            ("Network.responseReceived", self._on_response),
            ("Network.loadingFinished", self._on_finished),
            ("Network.loadingFailed", self._on_failed),
        ]
        for event, handler in self._subscriptions:
            cdp.on(event, handler)

    # Callbacks CDP síncronos: sólo libro de metadatos, nada de awaits.
    def _on_request(self, event: dict[str, Any]) -> None:
        request_id = str(event.get("requestId", ""))
        request = event.get("request") or {}
        url = str(request.get("url", ""))
        if not url.startswith("http"):
            return  # data:/blob:/devtools: no son evidencia de red
        previous_key = self._current_resource.get(request_id)
        redirect_response = event.get("redirectResponse")
        if previous_key and redirect_response:
            previous = self._resources[previous_key]
            previous.status = int(redirect_response.get("status", 0) or 0)
            previous.response_headers = _clean_headers(redirect_response.get("headers"))
            previous.mime = str(redirect_response.get("mimeType", ""))
            previous.finished = True
            previous.redirect = True
            self._redirect_counts[request_id] = self._redirect_counts.get(request_id, 0) + 1
        elif previous_key:
            return
        if len(self._resources) >= self._max_resources:
            self._current_resource.pop(request_id, None)
            return
        hop = self._redirect_counts.get(request_id, 0)
        resource_key = f"{request_id}:{hop}"
        resource = _Resource(
            request_id=request_id,
            url=url,
            method=str(request.get("method", "GET")),
            resource_type=str(event.get("type", "") or ""),
            request_headers=_clean_headers(request.get("headers")),
        )
        post_data = request.get("postData")
        if post_data:
            resource.request_body = str(post_data)[:1_000_000]
        self._resources[resource_key] = resource
        self._current_resource[request_id] = resource_key
        self._order.append(resource_key)

    def _on_response(self, event: dict[str, Any]) -> None:
        resource_key = self._current_resource.get(str(event.get("requestId", "")))
        resource = self._resources.get(resource_key) if resource_key else None
        if resource is None:
            return
        response = event.get("response") or {}
        resource.status = int(response.get("status", 0) or 0)
        resource.response_headers = _clean_headers(response.get("headers"))
        resource.mime = str(response.get("mimeType", ""))

    def _on_finished(self, event: dict[str, Any]) -> None:
        resource_key = self._current_resource.get(str(event.get("requestId", "")))
        resource = self._resources.get(resource_key) if resource_key else None
        if resource is not None:
            resource.finished = True

    def _on_failed(self, event: dict[str, Any]) -> None:
        request_id = str(event.get("requestId", ""))
        resource_key = self._current_resource.get(request_id)
        resource = self._resources.get(resource_key) if resource_key else None
        if resource is not None:
            self._failed.append(
                {"url": resource.url, "error": str(event.get("errorText", "unknown"))}
            )

    # ------------------------------------------------- cuerpos (contexto async)
    async def fetch_bodies(self, settle_seconds: float = 1.5) -> int:
        """Recupera los cuerpos de las respuestas terminadas vía CDP.

        Se llama tras la navegación (con un settle humano): los eventos ya
        depositaron los metadatos y la sesión CDP sigue abierta.
        """
        await asyncio.sleep(max(0.0, settle_seconds))
        fetched = 0
        for request_id in self._order:
            resource = self._resources[request_id]
            if (
                resource.status <= 0
                or not resource.finished
                or resource.body is not None
                or resource.redirect
            ):
                continue
            try:
                result = await self._cdp.send(
                    "Network.getResponseBody", {"requestId": resource.request_id}
                )
            except Exception:  # noqa: BLE001 - 204/304/redirects no traen cuerpo
                continue
            raw = result.get("body")
            if raw is None:
                continue
            if result.get("base64Encoded"):
                try:
                    data = base64.b64decode(raw)
                except Exception:  # noqa: BLE001 - cuerpo corrupto: se registra vacío
                    continue
            else:
                data = str(raw).encode("utf-8", "replace")
            if len(data) > self._max_body_bytes:
                resource.body_too_large = True
                continue
            resource.body = data
            fetched += 1
        return fetched

    async def close(self) -> None:
        """Desuscribe los handlers de CDP (la página sigue utilizable)."""
        for event, handler in self._subscriptions:
            with _suppress():
                self._cdp.remove_listener(event, handler)
        self._subscriptions = []
        with _suppress():
            await self._cdp.detach()

    # -------------------------------------------------------------- finalizar
    def finalize(self) -> dict[str, Any]:
        """Escribe el WARC en memoria y devuelve {content, sha256, manifest}."""
        from warcio.statusandheaders import StatusAndHeaders
        from warcio.warcwriter import WARCWriter

        buffer = io.BytesIO()
        writer = WARCWriter(buffer, gzip=True)
        info = writer.create_warcinfo_record(
            "wraith-osint.warc",
            {
                "software": "WraithOSINT engine (warcio + Chromium CDP)",
                "format": "WARC file version 1.1",
                "created": _now_warc(),
            },
        )
        writer.write_record(info)

        captured = 0
        captured_bytes = 0
        skipped = 0
        bodies_missing = 0
        bodies_truncated = 0
        for request_id in self._order:
            resource = self._resources[request_id]
            if resource.status <= 0:
                skipped += 1
                continue
            status_text = resource.response_headers.get("status-text", "")
            http_headers = StatusAndHeaders(
                f"{resource.status} {status_text}".strip(),
                list(resource.response_headers.items()),
                protocol="HTTP/1.1",
            )
            body_captured = resource.body is not None
            body_expected = (
                resource.method.upper() != "HEAD"
                and resource.status not in {204, 205, 304}
                and not 100 <= resource.status < 200
            )
            if body_expected and not body_captured and not resource.body_too_large:
                bodies_missing += 1
            if resource.body_too_large:
                bodies_truncated += 1
            body = resource.body if body_captured else b""
            payload = io.BytesIO(body)
            response_record = writer.create_warc_record(
                resource.url,
                "response",
                payload=payload,
                http_headers=http_headers,
                warc_headers_dict={
                    "X-Specter-Resource-Type": resource.resource_type or "other",
                    "X-Specter-Body-Truncated": "1" if resource.body_too_large else "0",
                    "X-Specter-Body-Captured": "1" if body_captured else "0",
                    "X-Specter-Body-Expected": "1" if body_expected else "0",
                    "X-Specter-Mime": resource.mime or "application/octet-stream",
                },
            )
            request_line = f"{resource.method} {urlparse(resource.url).path or '/'} HTTP/1.1"
            request_http = StatusAndHeaders(
                request_line, list(resource.request_headers.items()), is_http_request=True
            )
            request_payload = (
                io.BytesIO(resource.request_body.encode("utf-8"))
                if resource.request_body
                else io.BytesIO(b"")
            )
            request_record = writer.create_warc_record(
                resource.url,
                "request",
                payload=request_payload,
                http_headers=request_http,
                warc_headers_dict={
                    "WARC-Concurrent-To": (
                        response_record.rec_headers.get_header("WARC-Record-ID") or ""
                    )
                },
            )
            writer.write_record(response_record)
            writer.write_record(request_record)
            captured += 1
            captured_bytes += len(body)

        content = buffer.getvalue()
        sha256 = hashlib.sha256(content).hexdigest()
        manifest = {
            "captured_at": _now_warc(),
            "records": captured,
            "skipped": skipped,
            "failed": len(self._failed),
            "bodies_missing": bodies_missing,
            "bodies_truncated": bodies_truncated,
            "payload_bytes": captured_bytes,
            "warc_bytes": len(content),
            "sha256": sha256,
            "failed_requests": self._failed[:20],
        }
        return {"content": content, "sha256": sha256, "manifest": manifest}


def warc_store_path(case_id: str, url: str, captured_at: str) -> Path:
    """Ruta canónica: data/warc/<case>/<host>/<timestamp>__<slug>.warc.gz."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", case_id) or case_id in {".", ".."}:
        raise ValueError("Identificador de caso inválido para almacenar WARC")
    host = re.sub(r"[^a-zA-Z0-9.-]+", "-", urlparse(url).netloc).strip(".-") or "sin-host"
    slug = re.sub(r"[^a-z0-9]+", "-", urlparse(url).path.lower()).strip("-")[:40] or "root"
    stamp = re.sub(r"[^0-9TZ-]", "-", captured_at)
    root = (specter_config.data_dir() / "warc").resolve()
    directory = (root / case_id / host).resolve()
    if not directory.is_relative_to(root):
        raise ValueError("Ruta WARC fuera del directorio de evidencia")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{stamp}__{slug}__{uuid.uuid4().hex[:8]}.warc.gz"


async def capture_warc(
    url: str,
    case_id: str | None = None,
    max_resources: int = DEFAULT_MAX_RESOURCES,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    timeout_s: float = 40.0,
) -> dict[str, Any]:
    """Navega con el Chromium sigiloso y cosecha el tráfico completo como WARC.

    NetGuard aplica (sólo http(s) público). El WARC se guarda en disco y, si
    hay `case_id`, se sella en el ledger (SHA-256 del archivo completo).
    """
    assert_public_http_url(url)  # C2: sin loopback/privada/link-local
    if case_id:
        from specter.server import db

        if not db.get_case(case_id):
            raise ValueError(f"Caso {case_id} no existe")
    from specter.stealth_browser import get_browser

    browser = await get_browser()
    # Acceso a la sesión interna del singleton: el navegador ya trae su capa
    # anti-detección; aquí sólo añadimos la observación de red.
    await browser._ensure()
    page = await browser._context.new_page()
    capture = WarcCapture(page, max_resources=max_resources, max_body_bytes=max_body_bytes)
    try:
        await capture.attach()
        response = await page.goto(
            url, timeout=int(timeout_s * 1000), wait_until="domcontentloaded"
        )
        await browser._settle_like_human(page)
        await capture.fetch_bodies()
        finalized = capture.finalize()
    finally:
        await capture.close()
        with _suppress():
            await page.close()

    http_status = response.status if response else 0
    target_path: Path | None = None
    if finalized["manifest"]["records"] > 0:
        target_path = warc_store_path(
            case_id or "sin-caso", url, finalized["manifest"]["captured_at"]
        )
        target_path.write_bytes(finalized["content"])

    block_hash = None
    if case_id and target_path is not None:
        block_hash = _seal_warc(case_id, url, target_path, finalized)

    return {
        "url": url,
        "http_status": http_status,
        "warc_path": str(target_path) if target_path else None,
        "sha256": finalized["sha256"],
        "manifest": finalized["manifest"],
        "evidence": {"sealed": bool(block_hash), "block_hash": block_hash},
        "replay_hint": "ReplayWeb.page (https://replayweb.page) reproduce este .warc.gz sin servidor",
    }


def _seal_warc(case_id: str, url: str, path: Path | None, finalized: dict[str, Any]) -> str | None:
    """Sella el WARC en el ledger del caso (hash del archivo completo)."""
    try:
        from specter.osint_core.models import RawEvidence
        from specter.server import ledger

        if not ledger.db.get_case(case_id):
            logger.warning("warc-capture: caso %s no existe; evidencia sin sello", case_id)
            return None
        payload = {
            "evidence_type": "WARC_CAPTURE",
            "url": url,
            "warc_path": str(path) if path else None,
            "sha256": finalized["sha256"],
            "manifest": finalized["manifest"],
            "standard": "ISO 28500 (WARC 1.1), gzip",
        }
        ev = RawEvidence(
            id=f"ev-warc-{uuid.uuid4().hex[:10]}",
            case_id=case_id,
            collector="browser_osint",
            source_url=url,
            raw_payload=json.dumps(payload, ensure_ascii=False),
            payload_hash="auto",
            metadata={"sealed_by": "warc_capture", "sha256": finalized["sha256"]},
        )
        block = ledger.record_evidence_action(case_id, "browser_osint", f"WARC_CAPTURE: {url}", ev)
        return block.block_hash
    except Exception as exc:  # noqa: BLE001 - el sello no tumba la captura ya tomada
        logger.error("warc-capture: no se pudo sellar en el ledger: %s", exc)
        return None

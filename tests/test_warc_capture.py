"""
Tests del cosechador WARC (P0 preservación forense).

Sin navegador real: los recursos CDP se inyectan a mano y el contenedor se
valida con el propio warcio (ArchiveIterator), que es el mismo parser que
usan pywb/ReplayWeb.page del otro lado.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json

import pytest
from specter.collectors.warc_capture import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_MAX_RESOURCES,
    WarcCapture,
    _Resource,
    warc_store_path,
)
from warcio.archiveiterator import ArchiveIterator

pytestmark = pytest.mark.asyncio


def _inject(
    capture: WarcCapture,
    url: str,
    *,
    status: int = 200,
    body: bytes | None = b"hola",
    finished: bool = True,
    method: str = "GET",
    request_body: str | None = None,
    response_headers: dict[str, str] | None = None,
) -> _Resource:
    """Simula el ciclo CDP request→response→finished para un recurso."""
    if len(capture._order) >= capture._max_resources:
        raise AssertionError("_inject superó max_resources")
    rid = f"rid-{len(capture._order) + 1}"
    capture._on_request(
        {
            "requestId": rid,
            "type": "Document",
            "request": {
                "url": url,
                "method": method,
                "headers": {"User-Agent": "specter-test"},
                **({"postData": request_body} if request_body else {}),
            },
        }
    )
    capture._on_response(
        {
            "requestId": rid,
            "response": {
                "url": url,
                "status": status,
                "mimeType": "text/html",
                "headers": response_headers or {"Content-Type": "text/html"},
            },
        }
    )
    if finished:
        capture._on_finished({"requestId": rid})
    resource = capture._resources[capture._current_resource[rid]]
    # Los cuerpos se recuperan post-navegación vía getResponseBody: en tests se
    # inyectan directamente (el flujo fetch_bodies se ejercita aparte).
    if body is not None and finished and status > 0:
        if len(body) <= capture._max_body_bytes:
            resource.body = body
        else:
            resource.body_too_large = True
    return resource


async def test_ciclo_cdp_registra_metadatos() -> None:
    capture = WarcCapture(None)  # sin página: sólo callbacks + finalize

    resource = _inject(capture, "https://ejemplo.test/", body=b"<html>ok</html>")

    assert resource.status == 200
    assert resource.request_headers["User-Agent"] == "specter-test"
    assert capture._order == [capture._current_resource[resource.request_id]]

    # Recurso sin respuesta (petición huérfana): se ignora al finalizar.
    capture._on_request(
        {
            "requestId": "rid-huerfana",
            "request": {"url": "https://ejemplo.test/x", "method": "GET", "headers": {}},
        }
    )
    result = capture.finalize()
    assert result["manifest"]["records"] == 1
    assert result["manifest"]["skipped"] == 1


async def test_finalize_produce_warc_valido_y_sha256() -> None:
    capture = WarcCapture(None)
    _inject(capture, "https://ejemplo.test/", body=b"<html>portada</html>")
    _inject(
        capture,
        "https://api.ejemplo.test/v1/datos",
        status=200,
        body=b'{"ok": true}',
        method="POST",
        request_body="q=1",
        response_headers={"Content-Type": "application/json"},
    )

    result = capture.finalize()

    assert result["manifest"]["records"] == 2
    assert result["manifest"]["payload_bytes"] == len(b"<html>portada</html>") + len(
        b'{"ok": true}'
    )
    assert result["sha256"] == hashlib.sha256(result["content"]).hexdigest()

    # Una sola pasada: content_stream() se agota con el iterador.
    parsed = []
    for record in ArchiveIterator(io.BytesIO(result["content"])):
        parsed.append(
            {
                "type": record.rec_type,
                "uri": record.rec_headers.get_header("WARC-Target-URI"),
                "status": record.http_headers.get_statuscode() if record.http_headers else None,
                "body": record.content_stream().read(),
                "resource_type": record.rec_headers.get_header("X-Specter-Resource-Type"),
            }
        )
    types = [p["type"] for p in parsed]
    # 1 warcinfo + (response + request) por cada recurso
    assert types.count("warcinfo") == 1
    assert types.count("response") == 2
    assert types.count("request") == 2

    first_response = parsed[1]
    assert first_response["uri"] == "https://ejemplo.test/"
    assert first_response["status"] == "200"
    assert first_response["body"] == b"<html>portada</html>"
    assert first_response["resource_type"] == "Document"

    # La petición POST lleva su cuerpo.
    assert parsed[4]["type"] == "request"
    assert parsed[4]["body"] == b"q=1"


async def test_cuerpo_demasiado_grande_queda_truncado() -> None:
    capture = WarcCapture(None, max_body_bytes=1024)
    _inject(capture, "https://ejemplo.test/video", body=b"x" * 4096)

    result = capture.finalize()

    assert result["manifest"]["records"] == 1
    assert result["manifest"]["payload_bytes"] == 0  # el cuerpo no viaja
    response = next(
        r for r in ArchiveIterator(io.BytesIO(result["content"])) if r.rec_type == "response"
    )
    assert response.rec_headers.get_header("X-Specter-Body-Truncated") == "1"


async def test_failed_requests_se_registran() -> None:
    capture = WarcCapture(None)
    _inject(capture, "https://ejemplo.test/", body=b"ok")
    capture._on_request(
        {
            "requestId": "rid-rota",
            "request": {"url": "https://cdn.ejemplo.test/js", "method": "GET", "headers": {}},
        }
    )
    capture._on_response(
        {
            "requestId": "rid-rota",
            "response": {"url": "https://cdn.ejemplo.test/js", "status": 200, "headers": {}},
        }
    )
    capture._on_failed({"requestId": "rid-rota", "errorText": "net::ERR_ABORTED"})

    result = capture.finalize()
    assert result["manifest"]["failed"] == 1
    assert result["manifest"]["failed_requests"][0]["url"] == "https://cdn.ejemplo.test/js"


def test_warc_store_path_estructura_canonica(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "data"))
    path = warc_store_path(
        "case-x", "https://Docs.Ejemplo.test/Ruta/Pagina?w=1", "2026-09-27T10:00:00Z"
    )
    rel = path.relative_to(tmp_path / "data" / "warc" / "case-x")
    parts = rel.parts
    assert parts[0] == "Docs.Ejemplo.test"
    assert parts[1].startswith("2026-09-27T10-00-00Z__")
    assert parts[1].endswith(".warc.gz")


async def test_seal_warc_en_ledger_verificable(engine_env) -> None:
    """El sello del WARC queda en el ledger y la cadena sigue verificable."""
    import specter.server as server
    from specter.collectors import warc_capture as wc

    case_id = json.loads(server.create_case("Caso WARC", "d"))["case_id"]

    content = b"warc-sintetico-para-sello"
    finalized = {
        "content": content,
        "sha256": hashlib.sha256(content).hexdigest(),
        "manifest": {
            "captured_at": "2026-09-27T10:00:00Z",
            "records": 3,
            "skipped": 0,
            "failed": 0,
            "payload_bytes": len(content),
            "warc_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "failed_requests": [],
        },
    }
    path = warc_store_path(case_id, "https://ejemplo.test/", finalized["manifest"]["captured_at"])
    path.write_bytes(finalized["content"])

    block_hash = wc._seal_warc(case_id, "https://ejemplo.test/", path, finalized)

    assert block_hash
    audit = server.ledger.verify_case_integrity(case_id)
    assert audit["valid"] is True

    # El hash sellado coincide con el archivo en disco.
    evidence = server.db.get_evidence(server.db.get_case_ledger(case_id)[-1].evidence_id)
    payload = json.loads(evidence.raw_payload)
    assert payload["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


async def test_seal_warc_caso_inexistente_devuelve_none(engine_env) -> None:
    from specter.collectors import warc_capture as wc

    finalized = {"content": b"x", "sha256": "0" * 64, "manifest": {"records": 0}}
    assert wc._seal_warc("case-nope", "https://ejemplo.test/", None, finalized) is None


async def test_fetch_bodies_recupera_cuerpos_base64() -> None:
    """La fase post-navegación recupera cuerpos vía Network.getResponseBody."""

    class _FakeCdp:
        def __init__(self) -> None:
            self.methods: list[str] = []

        async def send(self, method: str, params: dict) -> dict:
            self.methods.append(method)
            return {"body": base64.b64encode(b"datos-binarios").decode(), "base64Encoded": True}

    capture = WarcCapture(None)
    fake = _FakeCdp()
    capture._cdp = fake
    _inject(capture, "https://ejemplo.test/img.png", body=None)  # metadatos, sin cuerpo

    fetched = await capture.fetch_bodies(settle_seconds=0)

    assert fetched == 1
    assert fake.methods == ["Network.getResponseBody"]
    assert capture._resources["rid-1:0"].body == b"datos-binarios"


def test_constantes_operativas() -> None:
    assert DEFAULT_MAX_RESOURCES >= 10
    assert DEFAULT_MAX_BODY_BYTES >= 1024 * 1024

"""
Tests del cazador de documentos (DuckDuckGo + forense de artefactos).

El motor de búsqueda está mockeado por consulta: cada query recibe un HTML
distinto, así se cubren las tres estrategias de extracción de enlaces.
"""

from __future__ import annotations

import json
from urllib.parse import quote, unquote

import httpx
from http_mock import MockRouter, patch_httpx
from specter.collectors.dorker import DocumentHunter
from specter.osint_core.models import CollectorResult, EntityNode, EntityType


def _redirect(target: str, css_class: str = "result__snippet", rut: str = "a") -> str:
    """Enlace de DuckDuckGo con el destino escapado en `uddg=` (formato real)."""
    return (
        f'<a class="{css_class}" href="//duckduckgo.com/l/?uddg='
        f'{quote(target, safe="")}&rut={rut}">{target}</a>'
    )


# Dos enlaces al mismo PDF (dedup por URL final) y uno distinto.
PDF_HTML = "\n".join(
    [
        _redirect("https://files.test/secret.pdf", rut="a"),
        _redirect("https://files.test/secret.pdf", rut="b"),
        _redirect("https://files.test/report.pdf"),
    ]
)

# Sin result__snippet ni result__url: obliga al tercer fallback (uddg suelto).
LEAK_HTML = (
    f'<a href="//duckduckgo.com/l/?uddg={quote("https://pastebin.com/xyz", safe="")}">paste</a>'
)

# Solo result__url con enlaces directos.
GENERAL_HTML = (
    '<a class="result__url" href="https://news.test/alice">noticia</a>'
    '<a class="result__url" href="https://github.com/alice">perfil</a>'
)


def _ddg_responder(request: httpx.Request) -> httpx.Response:
    query = unquote(request.content.decode("utf-8"))
    if "filetype:pdf" in query:
        body = PDF_HTML
    elif "pastebin" in query:
        body = LEAK_HTML
    else:
        body = GENERAL_HTML
    return httpx.Response(status_code=200, text=body, request=request)


class _StubForensics:
    """Sustituto de FileForensics: evita descargar y parsear un PDF real."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.fail_on = fail_on
        self.calls: list[str] = []

    async def collect(self, target: str, **kwargs: object) -> CollectorResult:
        self.calls.append(target)
        if self.fail_on and target == self.fail_on:
            raise RuntimeError("descarga fallida")
        node = EntityNode.create(
            type=EntityType.FILE_ARTIFACT,
            value="sha256:deadbeef",
            label="File: secret.pdf",
            attributes={"filename": "secret.pdf"},
        )
        return CollectorResult(
            collector_name="file_forensics", source_target=target, entities=[node]
        )


def _hunter(stub: _StubForensics) -> DocumentHunter:
    hunter = DocumentHunter()
    hunter.file_forensics = stub  # type: ignore[assignment]
    return hunter


async def test_document_hunter_clasifica_consultas_y_deduplica(monkeypatch):
    router = patch_httpx(
        monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder)
    )
    stub = _StubForensics()

    result = await _hunter(stub).collect("@alice")

    # El deduplicador elimina el segundo enlace idéntico.
    report = json.loads(result.raw_payload)
    assert report["pdf_documents"] == [
        "https://files.test/secret.pdf",
        "https://files.test/report.pdf",
    ]
    assert report["pastes_and_mentions"] == ["https://pastebin.com/xyz"]
    assert report["web_mentions"] == ["https://news.test/alice", "https://github.com/alice"]
    assert stub.calls == ["https://files.test/secret.pdf", "https://files.test/report.pdf"]
    assert router.count(r"duckduckgo") == 3

    assert result.source_target == "alice"
    assert result.metadata == {
        "pdfs_discovered": 2,
        "leaks_discovered": 1,
        "web_mentions_discovered": 2,
        "official_mentions_discovered": 0,
    }


async def test_document_hunter_tipifica_nodo_raiz_y_menciones(monkeypatch):
    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder))

    result = await _hunter(_StubForensics()).collect("alice")

    root = result.entities[0]
    assert root.type == EntityType.ALIAS and root.id == "alias:alice"

    mentions = [e for e in result.entities if e.type == EntityType.SOCIAL_PROFILE]
    assert {m.value for m in mentions} == {"https://github.com/alice"}
    assert all(m.confidence == 0.85 for m in mentions)
    mention_ids = {m.id for m in mentions}
    mention_edges = [r for r in result.relations if r.target_id in mention_ids]
    assert mention_edges and all(r.confidence == 0.85 for r in mention_edges)

    artifact = next(e for e in result.entities if e.type == EntityType.FILE_ARTIFACT)
    pdf_edge = next(r for r in result.relations if r.target_id == artifact.id)
    assert pdf_edge.source_id == root.id
    assert pdf_edge.attributes["discovery_query"] == "filetype:pdf"


async def test_document_hunter_dominio_como_nodo_raiz(monkeypatch):
    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder))

    result = await _hunter(_StubForensics()).collect("example.com")

    assert result.entities[0].type == EntityType.DOMAIN


async def test_document_hunter_registra_fallos_de_descarga(monkeypatch):
    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder))

    result = await _hunter(_StubForensics(fail_on="https://files.test/secret.pdf")).collect("alice")

    report = json.loads(result.raw_payload)
    errors = [k for k in report if k.startswith("error_")]
    assert len(errors) == 1
    assert report[errors[0]] == "descarga fallida"
    # El segundo PDF sí se procesó pese al fallo del primero.
    assert any(e.type == EntityType.FILE_ARTIFACT for e in result.entities)


async def test_document_hunter_sin_resultados(monkeypatch):
    def empty(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("ddg bloqueado", request=request)

    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", empty))

    result = await _hunter(_StubForensics()).collect("alice")

    assert result.metadata == {
        "pdfs_discovered": 0,
        "leaks_discovered": 0,
        "web_mentions_discovered": 0,
        "official_mentions_discovered": 0,
    }
    assert [e.type for e in result.entities] == [EntityType.ALIAS]


async def test_document_hunter_dni_como_documento_y_fuentes_oficiales(monkeypatch):
    router = patch_httpx(
        monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder)
    )

    result = await _hunter(_StubForensics()).collect("99999999")

    # El DNI ya no se registra como alias: es un documento de identidad.
    root = result.entities[0]
    assert root.type == EntityType.DOCUMENT_ID and root.id == "document_id:99999999"

    # 3 consultas base + 1 de fuentes oficiales AR (Boletín Oficial, InfoLEG, PJN).
    assert router.count(r"duckduckgo") == 4
    report = json.loads(result.raw_payload)
    assert report["official_mentions"] == [
        "https://news.test/alice",
        "https://github.com/alice",
    ]
    assert result.metadata["official_mentions_discovered"] == 2

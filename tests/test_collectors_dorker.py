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
    # 3 base + 3 dorks de repositorios de documentos (Scribd/Studocu/...).
    assert router.count(r"duckduckgo") == 6

    assert result.source_target == "alice"
    # Las claves estables del metadata; el diagnóstico de búsquedas se
    # verifica aparte (una entrada por query, sin fallos de transporte).
    metadata = dict(result.metadata)
    diagnostics = metadata.pop("search_diagnostics")
    assert metadata == {
        "pdfs_discovered": 2,
        "leaks_discovered": 1,
        "web_mentions_discovered": 2,
        "official_mentions_discovered": 0,
        "repository_mentions_discovered": 2,
        "seeds_pivoted": [],
        "context_tld": "com",
        "searches_attempted": 6,
        "search_failures": 0,
    }
    assert len(diagnostics) == 6


async def test_document_hunter_tipifica_nodo_raiz_y_menciones(monkeypatch):
    patch_httpx(monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder))

    result = await _hunter(_StubForensics()).collect("alice")

    root = result.entities[0]
    assert root.type == EntityType.ALIAS and root.id == "alias:alice"

    mentions = [e for e in result.entities if e.type == EntityType.SOCIAL_PROFILE]
    assert {m.value for m in mentions} == {"https://github.com/alice"}
    assert all(m.confidence == 0.5 for m in mentions)
    mention_ids = {m.id for m in mentions}
    mention_edges = [r for r in result.relations if r.target_id in mention_ids]
    assert mention_edges and all(r.confidence == 0.5 for r in mention_edges)

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

    # Con el buscador caído: cada query queda registrada como fallo de
    # transporte, sin reventar la campaña documental.
    metadata = dict(result.metadata)
    diagnostics = metadata.pop("search_diagnostics")
    assert metadata == {
        "pdfs_discovered": 0,
        "leaks_discovered": 0,
        "web_mentions_discovered": 0,
        "official_mentions_discovered": 0,
        "repository_mentions_discovered": 0,
        "seeds_pivoted": [],
        "context_tld": "com",
        "searches_attempted": 6,
        "search_failures": 6,
    }
    assert len(diagnostics) == 6
    assert all(d["status"] == "error" for d in diagnostics)


def _seed_pivot_responder(request: httpx.Request) -> httpx.Response:
    """DDG falso que distingue la búsqueda del pivote de la búsqueda base."""
    query = unquote(request.content.decode("utf-8"))
    if "11223344" in query:
        body = _redirect("https://files.test/codigo-universitario.pdf")
    else:
        body = PDF_HTML
    return httpx.Response(status_code=200, text=body, request=request)


async def test_document_hunter_pivota_por_identificador_del_contexto(monkeypatch):
    """El pivot loop: un código hallado en el caso dispara su propia búsqueda."""
    router = patch_httpx(
        monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _seed_pivot_responder)
    )

    result = await _hunter(_StubForensics()).collect(
        "Carlos Mendoza", context="codigo universitario 11223344 en el expediente"
    )

    assert result.metadata["seeds_pivoted"] == ["11223344"]
    pivots = [e for e in result.entities if e.attributes.get("bucket") == "pivot"]
    assert any(e.value == "https://files.test/codigo-universitario.pdf" for e in pivots)
    assert pivots[0].attributes["seed"] == "11223344"
    # La query del pivote llegó al buscador además de las 3 base + 3 repos.
    assert router.count(r"duckduckgo") == 7


def test_seed_pivots_filtra_el_propio_target_y_duplicados():
    from specter.collectors.dorker import _seed_pivots

    seeds = _seed_pivots(
        "11223344", "email cmendozagarcia@ejemplo.test y código 11223344, tel 988776655"
    )
    assert "11223344" not in seeds  # el target nunca es pivote de sí mismo
    assert "11223344" not in seeds[1:]  # y no se duplica
    assert "cmendozagarcia@ejemplo.test" in seeds
    assert "988776655" in seeds  # 9 dígitos está en el rango 6-12


async def test_document_hunter_recupera_pdf_caido_desde_wayback(monkeypatch):
    """Un 403/Cloudflare no mata el documento: Wayback antes de "irrecuperable"."""

    class _FlakyForensics:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def collect(self, target: str, **kwargs: object) -> CollectorResult:
            self.calls.append(target)
            if target.startswith("http://web.archive.org"):
                node = EntityNode.create(
                    type=EntityType.FILE_ARTIFACT,
                    value="sha256:wayback",
                    label="File: secret.pdf (wayback)",
                    attributes={"filename": "secret.pdf"},
                )
                return CollectorResult(
                    collector_name="file_forensics", source_target=target, entities=[node]
                )
            raise RuntimeError("HTTP 403")

    def wayback_yes(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            json={
                "archived_snapshots": {
                    "closest": {
                        "available": True,
                        "url": "http://web.archive.org/web/2024/https://files.test/secret.pdf",
                    }
                }
            },
            request=request,
        )

    router = MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder)
    router.add_responder("GET", r"archive.org/wayback", wayback_yes)
    patch_httpx(monkeypatch, router)
    flaky = _FlakyForensics()

    result = await _hunter(flaky).collect("alice")

    assert flaky.calls[0] == "https://files.test/secret.pdf"
    assert flaky.calls[1].startswith("http://web.archive.org/web/")
    report = json.loads(result.raw_payload)
    # Ambos PDFs fallan y ambos se recuperan desde Wayback.
    assert set(report["wayback_recovered"]) == {
        "https://files.test/secret.pdf",
        "https://files.test/report.pdf",
    }
    assert not any(k.startswith("error_") for k in report)


async def test_document_hunter_wayback_sin_snapshot_registra_error(monkeypatch):
    """Sin snapshot disponible, el error original se registra como antes."""

    def wayback_empty(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, json={"archived_snapshots": {}}, request=request)

    router = MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder)
    router.add_responder("GET", r"archive.org/wayback", wayback_empty)
    patch_httpx(monkeypatch, router)
    stub = _StubForensics(fail_on="https://files.test/secret.pdf")

    result = await _hunter(stub).collect("alice")

    report = json.loads(result.raw_payload)
    errors = [k for k in report if k.startswith("error_")]
    assert len(errors) == 1


async def test_document_hunter_dni_como_documento_y_fuentes_oficiales(monkeypatch):
    router = patch_httpx(
        monkeypatch, MockRouter().add_responder("POST", r"duckduckgo", _ddg_responder)
    )

    result = await _hunter(_StubForensics()).collect("99999999")

    # El DNI ya no se registra como alias: es un documento de identidad.
    root = result.entities[0]
    assert root.type == EntityType.DOCUMENT_ID and root.id == "document_id:99999999"

    # 3 base + 3 repositorios + 1 oficial (DNI → raíz DOCUMENT_ID, TLD genérico).
    assert router.count(r"duckduckgo") == 7
    report = json.loads(result.raw_payload)
    assert report["official_mentions"] == [
        "https://news.test/alice",
        "https://github.com/alice",
    ]
    assert result.metadata["official_mentions_discovered"] == 2

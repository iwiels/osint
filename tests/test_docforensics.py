"""
Tests P1 forense-documental: peepdf-style, ELA, minado OOXML y caza FOCA.
Sin red real (DDG + descargas mockeadas) salvo Pillow/pypdf locales.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.docforensics import (
    OfficeDocHunter,
    ela_score,
    mine_office_metadata,
    scan_pdf_threats,
)

pytestmark = pytest.mark.asyncio


def _pdf(js: bool = False, updates: int = 1) -> bytes:
    body = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R"
    if js:
        body += b"/OpenAction 5 0 R"
    body += b">>endobj\n"
    parts = [body + b"trailer<</Root 1 0 R>>\n%%EOF" for _ in range(updates)]
    if js:
        parts[0] = parts[0].replace(b"endobj", b"/JavaScript 9 0 R endobj")
    return b"".join(parts)


def test_scan_pdf_threats_detecta_js_y_updates() -> None:
    clean = scan_pdf_threats(_pdf())
    assert clean["suspicious"] is False and clean["incremental_updates"] == 0

    evil = scan_pdf_threats(_pdf(js=True, updates=2))
    assert evil["suspicious"] is True
    assert "/JavaScript" in evil["threat_markers"] or evil["has_open_action"] is True
    assert evil["incremental_updates"] == 1


def test_ela_score_orientativo() -> None:
    from PIL import Image

    img = Image.new("RGB", (64, 64), (200, 30, 30))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    result = ela_score(buf.getvalue())
    assert result["supported"] is True
    assert 0.0 <= result["score"] <= 100.0
    assert result["verdict"] in ("likely-pristine", "uncertain", "likely-edited")


def _docx(author: str = "Ana Lopez", body_extra: str = "") -> bytes:
    core = (
        '<?xml version="1.0"?><cp:coreProperties xmlns:cp="x">'
        f'<dc:creator xmlns:dc="y">{author}</dc:creator>'
        "<cp:revision>4</cp:revision></cp:coreProperties>"
    )
    doc = (
        '<?xml version="1.0"?><w:document xmlns:w="z"><w:body><w:p><w:r><w:t>'
        "Informe trimestral \\\\fileserver02\\rrhh\\sueldos.docx IP 10.20.30.40 "
        + body_extra
        + "</w:t></w:r></w:p></w:body></w:document>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docProps/core.xml", core)
        zf.writestr("word/document.xml", doc)
    return buf.getvalue()


def test_mine_office_metadata_autor_unc_e_ip() -> None:
    report = mine_office_metadata(_docx(), "informe.docx")
    assert report["authors"] == ["Ana Lopez"]
    assert report["doc_revision"] == "4"
    assert any("fileserver02" in u for u in report["unc_paths"])
    assert report["private_ips"] == ["10.20.30.40"]
    assert report["leak_signals"] is True


async def test_office_doc_hunter_caza_y_mina(monkeypatch) -> None:
    doc_bytes = _docx()
    router = (
        MockRouter()
        .add(
            "POST",
            r"duckduckgo\.com",
            text='<a href="https://ejemplo.test/docs/informe.docx?uddg=https%3A%2F%2Ffiles.ejemplo.test%2Finforme.docx&rut=x">x</a>',
        )
        .add("GET", r"files\.ejemplo\.test", content=doc_bytes)
    )
    patch_httpx(monkeypatch, router)
    result = await OfficeDocHunter().collect("ejemplo.test", max_docs=2)
    assert result.metadata["ok"] is True
    assert result.metadata["mined"] == 1
    assert result.metadata["leak_docs"] == 1
    values = [e.value for e in result.entities]
    assert "Ana Lopez" in values and "10.20.30.40" in values


async def test_office_doc_hunter_sin_resultados_no_falla(monkeypatch) -> None:
    router = MockRouter().add("POST", r"duckduckgo\.com", text="<html>sin resultados</html>")
    patch_httpx(monkeypatch, router)
    result = await OfficeDocHunter().collect("nada.test")
    assert result.metadata["ok"] is True
    assert result.metadata["mined"] == 0

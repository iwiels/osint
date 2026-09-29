"""
WraithOSINT - Forensia documental profunda (P1: FOCA/peepdf/ELA/mat2-lite).

Sin dependencias nuevas (Pillow + pypdf ya están):

- scan_pdf_threats: peepdf-style sobre el binario (JS/OpenAction/Launch/
  EmbeddedFiles/XFA + updates incrementales no purgadas).
- ela_score: Error Level Analysis con Pillow (recompresión JPEG q95 + matriz
  de diferencia; secciones pegadas delatan distinto ciclo de compresión).
- mine_office_metadata: FOCA-style sobre docx/xlsx/pdf (autores, software,
  rutas UNC, IPs privadas, impresoras).
- OfficeDocHunter: dorks `site:domain filetype:` + descarga + minado.

Lo OLE2/mat2 completo (macros VBA, strip) queda para P2 con `oletools`.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import re
import zipfile
from typing import Any
from xml.etree import ElementTree as ET

from specter.collectors.base import BaseCollector
from specter.httpx_transport import http_get, http_post
from specter.netguard import check_public_http_url, ssrf_enforce
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.docforensics")

_DDG_URL = "https://html.duckduckgo.com/html/"
_TIMEOUT = 12.0
_UA = {"User-Agent": "WraithOSINT/0.3 (+forense documental)"}
_MAX_DOCS = 8
_MAX_BYTES = 25 * 1024 * 1024

_PDF_THREAT_MARKERS = (
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/Launch",
    b"/EmbeddedFiles",
    b"/XFA",
    b"/AA",
)

_UNC_RE = re.compile(r"\\\\[A-Za-z0-9_.$-]{1,64}(?:\\[A-Za-z0-9_.$ -]{1,128}){1,6}")
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b"
)
_PRINTER_RE = re.compile(r"(?i)(?:printer|impresora|print)[\":\s=]{1,4}([A-Za-z0-9 _.-]{2,48})")


def scan_pdf_threats(data: bytes) -> dict[str, Any]:
    """Escaner estructural peepdf-style: devuelve marcadores + veredicto."""
    found = sorted({m.decode("ascii") for m in _PDF_THREAT_MARKERS if m in data})
    eof_count = data.count(b"%%EOF")
    report: dict[str, Any] = {
        "threat_markers": found,
        "incremental_updates": max(0, eof_count - 1),
        "suspicious": bool(found) or eof_count > 1,
    }
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        root = reader.trailer.get("/Root", {}) or {}
        report["pages"] = len(reader.pages)
        report["has_open_action"] = "/OpenAction" in root
        report["has_acroform"] = "/AcroForm" in root
        names = root.get("/Names", {}) or {}
        report["has_embedded_files"] = "/EmbeddedFiles" in names
        if report["has_open_action"] or report["has_acroform"]:
            report["suspicious"] = True
    except Exception as exc:
        report["parse_error"] = str(exc)[:200]
    return report


def ela_score(data: bytes) -> dict[str, Any]:
    """Error Level Analysis: recomprime a JPEG q95 y mide la diferencia media.

    Imagen genuina -> error uniforme y bajo. Pegados/clones -> zonas con tasa
    de error dispar (score alto). Solo orientativo, nunca veredicto final.
    """
    try:
        from PIL import Image, ImageChops, ImageStat
    except ImportError:
        return {"supported": False}
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
        img.thumbnail((800, 800))
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=95)
        buf.seek(0)
        recomp = Image.open(buf).convert("RGB")
        diff = ImageChops.difference(img, recomp)
        stat = ImageStat.Stat(diff)
        mean_err = sum(stat.mean) / 3.0
        score = round(min(100.0, max(0.0, (mean_err / 12.0) * 100.0)), 1)
        return {
            "supported": True,
            "mean_error": round(mean_err, 2),
            "score": score,
            "verdict": (
                "likely-edited"
                if score >= 60
                else "uncertain"
                if score >= 30
                else "likely-pristine"
            ),
        }
    except Exception as exc:
        return {"supported": False, "error": str(exc)[:200]}


def _zip_text_parts(data: bytes) -> tuple[str, dict[str, str]]:
    """Extrae texto + core properties de un OOXML (docx/xlsx/pptx)."""
    texts: list[str] = []
    props: dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if name == "docProps/core.xml":
                    try:
                        root = ET.fromstring(zf.read(name))
                        for child in root:
                            tag = child.tag.split("}")[-1]
                            if child.text and child.text.strip():
                                props[tag] = child.text.strip()[:200]
                    except ET.ParseError:
                        pass
                elif name.startswith(("word/", "xl/sharedStrings", "ppt/")) and name.endswith(
                    (".xml", ".xml.rels")
                ):
                    with contextlib.suppress(KeyError):
                        texts.append(zf.read(name).decode("utf-8", errors="ignore"))
    except zipfile.BadZipFile as exc:
        return "", {"zip_error": str(exc)[:200]}
    return "\n".join(texts)[:200_000], props


def mine_office_metadata(data: bytes, filename: str) -> dict[str, Any]:
    """Minería FOCA-style: autores, software, UNC, IPs privadas, impresoras."""
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    report: dict[str, Any] = {"filename": filename, "suffix": suffix}
    blob = ""
    if suffix in ("docx", "xlsx", "pptx", "odt"):
        blob, props = _zip_text_parts(data)
        report["core_properties"] = props
        authors = [v for k, v in props.items() if k in ("creator", "lastModifiedBy") and v]
        if authors:
            report["authors"] = sorted(set(authors))
        for key in ("version", "revision"):
            if key in props:
                report[f"doc_{key}"] = props[key]
    elif suffix == "pdf":
        try:
            from pypdf import PdfReader

            info = PdfReader(io.BytesIO(data)).metadata or {}
            flat = {str(k).lstrip("/"): str(v)[:200] for k, v in info.items()}
            report["pdf_info"] = flat
            if info.author:
                report["authors"] = [str(info.author).strip()]
            blob = " ".join(flat.values())
        except Exception as exc:
            report["pdf_error"] = str(exc)[:200]
    else:
        try:
            blob = data[:200_000].decode("utf-8", errors="ignore")
        except Exception:
            blob = ""

    uncs = sorted(set(_UNC_RE.findall(blob)))[:20]
    privates = sorted(set(_PRIVATE_IP_RE.findall(blob)))[:20]
    printers = sorted({m.group(1).strip() for m in _PRINTER_RE.finditer(blob)})[:10]
    if uncs:
        report["unc_paths"] = uncs
    if privates:
        report["private_ips"] = privates
    if printers:
        report["printers"] = printers
    report["leak_signals"] = bool(uncs or privates)
    return report


class OfficeDocHunter(BaseCollector):
    """Caza FOCA-style: documentos públicos de un dominio + minado de metadatos."""

    def __init__(self):
        super().__init__(name="office_doc_hunter")

    async def collect(
        self, target: str, max_docs: int = _MAX_DOCS, **kwargs: Any
    ) -> CollectorResult:
        domain = target.strip().lower()
        max_docs = max(1, min(int(max_docs), _MAX_DOCS))
        query = f"site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx"
        urls: list[str] = []
        try:
            # P0: búsqueda y descargas con impersonación TLS (curl_cffi).
            resp = await http_post(_DDG_URL, data={"q": query}, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                raise RuntimeError(f"DDG respondió {resp.status_code}")
            for m in re.finditer(r'href="([^"]*uddg=([^"&]+))', resp.text):
                from urllib.parse import unquote

                candidate = unquote(m.group(2))
                if candidate.startswith("http") and len(urls) < max_docs * 2:
                    urls.append(candidate)
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        mined = 0
        leak_docs = 0
        for url in urls[:max_docs]:
            try:
                from specter.osint_core.tempo import jitter_sleep

                await jitter_sleep(0.9, spread=0.5)  # anti-bloqueo, no intervalos fijos
                if ssrf_enforce() and (blocked := check_public_http_url(url)):
                    logger.debug("office_doc_hunter: %s bloqueada por NetGuard: %s", url, blocked)
                    continue
                resp = await http_get(url, headers=_UA, timeout=15.0)
                if resp.status_code >= 400:
                    raise RuntimeError(f"HTTP {resp.status_code}")
                data = resp.content
                if len(data) > _MAX_BYTES or not data:
                    continue
                filename = url.rsplit("/", 1)[-1].split("?")[0][:120] or "documento"
                report = mine_office_metadata(data, filename)
                mined += 1
                if report.get("leak_signals"):
                    leak_docs += 1
                doc_node = EntityNode.create(
                    EntityType.FILE_ARTIFACT,
                    filename,
                    f"Doc: {filename}",
                    attributes={"source_url": url, "report": report, "source": "office_doc_hunter"},
                    confidence=0.8,
                )
                entities.append(doc_node)
                for author in report.get("authors", [])[:5]:
                    person = EntityNode.create(
                        EntityType.PERSON,
                        author,
                        f"Autor: {author}",
                        attributes={"source": "office-metadata"},
                        confidence=0.7,
                    )
                    entities.append(person)
                    relations.append(
                        RelationEdge(
                            source_id=doc_node.id,
                            target_id=person.id,
                            relation_type=RelationType.CONTAINS_METADATA,
                        )
                    )
                for private_ip in report.get("private_ips", [])[:10]:
                    ip_node = EntityNode.create(
                        EntityType.IP_ADDRESS,
                        private_ip,
                        f"IP interna: {private_ip}",
                        attributes={"source": "office-metadata", "internal": True},
                        confidence=0.75,
                    )
                    entities.append(ip_node)
                    relations.append(
                        RelationEdge(
                            source_id=doc_node.id,
                            target_id=ip_node.id,
                            relation_type=RelationType.ASSOCIATED_WITH,
                        )
                    )
            except Exception as exc:
                logger.debug("office_doc_hunter: %s: %s", url, exc)
                continue

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"domain": domain, "mined": mined, "leak_docs": leak_docs}, ensure_ascii=False
            ),
            metadata={"ok": True, "mined": mined, "leak_docs": leak_docs},
        )

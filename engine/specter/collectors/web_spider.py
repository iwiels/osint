"""
WraithOSINT - Web Spider Collector
Crawling automático de páginas del target con extracción de entidades.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.web_spider")

_TIMEOUT = 15.0
_UA = {"User-Agent": "WraithOSINT/0.3 (+forense, web spider)"}

# Extensiones de archivos binarios a ignorar
_BINARY_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".svg",
        ".ico",
        ".webp",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".rar",
        ".7z",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".flv",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".css",
        ".js",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
    }
)

# Patrones de extracción
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_PHONE_RE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
_URL_RE = re.compile(r'href=["\'](.*?)["\']', re.IGNORECASE)


class _HTMLTextExtractor(HTMLParser):
    """Extrae texto y metadatos de HTML usando solo stdlib."""

    def __init__(self) -> None:
        super().__init__()
        self.title: str | None = None
        self.meta_description: str | None = None
        self.links: list[str] = []
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._in_title = True
        elif tag == "a":
            for attr, value in attrs:
                if attr == "href" and value:
                    self.links.append(value)
        elif tag == "meta":
            attrs_dict = dict(attrs)
            name = attrs_dict.get("name", "").lower()
            content = attrs_dict.get("content", "")
            if name == "description" and content:
                self.meta_description = content

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
            if self._title_parts:
                self.title = "".join(self._title_parts).strip()

    def handle_data(self, data: str) -> str:
        if self._in_title:
            self._title_parts.append(data)
        return data


def _is_binary_url(url: str) -> bool:
    """Verifica si la URL apunta a un archivo binario."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return any(path.endswith(ext) for ext in _BINARY_EXTENSIONS)


def _normalize_url(base: str, link: str) -> str | None:
    """Normaliza y filtra URLs encontradas en el HTML."""
    if not link or link.startswith(("javascript:", "mailto:", "tel:", "#")):
        return None
    full_url = urljoin(base, link)
    # Eliminar fragmento
    full_url, _ = urldefrag(full_url)
    parsed = urlparse(full_url)
    if parsed.scheme not in ("http", "https"):
        return None
    if _is_binary_url(full_url):
        return None
    return full_url


class WebSpiderCollector(BaseCollector):
    """Crawling automático de páginas del target.

    Sigue links con límite de profundidad y páginas, extrayendo:
    - URLs (entidades ALIAS)
    - Emails (entidades EMAIL)
    - Teléfonos (entidades PHONE)
    - Títulos y meta description (atributos del nodo)
    """

    def __init__(self) -> None:
        super().__init__(name="web_spider")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        max_levels: int = int(kwargs.get("maxlevels", 3))
        max_pages: int = int(kwargs.get("maxpages", 100))
        respect_robots: bool = bool(kwargs.get("respect_robots", False))

        start_url = target.strip()
        if not start_url.startswith(("http://", "https://")):
            start_url = f"https://{start_url}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        visited: set[str] = set()
        pages_crawled = 0
        emails_found: set[str] = set()
        phones_found: set[str] = set()
        urls_found: set[str] = set()

        # Cola de URLs por nivel: (url, nivel)
        queue: list[tuple[str, int]] = [(start_url, 0)]

        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT,
                follow_redirects=True,
                headers=_UA,
            ) as client:
                while queue and pages_crawled < max_pages:
                    current_url, level = queue.pop(0)

                    if current_url in visited:
                        continue
                    if level > max_levels:
                        continue

                    visited.add(current_url)
                    pages_crawled += 1

                    try:
                        resp = await client.get(current_url)
                        if resp.status_code != 200:
                            continue
                        content_type = resp.headers.get("content-type", "")
                        if "text/html" not in content_type:
                            continue
                        html = resp.text
                    except Exception as exc:
                        logger.debug("Error crawling %s: %s", current_url, exc)
                        continue

                    # Parsear HTML
                    parser = _HTMLTextExtractor()
                    with contextlib.suppress(Exception):
                        parser.feed(html)

                    # Extraer emails
                    for email in _EMAIL_RE.findall(html):
                        email = email.lower().strip()
                        if email and email not in emails_found and "@" in email:
                            emails_found.add(email)

                    # Extraer teléfonos
                    for phone in _PHONE_RE.findall(html):
                        phone = phone.strip()
                        if phone and phone not in phones_found:
                            phones_found.add(phone)

                    # Extraer y encolar links
                    if level < max_levels:
                        for link in parser.links:
                            normalized = _normalize_url(current_url, link)
                            if normalized and normalized not in visited:
                                urls_found.add(normalized)
                                queue.append((normalized, level + 1))

        except Exception as exc:
            logger.error("Web spider error: %s", exc)

        # Construir entidades
        # Nodo raíz: URL inicial
        root = EntityNode.create(
            EntityType.ALIAS,
            start_url,
            f"URL inicial: {start_url}",
            attributes={
                "source": "web_spider",
                "pages_crawled": pages_crawled,
                "max_levels": max_levels,
                "max_pages": max_pages,
            },
        )
        entities.append(root)

        # Entidades ALIAS para URLs encontradas
        for url in sorted(urls_found)[:200]:
            url_node = EntityNode.create(
                EntityType.ALIAS,
                url,
                f"URL: {url}",
                attributes={"source": "web_spider", "type": "crawled_url"},
                confidence=0.7,
            )
            entities.append(url_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=url_node.id,
                    relation_type=RelationType.LINKED_TO,
                )
            )

        # Entidades EMAIL
        for email in sorted(emails_found)[:100]:
            email_node = EntityNode.create(
                EntityType.EMAIL,
                email,
                f"Email: {email}",
                attributes={"source": "web_spider"},
                confidence=0.8,
            )
            entities.append(email_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=email_node.id,
                    relation_type=RelationType.EXPOSED_IN,
                )
            )

        # Entidades PHONE
        for phone in sorted(phones_found)[:50]:
            phone_node = EntityNode.create(
                EntityType.PHONE,
                phone,
                f"Teléfono: {phone}",
                attributes={"source": "web_spider"},
                confidence=0.7,
            )
            entities.append(phone_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=phone_node.id,
                    relation_type=RelationType.EXPOSED_IN,
                )
            )

        metadata: dict[str, Any] = {
            "ok": True,
            "pages_crawled": pages_crawled,
            "urls_found": len(urls_found),
            "emails_found": len(emails_found),
            "phones_found": len(phones_found),
            "max_levels": max_levels,
            "max_pages": max_pages,
            "respect_robots": respect_robots,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "start_url": start_url,
                    "pages_crawled": pages_crawled,
                    "urls": sorted(urls_found)[:200],
                    "emails": sorted(emails_found)[:100],
                    "phones": sorted(phones_found)[:50],
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )

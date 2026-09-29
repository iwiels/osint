"""
SpecterOSINT - Breach Data Collectors
Colectores de brechas de datos y fugas de información:

- HaveIBeenPwnedCollector: HIBP (requiere key, patrón _collector_key)
- LeakLookupCollector: Leak-Lookup (gratis, sin key)
- LeakIXCollector: LeakIX (gratis, sin key)
- IntelligenceXCollector: IntelligenceX (gratis, sin key)
"""

from __future__ import annotations

import json
import logging
import os
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote

import httpx
from specter.collectors.base import BaseCollector

# Implementación canónica de HIBP: vive en threatintel_enhanced porque es la
# que puntúa con Almirantazgo (rate_source/assess_evidence). Se reexporta aquí
# para que el grupo de breach-data y ese módulo compartan una sola clase.
from specter.collectors.threatintel_enhanced import HaveIBeenPwnedCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

__all__ = [
    "HaveIBeenPwnedCollector",
    "IntelligenceXCollector",
    "LeakIXCollector",
    "LeakLookupCollector",
]

logger = logging.getLogger("specter.collectors.breach_data")

_TIMEOUT = 12.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+breach-data)"}


def _collector_key(vault_name: str) -> str | None:
    """Key de la bóveda local o su env equivalente. None = no configurada.

    Regla Fase B: sin key el colector se omite (ok=False, requires_key) y el
    agente ni lo intenta: solo se habilita desde la UI de ajustes.
    """
    from specter import secrets as vault

    env_var = vault.ALLOWED_SECRETS.get(vault_name, "")
    return os.environ.get(env_var) or vault.get_secret(vault_name) or None


def _missing_key_result(name: str, target: str, vault_name: str) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        source_target=target,
        raw_payload=json.dumps({"target": target, "skipped": f"requiere {vault_name}"}),
        metadata={"ok": False, "requires_key": vault_name},
    )


class _LeakIXParser(HTMLParser):
    """Extrae puertos, servicios y datos expuestos del HTML de LeakIX."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ports: list[str] = []
        self.services: list[str] = []
        self.certificates: list[str] = []
        self.breaches: list[str] = []
        self._in_table = False
        self._in_cell = False
        self._cell_text: list[str] = []
        self._section = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self._in_table = True
        elif self._in_table and tag == "td":
            self._in_cell = True
            self._cell_text = []
        elif tag in ("h2", "h3", "h4"):
            self._section = ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "table":
            self._in_table = False
        elif self._in_table and tag == "td" and self._in_cell:
            text = " ".join("".join(self._cell_text).split())
            if text:
                self._classify_cell(text)
            self._in_cell = False
        elif tag in ("h2", "h3", "h4"):
            self._section = ""

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell_text.append(data)

    def _classify_cell(self, text: str) -> None:
        """Clasifica el texto de una celda según la sección de la tabla."""
        lowered = text.lower()
        if re.match(r"^\d{1,5}$", text):
            self.ports.append(text)
        elif any(
            kw in lowered
            for kw in ("http", "https", "ssh", "ftp", "smtp", "dns", "mysql", "postgres")
        ):
            self.services.append(text)
        elif any(kw in lowered for kw in ("cert", "tls", "ssl", "issuer", "subject")):
            self.certificates.append(text)
        elif any(kw in lowered for kw in ("breach", "leak", "pwned", "exposed")):
            self.breaches.append(text)


class _IntelligenceXParser(HTMLParser):
    """Extrae resultados de brechas del HTML de IntelligenceX."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[dict[str, str]] = []
        self._in_result = False
        self._in_link = False
        self._text_parts: list[str] = []
        self._href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        if tag == "div" and ("result" in classes or "search-result" in classes):
            self._in_result = True
            self._text_parts = []
            self._href = ""
        elif self._in_result and tag == "a":
            self._in_link = True
            self._href = values.get("href") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "div" and self._in_result:
            text = " ".join("".join(self._text_parts).split())
            if text:
                self.results.append({"text": text, "url": self._href})
            self._in_result = False
        elif tag == "a":
            self._in_link = False

    def handle_data(self, data: str) -> None:
        if self._in_result:
            self._text_parts.append(data)


class LeakLookupCollector(BaseCollector):
    """Leak-Lookup: brechas conocidas para un email (gratis, sin key)."""

    def __init__(self) -> None:
        super().__init__(name="leaklookup")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        email = target.strip().lower()
        url = f"https://leak-lookup.com/api/search?query={quote(email)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("LeakLookup request failed for %s: %s", email, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=email,
                raw_payload=json.dumps({"email": email, "error": str(exc)}),
                metadata={"ok": False},
            )

        # La API puede devolver lista directa o dict con results/data
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("results") or data.get("data") or data.get("breaches") or []
        else:
            items = []

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        email_node = EntityNode.create(
            EntityType.EMAIL,
            email,
            f"Email: {email}",
            attributes={"source": "leaklookup", "breach_count": len(items)},
            confidence=0.85,
        )
        entities.append(email_node)
        for item in items[:20]:
            if not isinstance(item, dict):
                continue
            breach_name = str(item.get("name") or item.get("Name") or "Unknown").strip()
            breach_node = EntityNode.create(
                EntityType.BREACH,
                breach_name,
                f"Breach: {breach_name}",
                attributes={
                    "date": item.get("date") or item.get("BreachDate"),
                    "source": "leaklookup",
                },
                confidence=0.8,
            )
            entities.append(breach_node)
            relations.append(
                RelationEdge(
                    source_id=email_node.id,
                    target_id=breach_node.id,
                    relation_type=RelationType.EXPOSED_IN,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=email,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"email": email, "breaches": len(items)}),
            metadata={"ok": True, "breaches": len(items)},
        )


class LeakIXCollector(BaseCollector):
    """LeakIX: datos expuestos de un dominio (gratis, sin key)."""

    def __init__(self) -> None:
        super().__init__(name="leakix")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://leakix.net/search?q={quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                body = resp.text
        except Exception as exc:
            logger.warning("LeakIX request failed for %s: %s", domain, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        parser = _LeakIXParser()
        parser.feed(body)

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"Dominio: {domain}",
            attributes={
                "ports": parser.ports[:20],
                "services": parser.services[:20],
                "certificates": parser.certificates[:10],
                "breaches": parser.breaches[:10],
                "source": "leakix",
            },
            confidence=0.75,
        )
        entities.append(root)
        for port in parser.ports[:20]:
            port_node = EntityNode.create(
                EntityType.PORT,
                f"{domain}:{port}",
                f"Puerto: {port}",
                attributes={"port": port, "source": "leakix"},
                confidence=0.8,
            )
            entities.append(port_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=port_node.id,
                    relation_type=RelationType.RUNS_PORT,
                )
            )
        for breach in parser.breaches[:10]:
            breach_node = EntityNode.create(
                EntityType.BREACH,
                breach,
                f"Breach: {breach}",
                attributes={"source": "leakix"},
                confidence=0.75,
            )
            entities.append(breach_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=breach_node.id,
                    relation_type=RelationType.EXPOSED_IN,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "ports": parser.ports[:20],
                    "services": parser.services[:20],
                    "certificates": parser.certificates[:10],
                    "breaches": parser.breaches[:10],
                }
            ),
            metadata={
                "ok": True,
                "ports": len(parser.ports),
                "services": len(parser.services),
                "breaches": len(parser.breaches),
            },
        )


class IntelligenceXCollector(BaseCollector):
    """IntelligenceX: resultados de búsqueda en brechas (gratis, sin key)."""

    def __init__(self) -> None:
        super().__init__(name="intelligencex")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://intelx.io/search?term={quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                body = resp.text
        except Exception as exc:
            logger.warning("IntelligenceX request failed for %s: %s", domain, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        parser = _IntelligenceXParser()
        parser.feed(body)

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"Dominio: {domain}",
            attributes={"source": "intelligencex"},
        )
        entities.append(root)
        for item in parser.results[:20]:
            text = str(item.get("text", ""))[:200]
            if not text:
                continue
            node = EntityNode.create(
                EntityType.ALIAS,
                text,
                f"IntelX: {text[:80]}",
                attributes={"url": item.get("url", ""), "source": "intelligencex"},
                confidence=0.65,
            )
            entities.append(node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "results": len(parser.results)}),
            metadata={"ok": True, "results": len(parser.results)},
        )

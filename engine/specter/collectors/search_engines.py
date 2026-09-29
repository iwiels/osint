"""
SpecterOSINT - Search Engine Collectors
Colectores de motores de búsqueda y código (todos gratuitos, sin API key):

- DuckDuckGoCollector: búsqueda HTML gratuita (títulos, URLs, snippets)
- BingSearchCollector: búsqueda HTML gratuita (títulos, URLs, snippets)
- CommonCrawlCollector: índice histórico de URLs de un dominio
- GrepAppCollector: búsqueda en código (repos que mencionan el dominio)
- SearchcodeCollector: búsqueda en código (searchcode.com)
"""

from __future__ import annotations

import json
import logging
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote

import httpx
from specter.collectors.base import BaseCollector
from specter.collectors.web import parse_ddg_html
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.search_engines")

_TIMEOUT = 12.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+search-engines)"}


class _BingResultsParser(HTMLParser):
    """Extrae resultados del HTML de Bing (li.b_algo > h2 > a + p)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[dict[str, str]] = []
        self._in_algo = False
        self._in_h2 = False
        self._in_snippet = False
        self._title_parts: list[str] = []
        self._snippet_parts: list[str] = []
        self._url = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        if tag == "li" and "b_algo" in classes:
            self._in_algo = True
            self._title_parts = []
            self._snippet_parts = []
            self._url = ""
        elif self._in_algo and tag == "h2":
            self._in_h2 = True
        elif self._in_algo and self._in_h2 and tag == "a":
            self._url = values.get("href") or ""
        elif self._in_algo and tag == "p" and "b_lineclamp" in classes:
            self._in_snippet = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "li" and self._in_algo:
            if self._url:
                title = " ".join("".join(self._title_parts).split())
                snippet = " ".join("".join(self._snippet_parts).split())
                self.results.append(
                    {"title": title or self._url, "url": self._url, "snippet": snippet}
                )
            self._in_algo = False
        elif tag == "h2":
            self._in_h2 = False
        elif tag == "p" and self._in_snippet:
            self._in_snippet = False

    def handle_data(self, data: str) -> None:
        if self._in_h2:
            self._title_parts.append(data)
        elif self._in_snippet:
            self._snippet_parts.append(data)


def _parse_bing_html(body: str) -> list[dict[str, str]]:
    """Extrae [{title, url, snippet}] del HTML de Bing."""
    parser = _BingResultsParser()
    parser.feed(body)
    return parser.results


def _url_entity(
    url: str, root_id: str, position: int, title: str, snippet: str
) -> tuple[EntityNode, RelationEdge]:
    """Crea un nodo ALIAS para una URL y su arista ASSOCIATED_WITH al raíz."""
    node = EntityNode.create(
        EntityType.ALIAS,
        url,
        f"URL: {url[:80]}",
        attributes={
            "title": title,
            "snippet": snippet,
            "position": position,
        },
        confidence=0.7,
    )
    edge = RelationEdge(
        source_id=root_id,
        target_id=node.id,
        relation_type=RelationType.ASSOCIATED_WITH,
    )
    return node, edge


class DuckDuckGoCollector(BaseCollector):
    """DuckDuckGo búsqueda HTML gratuita: títulos, URLs y snippets sin API key."""

    def __init__(self) -> None:
        super().__init__(name="duckduckgo")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        query = target.strip()
        url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                body = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=query,
                raw_payload=json.dumps({"query": query, "error": str(exc)}),
                metadata={"ok": False},
            )

        results = parse_ddg_html(body)
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.ALIAS, query, f"Búsqueda: {query}", attributes={"source": "duckduckgo"}
        )
        entities.append(root)
        for i, item in enumerate(results[:20]):
            url_value = str(item.get("url", ""))[:300]
            if not url_value:
                continue
            node, edge = _url_entity(
                url_value, root.id, i, str(item.get("title", "")), str(item.get("snippet", ""))
            )
            entities.append(node)
            relations.append(edge)
        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"query": query, "results": results[:20]}, ensure_ascii=False),
            metadata={"ok": True, "results": len(results)},
        )


class BingSearchCollector(BaseCollector):
    """Bing búsqueda HTML gratuita: títulos, URLs y snippets sin API key."""

    def __init__(self) -> None:
        super().__init__(name="bing")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        query = target.strip()
        url = f"https://www.bing.com/search?q={quote(query)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                body = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=query,
                raw_payload=json.dumps({"query": query, "error": str(exc)}),
                metadata={"ok": False},
            )

        results = _parse_bing_html(body)
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.ALIAS, query, f"Búsqueda: {query}", attributes={"source": "bing"}
        )
        entities.append(root)
        for i, item in enumerate(results[:20]):
            url_value = str(item.get("url", ""))[:300]
            if not url_value:
                continue
            node, edge = _url_entity(
                url_value, root.id, i, str(item.get("title", "")), str(item.get("snippet", ""))
            )
            entities.append(node)
            relations.append(edge)
        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"query": query, "results": results[:20]}, ensure_ascii=False),
            metadata={"ok": True, "results": len(results)},
        )


class CommonCrawlCollector(BaseCollector):
    """CommonCrawl index: URLs históricas de un dominio (gratis, sin key)."""

    def __init__(self) -> None:
        super().__init__(name="commoncrawl")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://index.commoncrawl.org/CC-MAIN-2026-30-index?url={quote(domain)}&output=json"
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN, domain, f"Dominio: {domain}", attributes={"source": "commoncrawl"}
        )
        entities.append(root)
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url_value = str(row.get("url", ""))[:300]
            if not url_value:
                continue
            count += 1
            if count > 100:
                break
            node = EntityNode.create(
                EntityType.ALIAS,
                url_value,
                f"Histórica: {url_value[:80]}",
                attributes={
                    "timestamp": row.get("timestamp"),
                    "status": row.get("status"),
                    "source": "commoncrawl",
                },
                confidence=0.7,
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
            raw_payload=json.dumps({"domain": domain, "urls": count}),
            metadata={"ok": True, "urls": count},
        )


class GrepAppCollector(BaseCollector):
    """GrepApp: repositorios de código que mencionan un dominio (gratis, sin key)."""

    def __init__(self) -> None:
        super().__init__(name="grepapp")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://grep.app/api/search?q={quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN, domain, f"Dominio: {domain}", attributes={"source": "grepapp"}
        )
        entities.append(root)
        hits = data.get("hits", {}).get("hits", [])
        for hit in hits[:20]:
            repo = str(hit.get("repo", ""))
            path = str(hit.get("path", ""))
            if not repo:
                continue
            repo_node = EntityNode.create(
                EntityType.ALIAS,
                repo,
                f"Repo: {repo}",
                attributes={"path": path, "source": "grepapp"},
                confidence=0.75,
            )
            entities.append(repo_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=repo_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "hits": len(hits)}),
            metadata={"ok": True, "repos": len(hits)},
        )


class SearchcodeCollector(BaseCollector):
    """Searchcode.com: búsqueda en código (gratis, sin key)."""

    def __init__(self) -> None:
        super().__init__(name="searchcode")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://searchcode.com/api/codesearch_I/?q={quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN, domain, f"Dominio: {domain}", attributes={"source": "searchcode"}
        )
        entities.append(root)
        results = data.get("results", [])
        for item in results[:20]:
            repo = str(item.get("repo", ""))
            filename = str(item.get("filename", ""))
            item_url = str(item.get("url", ""))[:300]
            if not repo:
                continue
            label = f"{repo}/{filename}" if filename else repo
            node = EntityNode.create(
                EntityType.ALIAS,
                label,
                f"Código: {label}",
                attributes={"url": item_url, "source": "searchcode"},
                confidence=0.75,
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
            raw_payload=json.dumps({"domain": domain, "results": len(results)}),
            metadata={"ok": True, "results": len(results)},
        )

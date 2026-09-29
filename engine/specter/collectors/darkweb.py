"""
WraithOSINT - Dark Web Collectors
Búsquedas en la dark web para menciones de objetivos.

- Ahmia: buscador de servicios ocultos (sin key, clearnet)
- TORCH: buscador de la dark web más antiguo (sin key, onion)
- Onion.link: directorio de enlaces onion (sin key, clearnet)

Todos los colectores manejan timeouts y errores gracefully. Si una fuente
no está disponible, retorna ok=False con el error en metadata.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import quote

import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.darkweb")

_TIMEOUT = 20.0
# ASCII estricto: httpx codifica los headers en ASCII.
_UA = {"User-Agent": "WraithOSINT/0.3 (+forense, key en boveda local)"}


class AhmiaCollector(BaseCollector):
    """Ahmia: buscador de servicios ocultos en la dark web.

    API: https://ahmia.fi/search/?q={query}
    Retorna menciones en la dark web con título, URL onion y descripción.
    """

    def __init__(self) -> None:
        super().__init__(name="ahmia")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        query = target.strip()
        url = f"https://ahmia.fi/search/?q={quote(query)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=query,
                raw_payload=json.dumps({"query": query, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.ALIAS, query, f"Búsqueda: {query}", attributes={"source": "ahmia"}
        )
        entities.append(root)

        # Ahmia retorna URLs onion en atributos redirect_url
        links = re.findall(r'redirect_url=([^"]+)', html, re.IGNORECASE | re.DOTALL)

        seen_urls: set[str] = set()
        for link in links[:50]:
            link = link.strip()
            if not link or link in seen_urls:
                continue
            if ".onion" not in link:
                continue
            seen_urls.add(link)

            onion_node = EntityNode.create(
                EntityType.ALIAS,
                link,
                f"Onion: {link[:80]}",
                attributes={"source": "ahmia", "url_type": "onion"},
                confidence=0.7,
            )
            entities.append(onion_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=onion_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"query": query, "urls": list(seen_urls)}, ensure_ascii=False),
            metadata={"ok": True, "results": len(seen_urls)},
        )


class TorCHCollector(BaseCollector):
    """TORCH: buscador de la dark web más antiguo y con más páginas indexadas.

    API: http://torchdeedp3i2jigzjdmfpn5ttjhthh5wlo667czjscjpxnfpyd.onion/search?query={query}
    Nota: usar fallback HTTP si no hay Tor disponible.
    Retorna resultados de búsqueda en la dark web.
    """

    def __init__(self) -> None:
        super().__init__(name="torch")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        query = target.strip()
        # Intentar vía Tor (onion) primero, luego fallback a HTTP
        onion_url = (
            "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wlo667czjscjpxnfpyd.onion"
            f"/search?query={quote(query)}"
        )
        # Fallback HTTP (algunos proxies clearnet permiten acceso)
        http_url = f"https://torchsearch.wordpress.com/?s={quote(query)}"

        html = ""
        used_fallback = False
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(onion_url, headers=_UA)
                resp.raise_for_status()
                html = resp.text
        except Exception:
            # Fallback a HTTP si no hay Tor
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(http_url, headers=_UA)
                    resp.raise_for_status()
                    html = resp.text
                    used_fallback = True
            except Exception as exc:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=query,
                    raw_payload=json.dumps({"query": query, "error": str(exc)}),
                    metadata={"ok": False},
                )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.ALIAS, query, f"Búsqueda: {query}", attributes={"source": "torch"}
        )
        entities.append(root)

        # TORCH retorna enlaces en <h5><a href="..." target="_blank">
        links = re.findall(r'<h5><a href="(.*?)"\s+target="_blank">', html, re.IGNORECASE)

        seen_urls: set[str] = set()
        for link in links[:50]:
            link = link.strip()
            if not link or link in seen_urls:
                continue
            seen_urls.add(link)

            onion_node = EntityNode.create(
                EntityType.ALIAS,
                link,
                f"Onion: {link[:80]}",
                attributes={"source": "torch", "url_type": "onion"},
                confidence=0.7,
            )
            entities.append(onion_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=onion_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"query": query, "urls": list(seen_urls), "fallback": used_fallback},
                ensure_ascii=False,
            ),
            metadata={"ok": True, "results": len(seen_urls), "fallback": used_fallback},
        )


class OnionLinkCollector(BaseCollector):
    """Onion.link: directorio de enlaces onion de la dark web.

    API: https://onion.link/search?q={query}
    Retorna URLs onion y títulos de servicios ocultos.
    """

    def __init__(self) -> None:
        super().__init__(name="onion_link")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        query = target.strip()
        url = f"https://onion.link/search?q={quote(query)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=query,
                raw_payload=json.dumps({"query": query, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.ALIAS, query, f"Búsqueda: {query}", attributes={"source": "onion_link"}
        )
        entities.append(root)

        # Onion.link retorna enlaces onion en href
        links = re.findall(r'href="(https?://[^"]+\.onion[^"]*)"', html, re.IGNORECASE)

        seen_urls: set[str] = set()
        for link in links[:50]:
            link = link.strip()
            if not link or link in seen_urls:
                continue
            seen_urls.add(link)

            onion_node = EntityNode.create(
                EntityType.ALIAS,
                link,
                f"Onion: {link[:80]}",
                attributes={"source": "onion_link", "url_type": "onion"},
                confidence=0.7,
            )
            entities.append(onion_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=onion_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"query": query, "urls": list(seen_urls)}, ensure_ascii=False),
            metadata={"ok": True, "results": len(seen_urls)},
        )

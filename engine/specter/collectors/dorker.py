"""
SpecterOSINT - Passive Search Engine & Document Hunter Collector
Búsqueda pasiva de menciones en la web, filtraciones (leaks/pastes) y descubrimiento automático
de documentos (PDF, DOCX) con extracción forense de metadatos integrada.
"""

import json
import re
from typing import Any
from urllib.parse import unquote

import httpx
from specter.collectors.artifacts import FileForensics
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)


class DocumentHunter(BaseCollector):
    def __init__(self):
        super().__init__(name="document_hunter")
        self.file_forensics = FileForensics()

    async def _query_duckduckgo(self, client: httpx.AsyncClient, query: str) -> list[str]:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        found_urls = []
        try:
            resp = await client.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query},
                headers=headers,
                timeout=8.0,
            )
            if resp.status_code == 200:
                matches = re.findall(r'<a class="result__snippet"[^>]*href="([^"]+)"', resp.text)
                if not matches:
                    matches = re.findall(
                        r'<a[^>]+class="result__url"[^>]*href="([^"]+)"', resp.text
                    )
                if not matches:
                    matches = re.findall(r'href="([^"]*uddg=[^"]*)"', resp.text)

                for m in matches:
                    if "uddg=" in m:
                        real_url = unquote(m.split("uddg=")[1].split("&")[0])
                        found_urls.append(real_url)
                    elif m.startswith("http"):
                        found_urls.append(m)
        except Exception:
            pass

        # Deduplicar preservando orden
        seen = set()
        deduped = []
        for u in found_urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        identifier = target.strip().lstrip("@")
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        intel_report: dict[str, Any] = {
            "target": identifier,
            "pdf_documents": [],
            "pastes_and_mentions": [],
            "web_mentions": [],
        }

        # Nodo raíz del objetivo (Alias o Dominio)
        if "." in identifier and not identifier.startswith(" "):
            root_node = EntityNode.create(EntityType.DOMAIN, identifier, f"Domain: {identifier}")
        else:
            root_node = EntityNode.create(EntityType.ALIAS, identifier, f"Alias: @{identifier}")
        entities.append(root_node)

        limits = httpx.Limits(max_connections=20)
        async with httpx.AsyncClient(limits=limits, timeout=12.0) as client:
            # 1. Búsqueda de documentos PDF específicos
            pdf_urls = await self._query_duckduckgo(client, f'"{identifier}" filetype:pdf')
            # 2. Búsqueda de menciones y pastes
            leak_urls = await self._query_duckduckgo(
                client, f'"{identifier}" (pastebin OR rentry.co OR leak OR breach)'
            )
            # 3. Búsqueda de menciones web generales
            general_urls = await self._query_duckduckgo(client, f'"{identifier}"')

        intel_report["pdf_documents"] = pdf_urls[:5]
        intel_report["pastes_and_mentions"] = leak_urls[:5]
        intel_report["web_mentions"] = general_urls[:10]

        # Procesamiento forense de documentos PDF encontrados
        for pdf_url in pdf_urls[:3]:
            try:
                # Descargar e inspeccionar metadatos con FileForensics
                doc_result = await self.file_forensics.collect(pdf_url)
                entities.extend(doc_result.entities)
                relations.extend(doc_result.relations)

                # Vincular el documento encontrado con el target
                for e in doc_result.entities:
                    if e.type == EntityType.FILE_ARTIFACT:
                        relations.append(
                            RelationEdge(
                                source_id=root_node.id,
                                target_id=e.id,
                                relation_type=RelationType.ASSOCIATED_WITH,
                                attributes={
                                    "discovery_query": "filetype:pdf",
                                    "source_url": pdf_url,
                                },
                            )
                        )
            except Exception as e:
                intel_report[f"error_{pdf_url[:30]}"] = str(e)

        # Vincular menciones web y pastes
        for mention in (leak_urls + general_urls)[:10]:
            mention_node = EntityNode.create(
                type=EntityType.SOCIAL_PROFILE
                if any(s in mention for s in ["github", "reddit", "twitter", "x.com"])
                else EntityType.DOMAIN,
                value=mention,
                label=f"Mention: {mention[:35]}...",
                attributes={"url": mention, "source": "DuckDuckGo Intelligence"},
                confidence=0.85,
            )
            entities.append(mention_node)
            relations.append(
                RelationEdge(
                    source_id=root_node.id,
                    target_id=mention_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                    confidence=0.85,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=identifier,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(intel_report, indent=2),
            metadata={
                "pdfs_discovered": len(pdf_urls),
                "leaks_discovered": len(leak_urls),
                "web_mentions_discovered": len(general_urls),
            },
        )

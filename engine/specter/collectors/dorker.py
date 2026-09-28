"""
SpecterOSINT - Passive Search Engine & Document Hunter Collector
Búsqueda pasiva de menciones en la web, filtraciones (leaks/pastes) y descubrimiento automático
de documentos (PDF, DOCX) con extracción forense de metadatos integrada.
"""

import json
import re
from typing import Any

import httpx
from specter.collectors.artifacts import FileForensics
from specter.collectors.base import BaseCollector
from specter.collectors.person import (
    build_official_dorks,
    build_repository_dorks,
    detect_context_tld,
)
from specter.collectors.web import ddg_html_status, parse_ddg_html
from specter.httpx_transport import http_post
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

# Documento de identidad ES/LATAM (espejo de specter.triage): un DNI/CUIT/RUT
# no es un alias y no debe tipificarse como tal en el grafo.
_DOCUMENT_RE = re.compile(
    r"^(?:\d{7,8}|\d{8}[A-Z]|[XYZ]\d{7}[A-Z]|\d{2}-?\d{8}-?\d"
    r"|\d{1,2}\.?\d{3}\.?\d{3}-[\dkK])$",
    re.IGNORECASE,
)

# Pivotes dinámicos: identificadores que aparecen en el contexto del caso y
# que merecen su propia ronda de búsqueda (el "pivot loop" que hacía el
# analista a mano: hallazgo → seed → nueva búsqueda).
_SEED_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_SEED_CODE_RE = re.compile(r"(?<![\w-])\d{6,12}(?![\w-])")
_SEED_MAX = 2


def _seed_pivots(identifier: str, context: str) -> list[str]:
    """Identificadores (emails, códigos numéricos) hallados en el contexto.

    Nunca devuelve el propio target ni duplicados: son semillas NUEVAS. Un
    código universitario '11223344' mencionado en un documento del caso entra
    aquí y dispara su propia búsqueda documental.
    """
    text = f"{identifier} {context}"
    seeds: list[str] = []
    for candidate in (*_SEED_EMAIL_RE.findall(text), *_SEED_CODE_RE.findall(text)):
        value = candidate.strip().rstrip(".,;:")
        if value.lower() == identifier.lower():
            continue
        if value not in seeds:
            seeds.append(value)
        if len(seeds) >= _SEED_MAX:
            break
    return seeds


class _WaybackClient:
    """Cliente efímero para Wayback: se usa fuera del scope del client principal.

    En producción abre su propia conexión; en tests hereda el MockRouter del
    arnés (http_mock parchea httpx.AsyncClient globalmente).
    """

    async def get(
        self, url: str, params: dict[str, str] | None = None, timeout: float = 10.0
    ) -> httpx.Response:
        async with httpx.AsyncClient() as client:
            return await client.get(url, params=params, timeout=timeout)


class DocumentHunter(BaseCollector):
    def __init__(self):
        super().__init__(name="document_hunter")
        self.file_forensics = FileForensics()

    async def _query_duckduckgo(
        self,
        client: httpx.AsyncClient,
        query: str,
        diagnostics: list[dict[str, Any]] | None = None,
    ) -> list[str]:
        # Nota: este colector NO pasa por el navegador sigiloso (dorker opera
        # sobre el HTML de DuckDuckGo con su propia lógica de dedupe y
        # extracción forense); el navegador queda para web_search/web_fetch.

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        found_urls: list[str] = []
        outcome: dict[str, Any] = {
            "query": query,
            "provider": "ddg_html",
            "status": "error",
            "results": 0,
            "transport": "curl_cffi",
        }
        try:
            try:
                resp = await http_post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": query},
                    headers=headers,
                    timeout=8.0,
                )
            except Exception as primary_exc:
                # El client existente queda como fallback explícito si curl_cffi
                # no puede arrancar en esta instalación.
                try:
                    resp = await client.post(
                        "https://html.duckduckgo.com/html/",
                        data={"q": query},
                        headers=headers,
                        timeout=8.0,
                    )
                    outcome["transport"] = "httpx_fallback"
                except Exception as fallback_exc:
                    raise RuntimeError(
                        f"curl_cffi: {primary_exc}; httpx: {fallback_exc}"
                    ) from fallback_exc
            if resp.status_code >= 400:
                outcome.update(status="error", error=f"http_{resp.status_code}")
            else:
                parsed = parse_ddg_html(resp.text)
                found_urls = [item["url"] for item in parsed if item.get("url")]
                outcome["status"], reason = ddg_html_status(resp.text, len(found_urls))
                if reason:
                    outcome["error"] = reason
                outcome["results"] = len(found_urls)
        except Exception as exc:
            outcome["error"] = f"{type(exc).__name__}: {exc}"
        # Deduplicar preservando orden
        seen = set()
        deduped = []
        for u in found_urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        outcome["results"] = len(deduped)
        if diagnostics is not None:
            diagnostics.append(outcome)
        return deduped

    async def _wayback_snapshot(self, client: httpx.AsyncClient, url: str) -> str | None:
        """Snapshot más cercano en Wayback Machine para una URL caída (o None)."""
        try:
            resp = await client.get(
                "http://archive.org/wayback/available",
                params={"url": url},
                timeout=10.0,
            )
            if resp.status_code != 200:
                return None
            snapshot = (resp.json().get("archived_snapshots") or {}).get("closest") or {}
            snapshot_url = snapshot.get("url")
            return str(snapshot_url) if snapshot.get("available") and snapshot_url else None
        except Exception:
            return None

    async def collect(self, target: str, context: str = "", **kwargs: Any) -> CollectorResult:
        identifier = target.strip().lstrip("@")
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        # El contexto (hallazgos previos del caso) alimenta el país de los
        # dorks oficiales y los pivotes dinámicos: nada hardcodeado.
        context_tld = detect_context_tld(f"{identifier} {context}")
        seed_pivots = _seed_pivots(identifier, context)
        intel_report: dict[str, Any] = {
            "target": identifier,
            "pdf_documents": [],
            "pastes_and_mentions": [],
            "web_mentions": [],
            "official_mentions": [],
            "repository_mentions": [],
            "seed_pivots": seed_pivots,
            "context_tld": context_tld,
        }
        search_diagnostics: list[dict[str, Any]] = []

        # Nodo raíz tipificado: un DNI/CUIT/RUT no es un alias (antes se
        # registraba como `Alias: @99999999`, ruido en el grafo y en la UI).
        if _DOCUMENT_RE.match(identifier):
            root_node = EntityNode.create(
                EntityType.DOCUMENT_ID, identifier, f"Documento: {identifier}"
            )
        elif "." in identifier and not identifier.startswith(" "):
            root_node = EntityNode.create(EntityType.DOMAIN, identifier, f"Domain: {identifier}")
        else:
            root_node = EntityNode.create(EntityType.ALIAS, identifier, f"Alias: @{identifier}")
        entities.append(root_node)

        limits = httpx.Limits(max_connections=20)
        async with httpx.AsyncClient(limits=limits, timeout=12.0) as client:
            # 1. Búsqueda de documentos PDF específicos
            pdf_urls = await self._query_duckduckgo(
                client, f'"{identifier}" filetype:pdf', search_diagnostics
            )
            # 2. Búsqueda de menciones y pastes
            leak_urls = await self._query_duckduckgo(
                client,
                f'"{identifier}" (pastebin OR rentry.co OR leak OR breach)',
                search_diagnostics,
            )
            # 3. Búsqueda de menciones web generales
            general_urls = await self._query_duckduckgo(
                client, f'"{identifier}"', search_diagnostics
            )
            # 4. Repositorios de documentos: Scribd/Studocu/CourseHero/etc.
            #    Ahí viven la mayoría de documentos académicos nominales.
            repository_urls: list[str] = []
            for dork in build_repository_dorks(identifier):
                repository_urls.extend(
                    await self._query_duckduckgo(client, dork, search_diagnostics)
                )
            repository_urls = list(dict.fromkeys(repository_urls))
            # 5. Fuentes oficiales del país detectado en el contexto: un DNI
            #    o nombre rara vez aparece en pastes, pero sí en designaciones,
            #    edictos y actas publicadas. El país lo da el TLD del contexto.
            official_urls: list[str] = []
            if root_node.type == EntityType.DOCUMENT_ID or context_tld != "com":
                for dork in build_official_dorks(identifier, context_tld):
                    official_urls.extend(
                        await self._query_duckduckgo(client, dork, search_diagnostics)
                    )
                official_urls = list(dict.fromkeys(official_urls))
            # 6. Pivot loop: cada identificador hallado en el contexto es una
            #    semilla nueva (código universitario, email del caso...).
            pivot_urls: dict[str, list[str]] = {}
            for seed in seed_pivots:
                pivot_urls[seed] = (
                    await self._query_duckduckgo(
                        client, f'"{seed}" filetype:pdf', search_diagnostics
                    )
                )[:5]

        intel_report["search_diagnostics"] = search_diagnostics
        intel_report["pdf_documents"] = pdf_urls[:5]
        intel_report["pastes_and_mentions"] = leak_urls[:5]
        intel_report["web_mentions"] = general_urls[:10]
        intel_report["official_mentions"] = official_urls[:10]
        intel_report["repository_mentions"] = repository_urls[:10]
        intel_report["pivot_hits"] = {k: v for k, v in pivot_urls.items()}

        # Procesamiento forense de documentos PDF encontrados. Si la descarga
        # falla (403/Cloudflare/eliminado), se intenta el snapshot de Wayback
        # antes de dar el documento por irrecuperable.
        for pdf_url in pdf_urls[:3]:
            try:
                doc_result = await self.file_forensics.collect(pdf_url)
            except Exception as exc:
                snapshot = await self._wayback_snapshot(_WaybackClient(), pdf_url)
                if not snapshot:
                    intel_report[f"error_{pdf_url[:30]}"] = str(exc)
                    continue
                try:
                    doc_result = await self.file_forensics.collect(snapshot)
                    intel_report["wayback_recovered"] = intel_report.get(
                        "wayback_recovered", []
                    ) + [pdf_url]
                except Exception as exc2:
                    intel_report[f"error_{pdf_url[:30]}"] = str(exc2)
                    continue
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

        # Vincular menciones web, pastes, fuentes oficiales y repositorios.
        seen_mentions: set[str] = set()

        def _mention_node(mention: str, bucket: str, seed: str | None = None) -> EntityNode:
            node = EntityNode.create(
                type=EntityType.SOCIAL_PROFILE
                if any(s in mention for s in ["github", "reddit", "twitter", "x.com"])
                else EntityType.DOMAIN,
                value=mention,
                label=f"Mention: {mention[:35]}...",
                attributes={
                    "url": mention,
                    "source": "DuckDuckGo Intelligence",
                    "bucket": bucket,
                    "candidate": True,
                    **({"seed": seed} if seed else {}),
                },
                confidence=0.5,
            )
            entities.append(node)
            relations.append(
                RelationEdge(
                    source_id=root_node.id,
                    target_id=node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                    confidence=0.5,
                )
            )
            return node

        for mention in (leak_urls + general_urls + official_urls)[:15]:
            if mention in seen_mentions:
                continue
            seen_mentions.add(mention)
            _mention_node(mention, "general")
        for mention in repository_urls[:10]:
            if mention in seen_mentions:
                continue
            seen_mentions.add(mention)
            _mention_node(mention, "repository")
        for seed, urls in pivot_urls.items():
            for mention in urls:
                if mention in seen_mentions:
                    continue
                seen_mentions.add(mention)
                _mention_node(mention, "pivot", seed=seed)

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
                "official_mentions_discovered": len(official_urls),
                "repository_mentions_discovered": len(repository_urls),
                "seeds_pivoted": seed_pivots,
                "context_tld": context_tld,
                "searches_attempted": len(search_diagnostics),
                "search_diagnostics": search_diagnostics,
                "search_failures": sum(
                    item["status"] not in {"results", "no_results"} for item in search_diagnostics
                ),
            },
        )

"""Bounded multi-source web research with page reading and evidence pivots."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

from specter.collectors.base import BaseCollector
from specter.collectors.person import build_person_search_queries, strip_accents
from specter.collectors.web import WebFetchCollector, WebSearchCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![\w@])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
_CAPITALIZED = r"[A-ZÁÉÍÓÚÜÑ][a-záéíóúüñ]+(?:[-'][A-ZÁÉÍÓÚÜÑ]?[a-záéíóúüñ]+)?"
_NAME_RE = re.compile(rf"\b{_CAPITALIZED}(?:\s+{_CAPITALIZED}){{1,3}}\b")
_SOCIAL_HOSTS = (
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "gitlab.com",
    "reddit.com",
    "x.com",
    "twitter.com",
    "tiktok.com",
    "youtube.com",
    "youtu.be",
)
_GENERIC_HOSTS = {
    "google.com",
    "bing.com",
    "duckduckgo.com",
    "microsoft.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "gitlab.com",
    "reddit.com",
    "x.com",
    "twitter.com",
    "tiktok.com",
    "youtube.com",
    "youtu.be",
    "wikipedia.org",
}
_NAME_STOP_PHRASES = {
    "about us",
    "contact us",
    "privacy policy",
    "terms service",
    "terms conditions",
    "read more",
    "learn more",
    "search results",
    "no results",
    "sign in",
    "sign up",
    "all rights reserved",
    "política privacidad",
    "términos servicio",
    "leer más",
    "más información",
}
_ORG_MARKERS = {
    "association",
    "college",
    "company",
    "corp",
    "corporation",
    "foundation",
    "fundación",
    "hospital",
    "institute",
    "instituto",
    "llc",
    "ltd",
    "ministry",
    "ministerio",
    "municipalidad",
    "organization",
    "organización",
    "sac",
    "srl",
    "university",
    "universidad",
}


def _normalize(value: str) -> str:
    return " ".join(strip_accents(value).casefold().split())


def _target_type(value: str, requested: str) -> str:
    allowed = {"auto", "person", "organization", "domain", "email", "username"}
    normalized = requested.strip().lower()
    if normalized not in allowed:
        raise ValueError(f"target_type debe ser uno de {sorted(allowed)}")
    if normalized != "auto":
        return normalized
    target = value.strip().lstrip("@")
    if _EMAIL_RE.fullmatch(target):
        return "email"
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.hostname and "." in parsed.hostname and " " not in target:
        return "domain"
    if len(target.split()) > 1:
        return "person"
    return "username"


def _seed_queries(target: str, kind: str, context: str = "") -> list[str]:
    if kind == "person":
        return build_person_search_queries(target, context=context)
    if kind == "domain":
        domain = urlparse(target if "://" in target else f"https://{target}").hostname or target
        return [
            f'"{domain}"',
            f"site:{domain}",
            f"site:{domain} (contact OR about OR team OR staff)",
            f"site:{domain} (filetype:pdf OR filetype:docx)",
            f'"{domain}" (owner OR registrar OR certificate)',
        ]
    if kind == "email":
        local, _, domain = target.partition("@")
        return [
            f'"{target}"',
            f'"{target}" (profile OR contact OR cv OR resume)',
            f'"{local}" "{domain}"',
            f'"{target}" (pastebin OR rentry OR breach)',
        ]
    if kind == "organization":
        return [
            f'"{target}"',
            target,
            f'"{target}" (leadership OR team OR staff OR board)',
            f'"{target}" (site:linkedin.com/company OR site:github.com)',
            f'"{target}" (filetype:pdf OR filetype:docx)',
            f'"{target}" (news OR press OR announcement)',
        ]
    username = target.strip().lstrip("@")
    return [
        f'"{username}"',
        f'"@{username}"',
        f'"{username}" (site:github.com OR site:gitlab.com)',
        f'"{username}" (site:reddit.com OR site:x.com OR site:instagram.com)',
        f'"{username}" (profile OR portfolio OR blog)',
    ]


def _budget_seed_queries(queries: list[str], limit: int, kind: str) -> list[str]:
    """Keep exact person-name variants and sample across all dork families."""
    if len(queries) <= limit:
        return queries
    if kind != "person" or limit <= 3:
        return queries[:limit]

    selected = queries[:3]
    remainder = queries[3:]
    slots = limit - len(selected)
    if slots == 1:
        selected.append(remainder[0])
    else:
        last = len(remainder) - 1
        indexes = [round(i * last / (slots - 1)) for i in range(slots)]
        selected.extend(remainder[index] for index in indexes)
    return list(dict.fromkeys(selected))[:limit]


def _pivot_candidates(text: str, target: str) -> list[tuple[EntityType, str]]:
    found: dict[tuple[EntityType, str], None] = {}
    normalized_target = _normalize(target)
    email_domains: set[str] = set()
    for match in _EMAIL_RE.findall(text):
        value = match.rstrip(".,;:)")
        email_domains.add(value.rsplit("@", 1)[-1].casefold())
        if _normalize(value) != normalized_target:
            found[(EntityType.EMAIL, value)] = None

    for match in _DOMAIN_RE.findall(text):
        value = match.rstrip(".,;:)").lower()
        if value in email_domains or value in _GENERIC_HOSTS:
            continue
        if value.split(".")[-1] in {"pdf", "doc", "docx", "jpg", "jpeg", "png", "gif"}:
            continue
        if value in normalized_target or normalized_target in value:
            continue
        found[(EntityType.DOMAIN, value)] = None

    for match in _NAME_RE.findall(text):
        value = " ".join(match.split()).strip(" ,.;:")
        normalized = _normalize(value)
        if (
            len(normalized) < 6
            or normalized in normalized_target
            or normalized_target in normalized
            or normalized in _NAME_STOP_PHRASES
        ):
            continue
        words = set(normalized.split())
        kind = EntityType.ORGANIZATION if words & _ORG_MARKERS else EntityType.PERSON
        found[(kind, value)] = None
    return list(found.keys())[:80]


def _source_pivots(text: str, target: str, source_url: str) -> list[tuple[EntityType, str]]:
    host = (urlparse(source_url).hostname or "").lower()
    pivots = []
    for pivot_type, value in _pivot_candidates(text, target):
        domain = value.lower()
        if (
            pivot_type == EntityType.DOMAIN
            and host
            and (domain == host or domain.endswith(f".{host}") or host.endswith(f".{domain}"))
        ):
            continue
        pivots.append((pivot_type, value))
    return pivots


class DeepResearchCollector(BaseCollector):
    """Runs bounded web search, page extraction, and query pivots."""

    def __init__(
        self,
        search_collector: WebSearchCollector | None = None,
        fetch_collector: WebFetchCollector | None = None,
    ) -> None:
        super().__init__(name="deep_research")
        self.search_collector = search_collector or WebSearchCollector()
        self.fetch_collector = fetch_collector or WebFetchCollector()

    async def _read_page(self, hit: dict[str, Any]) -> dict[str, Any]:
        url = str(hit.get("url") or "")
        try:
            result = await asyncio.wait_for(
                self.fetch_collector.collect(url, max_chars=12_000, timeout=20),
                timeout=25,
            )
            payload = json.loads(result.raw_payload or "{}")
            if not result.metadata.get("ok"):
                return {
                    "url": url,
                    "status": "error",
                    "error": payload.get("error", "fetch_failed"),
                }
            text = str(payload.get("text") or "")
            return {
                "url": url,
                "status": "truncated" if payload.get("truncated") else "read",
                "title": str(payload.get("title") or hit.get("title") or ""),
                "text": text,
                "chars_total": payload.get("chars_total", len(text)),
                "truncated": bool(payload.get("truncated")),
                "query_depth": hit.get("query_depth", 0),
                "queries": hit.get("queries", []),
                "search_engines": hit.get("search_engines", []),
            }
        except Exception as exc:
            return {"url": url, "status": "error", "error": f"{type(exc).__name__}: {exc}"}

    @staticmethod
    def _select_pages(hits: Iterable[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
        ranked = sorted(
            hits,
            key=lambda hit: (
                -len(hit.get("search_engines", [])),
                min(
                    (int(item.get("rank", 99)) for item in hit.get("observations", [])),
                    default=99,
                ),
                -len(str(hit.get("snippet") or "")),
                str(hit.get("url") or ""),
            ),
        )
        selected: list[dict[str, Any]] = []
        seen_hosts: set[str] = set()
        for distinct_host_pass in (True, False):
            for hit in ranked:
                if hit in selected:
                    continue
                host = (urlparse(str(hit.get("url") or "")).hostname or "").lower()
                if distinct_host_pass and host in seen_hosts:
                    continue
                selected.append(hit)
                seen_hosts.add(host)
                if len(selected) >= limit:
                    return selected
        return selected

    async def collect(
        self,
        target: str,
        target_type: str = "auto",
        max_queries: int = 30,
        max_pages: int = 12,
        max_depth: int = 2,
        context: str = "",
        **kwargs: Any,
    ) -> CollectorResult:
        target = " ".join(str(target).split())
        if not target:
            raise ValueError("Objetivo vacío")
        if len(target) > 500:
            raise ValueError("Objetivo demasiado largo (máximo 500 caracteres)")
        kind = _target_type(target, target_type)
        query_budget = max(1, min(int(max_queries), 40))
        page_budget = max(1, min(int(max_pages), 20))
        depth_budget = max(0, min(int(max_depth), 2))
        root_values = {
            "person": (EntityType.PERSON, target),
            "organization": (EntityType.ORGANIZATION, target),
            "domain": (
                EntityType.DOMAIN,
                urlparse(target if "://" in target else f"https://{target}").hostname or target,
            ),
            "email": (EntityType.EMAIL, target),
            "username": (EntityType.ALIAS, target.lstrip("@")),
        }
        root_type, root_value = root_values[kind]
        root = EntityNode.create(
            root_type,
            root_value,
            f"Objetivo: {root_value}",
            attributes={"research_type": kind, "derived_from": "deep_research_input"},
        )

        initial_queries = _seed_queries(target, kind, context=context)
        if depth_budget:
            seed_budget = max(1, query_budget // 2)
            initial_queries = _budget_seed_queries(initial_queries, seed_budget, kind)
            remaining_for_pivots = query_budget - len(initial_queries)
            pivot_batch_budget = max(
                1,
                (remaining_for_pivots + depth_budget - 1) // depth_budget,
            )
        else:
            initial_queries = initial_queries[:query_budget]
            pivot_batch_budget = 0
        queries_seen: set[str] = set()
        next_queries = initial_queries
        query_runs: list[dict[str, Any]] = []
        provider_status: dict[str, dict[str, int]] = {}
        hits_by_url: dict[str, dict[str, Any]] = {}
        pages_by_url: dict[str, dict[str, Any]] = {}
        pivots: dict[tuple[EntityType, str], dict[str, Any]] = {}
        pivots_searched: set[str] = set()
        pages_read = 0
        pages_attempted = 0
        pivot_query_values: dict[str, str] = {}
        stop_reason = "no_new_pivots"

        for depth in range(depth_budget + 1):
            unique_queries: list[str] = []
            for query in next_queries:
                key = " ".join(query.split()).casefold()
                if key and key not in queries_seen:
                    queries_seen.add(key)
                    unique_queries.append(" ".join(query.split()))
                if len(queries_seen) >= query_budget:
                    break
            remaining_budget = query_budget - len(query_runs)
            unique_queries = unique_queries[:remaining_budget]
            if not unique_queries:
                stop_reason = (
                    "query_budget_reached" if len(query_runs) >= query_budget else "no_new_pivots"
                )
                break
            for query in unique_queries:
                if normalized_query := pivot_query_values.get(query.casefold()):
                    pivots_searched.add(normalized_query)

            search_result = await self.search_collector.collect_many(
                unique_queries, top_k=5, concurrency=3
            )
            query_runs.extend(search_result.metadata.get("query_runs", []))
            for engine, states in search_result.metadata.get("provider_status", {}).items():
                totals = provider_status.setdefault(engine, {})
                for state, count in states.items():
                    totals[state] = totals.get(state, 0) + int(count)

            for node in search_result.entities[1:]:
                attrs = dict(node.attributes)
                url = str(attrs.get("url") or node.value)
                canonical = str(attrs.get("canonical_url") or url)
                hit = {
                    "type": node.type.value,
                    "url": url,
                    "canonical_url": canonical,
                    "title": str(attrs.get("title") or ""),
                    "snippet": str(attrs.get("snippet") or ""),
                    "search_engines": list(attrs.get("search_engines") or []),
                    "queries": list(attrs.get("queries") or []),
                    "observations": list(attrs.get("observations") or []),
                    "query_depth": depth,
                }
                if canonical in hits_by_url:
                    current = hits_by_url[canonical]
                    current["search_engines"] = sorted(
                        set(current["search_engines"]) | set(hit["search_engines"])
                    )
                    current["queries"] = sorted(set(current["queries"]) | set(hit["queries"]))
                    current["observations"].extend(
                        item for item in hit["observations"] if item not in current["observations"]
                    )
                    if not current["title"] and hit["title"]:
                        current["title"] = hit["title"]
                    if len(hit["snippet"]) > len(current["snippet"]):
                        current["snippet"] = hit["snippet"]
                else:
                    hits_by_url[canonical] = hit
                for pivot_type, value in _source_pivots(
                    f"{hit['title']} {hit['snippet']}", target, url
                ):
                    pivot_key = (pivot_type, _normalize(value))
                    entry = pivots.setdefault(
                        pivot_key,
                        {"type": pivot_type, "value": value, "sources": [], "depth": depth},
                    )
                    source = {"url": url, "query": hit["queries"][:3]}
                    if source not in entry["sources"]:
                        entry["sources"].append(source)

            available_pages = [
                hit for hit in hits_by_url.values() if hit["canonical_url"] not in pages_by_url
            ]
            page_slots = page_budget - pages_attempted
            selected = self._select_pages(available_pages, page_slots) if page_slots > 0 else []
            pages_attempted += len(selected)
            semaphore = asyncio.Semaphore(4)

            async def read(
                hit: dict[str, Any], _sem: asyncio.Semaphore = semaphore
            ) -> dict[str, Any]:
                async with _sem:
                    return await self._read_page(hit)

            page_reports = await asyncio.gather(*(read(hit) for hit in selected))
            for page in page_reports:
                canonical = next(
                    (key for key, hit in hits_by_url.items() if hit["url"] == page["url"]),
                    page["url"].casefold(),
                )
                pages_by_url[canonical] = page
                if page["status"] in {"read", "truncated"}:
                    pages_read += 1
                    source_hit = hits_by_url.get(canonical, {})
                    for pivot_type, value in _source_pivots(
                        f"{page.get('title', '')} {page.get('text', '')}", target, page["url"]
                    ):
                        pivot_key = (pivot_type, _normalize(value))
                        entry = pivots.setdefault(
                            pivot_key,
                            {
                                "type": pivot_type,
                                "value": value,
                                "sources": [],
                                "depth": depth,
                            },
                        )
                        source = {
                            "url": page["url"],
                            "query": source_hit.get("queries", [])[:3],
                        }
                        if source not in entry["sources"]:
                            entry["sources"].append(source)

            next_pivots: list[dict[str, Any]] = []
            for key, pivot in pivots.items():
                pivot_id = _normalize(str(pivot["value"]))
                if pivot_id == _normalize(root_value) or pivot_id in pivots_searched:
                    continue
                if key[0] == EntityType.DOMAIN:
                    query = f"site:{pivot['value']}"
                else:
                    query = f'"{pivot["value"]}"'
                next_pivots.append({**pivot, "query": query})
            next_pivots.sort(
                key=lambda item: (
                    item["type"] not in {EntityType.EMAIL, EntityType.ORGANIZATION},
                    -len(item["sources"]),
                    item["value"].casefold(),
                )
            )
            for item in next_pivots:
                item["searched"] = False
            max_next = min(
                pivot_batch_budget,
                query_budget - len(query_runs),
            )
            next_queries = [item["query"] for item in next_pivots[:max_next]]
            for item in next_pivots[:max_next]:
                pivot_query_values[item["query"].casefold()] = _normalize(item["value"])

            if not search_result.metadata.get("ok") and not hits_by_url:
                stop_reason = "search_providers_unavailable"
                break
            if len(search_result.entities) <= 1 and not hits_by_url:
                stop_reason = "no_search_results"
                break
            if not next_queries:
                if next_pivots and depth >= depth_budget:
                    stop_reason = "depth_budget_reached"
                elif next_pivots and len(query_runs) >= query_budget:
                    stop_reason = "query_budget_reached"
                else:
                    stop_reason = "no_new_pivots"
                break
            if depth >= depth_budget:
                stop_reason = "depth_budget_reached"
                break
            if len(query_runs) >= query_budget:
                stop_reason = "query_budget_reached"
                break

        page_lookup: dict[str, dict[str, Any]] = {}
        for hit in hits_by_url.values():
            page = pages_by_url.get(hit["canonical_url"], {})
            host = urlparse(hit["url"]).hostname or ""
            node_type = (
                EntityType.SOCIAL_PROFILE
                if any(host == social or host.endswith(f".{social}") for social in _SOCIAL_HOSTS)
                else EntityType.DOMAIN
            )
            attrs = {
                "url": hit["url"],
                "canonical_url": hit["canonical_url"],
                "title": hit["title"],
                "snippet": hit["snippet"][:500],
                "search_engines": hit["search_engines"],
                "queries": hit["queries"],
                "observations": hit["observations"],
                "query_depth": hit["query_depth"],
                "fetch_status": page.get("status", "not_read_within_budget"),
                "truncated": page.get("truncated", False),
                "page_excerpt": str(page.get("text") or "")[:1200],
                "source": "deep_research",
            }
            node = EntityNode.create(
                node_type,
                hit["url"],
                f"Fuente: {hit['title'][:60] or host}",
                attributes=attrs,
                confidence=0.55,
            )
            page_lookup[hit["canonical_url"]] = node.model_dump()

        entities = [root]
        relations: list[RelationEdge] = []
        for hit in hits_by_url.values():
            node_data = page_lookup[hit["canonical_url"]]
            node = EntityNode.model_validate(node_data)
            entities.append(node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                    confidence=0.55,
                    attributes={
                        "queries": hit["queries"],
                        "search_engines": hit["search_engines"],
                        "query_depth": hit["query_depth"],
                        "source_url": hit["url"],
                    },
                )
            )

        pivot_report: list[dict[str, Any]] = []
        for (pivot_type, normalized), pivot in pivots.items():
            value = str(pivot["value"])
            searched = normalized in pivots_searched
            entity = EntityNode.create(
                pivot_type,
                value,
                f"Candidato: {value}",
                attributes={
                    "candidate_pivot": True,
                    "sources": pivot["sources"][:10],
                    "searched": searched,
                    "research_type": kind,
                },
                confidence=0.3,
            )
            entities.append(entity)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=entity.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                    confidence=0.3,
                    attributes={
                        "candidate_pivot": True,
                        "source_urls": [item["url"] for item in pivot["sources"][:10]],
                    },
                )
            )
            pivot_report.append(
                {
                    "type": pivot_type.value,
                    "value": value,
                    "sources": pivot["sources"][:5],
                    "searched": searched,
                }
            )

        provider_failures = sum(
            count
            for states in provider_status.values()
            for state, count in states.items()
            if state not in {"results", "no_results"}
        )
        provider_successes = sum(
            count
            for states in provider_status.values()
            for state, count in states.items()
            if state in {"results", "no_results"}
        )
        status = (
            "COMPLETED" if hits_by_url else ("NO_RESULTS" if provider_successes else "UNAVAILABLE")
        )
        limits_reached = []
        if len(query_runs) >= query_budget:
            limits_reached.append("query_budget")
        if pages_attempted >= page_budget:
            limits_reached.append("page_budget")
        if stop_reason == "depth_budget_reached":
            limits_reached.append("pivot_depth")
        report = {
            "status": status,
            "target_type": kind,
            "queries_attempted": len(query_runs),
            "query_budget": query_budget,
            "query_runs": query_runs,
            "provider_status": provider_status,
            "provider_failures": provider_failures,
            "unique_results": len(hits_by_url),
            "pages_selected": len(pages_by_url),
            "pages_attempted": pages_attempted,
            "pages_read": pages_read,
            "page_errors": sum(page["status"] == "error" for page in pages_by_url.values()),
            "page_sources": [
                {
                    "url": page["url"],
                    "status": page["status"],
                    "title": page.get("title", ""),
                    "error": page.get("error"),
                    "search_engines": page.get("search_engines", []),
                    "queries": page.get("queries", [])[:3],
                }
                for page in pages_by_url.values()
            ],
            "page_budget": page_budget,
            "pivot_depth": depth_budget,
            "limits_reached": limits_reached,
            "pivots_found": len(pivots),
            "pivots_searched": sum(
                _normalize(str(pivot["value"])) in pivots_searched for pivot in pivots.values()
            ),
            "pivots": pivot_report[:60],
            "stop_reason": stop_reason,
        }
        raw_payload = {
            **report,
            "target": target,
            "pages": [
                {
                    **{key: value for key, value in page.items() if key != "text"},
                    "text": page.get("text", "")[:12_000],
                }
                for page in pages_by_url.values()
            ],
        }
        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(raw_payload, ensure_ascii=False),
            metadata=report,
        )

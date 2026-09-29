"""
SpecterOSINT - Web Search & Fetch (sin API key, estilo opencode)

Inspirado en `websearch`/`webfetch` de opencode (sst/opencode), pero sin
proveedor externo de pago (ellos usan Exa/Parallel vía MCP con API key):
aquí el backend es DuckDuckGo HTML + descarga directa, 100% sin clave.

Paridades deliberadas con opencode:
- `SEARCH_TIMEOUT = 25s` (su `Effect.timeoutOrElse 25 seconds` por proveedor).
- `FETCH_MAX_BYTES = 5MB` y timeout default 30s / máximo 120s (su webfetch).
- Extracción de texto saltando script/style/noscript/iframe/object/embed.
"""

from __future__ import annotations

import asyncio
import html as html_module
import json
import logging
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlsplit, urlunsplit

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

DDG_HTML_URL = "https://html.duckduckgo.com/html/"
SEARCH_TIMEOUT = 25.0
# El fallback HTML de DDG corre en serie, después de los motores. Le damos un
# presupuesto propio y corto: es una red de seguridad, no la vía principal, y
# bloquea el resto de la búsqueda mientras espera.
DDG_HTML_TIMEOUT = 8.0
FETCH_TIMEOUT_DEFAULT = 30.0
FETCH_TIMEOUT_MAX = 120.0
FETCH_MAX_BYTES = 5 * 1024 * 1024
TOP_K_DEFAULT = 8
FETCH_MAX_CHARS = 12000

logger = logging.getLogger("specter.collectors.web")
PARALLEL_QUERIES_MAX = 10

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 puro-python (sin dependencia mmh3).

    Convención Shodan para favicons: hash sobre el .ico codificado en base64
    (`mmh3.hash(base64.encodebytes(data))`). Sirve para pivotar
    infraestructura clonada cuando se tenga key de Shodan (Fase B).
    """
    import base64

    data = base64.encodebytes(data)
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4 : i * 4 + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 if h1 < 0x80000000 else h1 - 0x100000000


async def _favicon_mmh3(page_url: str, timeout_s: float = 10.0) -> int | None:
    """Hash del favicon para pivote Shodan. Best-effort: nunca falla el collect."""
    try:
        from urllib.parse import urljoin

        parsed = urlparse(page_url)
        if not parsed.hostname or not ssrf_enforce():
            return None
        if (reason := check_public_http_url(page_url)) is not None:
            logger.debug("favicon omitido por NetGuard: %s", reason)
            return None
        fav_url = urljoin(f"{parsed.scheme}://{parsed.netloc}", "/favicon.ico")
        if (reason := check_public_http_url(fav_url)) is not None:
            return None
        # P0 anti-fingerprinting: transporte curl_cffi (huella TLS de Chrome).
        resp = await http_get(
            fav_url,
            headers={"User-Agent": BROWSER_UA},
            timeout=min(timeout_s, 10.0),
        )
        if resp.status_code != 200 or not resp.content:
            return None
        if ssrf_enforce():
            for hop in [*resp.history, resp]:
                if check_public_http_url(str(hop.url)) is not None:
                    return None
        return _murmur3_x86_32(resp.content)
    except Exception as exc:
        logger.debug("favicon hash fallido: %s", exc)
        return None


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_TITLE_TAG_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Hosts que delatan un perfil social (igual que DocumentHunter).
_SOCIAL_HOSTS = ("github", "reddit", "twitter", "x.com", "linkedin", "instagram")


def _clean_text(raw: str) -> str:
    """Quita tags HTML, desescapa entidades y colapsa espacios."""
    return _WS_RE.sub(" ", html_module.unescape(_TAG_RE.sub("", raw))).strip()


def _real_url(redir: str) -> str | None:
    """Resuelve el redirect `uddg=` de DuckDuckGo a la URL destino."""
    if "uddg=" in redir:
        return unquote(redir.split("uddg=")[1].split("&")[0])
    return redir if redir.startswith("http") else None


class _DDGResultsParser(HTMLParser):
    """Reads search-result links across DuckDuckGo HTML variants."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, Any]] = []
        self._active_link: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        values = dict(attrs)
        classes = set((values.get("class") or "").split())
        link = {
            "href": values.get("href") or "",
            "classes": classes,
            "text": [],
        }
        self.links.append(link)
        self._active_link = link

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._active_link = None

    def handle_data(self, data: str) -> None:
        if self._active_link is not None:
            self._active_link["text"].append(data)


def parse_ddg_html(body: str) -> list[dict[str, str]]:
    """Extrae [{title, url, snippet}] del HTML de DuckDuckGo (sin API key)."""
    parser = _DDGResultsParser()
    parser.feed(body)
    results: list[dict[str, str]] = []
    title_links = [item for item in parser.links if "result__a" in item["classes"]]
    # Las respuestas HTML varían: además de result__a, algunos endpoints y
    # respuestas antiguas solo exponen result__url, result__snippet o uddg=.
    candidates = title_links or [
        item
        for item in parser.links
        if item["href"]
        and (item["classes"] & {"result__url", "result__snippet"} or "uddg=" in item["href"])
    ]
    snippets = [
        _clean_text(" ".join(item["text"]))
        for item in parser.links
        if "result__snippet" in item["classes"]
    ]
    for i, item in enumerate(candidates):
        url = _real_url(html_module.unescape(item["href"]))
        title = _clean_text(" ".join(item["text"]))
        if not url:
            continue
        if not title:
            title = url
        snippet = snippets[i] if title_links and i < len(snippets) else ""
        results.append({"title": title, "url": url, "snippet": snippet})
    # Deduplicar por URL preservando orden.
    seen: set[str] = set()
    deduped = [r for r in results if not (r["url"] in seen or seen.add(r["url"]))]
    return deduped


def ddg_html_status(body: str, result_count: int) -> tuple[str, str | None]:
    """Clasifica una respuesta DDG vacía como búsqueda vacía o parser roto."""
    if result_count:
        return "results", None
    if re.search(r'class=["\'][^"\']*result', body, re.IGNORECASE):
        return "parse_error", "DuckDuckGo mostró bloques de resultados que el parser no pudo leer"
    if re.search(r"no results|sin resultados|no se han encontrado", body, re.IGNORECASE):
        return "no_results", None
    return (
        "empty_or_unrecognized_page",
        "La respuesta no contiene resultados reconocibles ni mensaje de búsqueda vacía",
    )


class _TextExtractor(HTMLParser):
    """Extrae texto visible saltando script/style/noscript/iframe/object/embed."""

    _SKIP = {"script", "style", "noscript", "iframe", "object", "embed"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            text = data.strip()
            if text:
                self._chunks.append(text)

    def text(self) -> str:
        return _WS_RE.sub(" ", " ".join(self._chunks)).strip()


def html_to_text(body: bytes) -> tuple[str, str]:
    """(título, texto) desde un HTML. Decodifica con reemplazo si falla UTF-8."""
    text = body.decode("utf-8", errors="replace")
    title_match = _TITLE_TAG_RE.search(text)
    title = _clean_text(title_match.group(1)) if title_match else ""
    extractor = _TextExtractor()
    extractor.feed(text)
    return title, extractor.text()


class WebSearchCollector(BaseCollector):
    """Búsqueda web pasiva en varios índices con cobertura por proveedor."""

    # mojeek entra como red de seguridad: motor independiente, sin captcha y
    # con markup estable, para cuando Google da captcha y DDG/Bing se bloquean
    # o cambian el HTML. Contexto aislado por motor: uno caído no arrastra a los
    # demás (antes compartían un único contexto y se mataban en cascada).
    ENGINES = ("bing", "ddg", "google", "mojeek")

    def __init__(self):
        super().__init__(name="web_search")

    @staticmethod
    def _canonical_url(url: str) -> str:
        """Quita fragmentos y parámetros de tracking para unir duplicados."""
        try:
            parts = urlsplit(url.strip())
            if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
                return ""
            tracking = {"fbclid", "gclid", "dclid", "mc_cid", "mc_eid", "ref_src"}
            netloc = parts.netloc.lower()
            if netloc.startswith("www."):
                netloc = netloc[4:]
            query = [
                (key, value)
                for key, value in parse_qsl(parts.query, keep_blank_values=True)
                if key.lower() not in tracking and not key.lower().startswith("utm_")
            ]
            return urlunsplit(
                (
                    parts.scheme.lower(),
                    netloc,
                    parts.path or "/",
                    urlencode(sorted(query)),
                    "",
                )
            )
        except ValueError:
            return ""

    async def _search_query(self, query: str, top_k: int) -> dict[str, Any]:
        from specter.stealth_browser import get_browser

        browser = None
        try:
            browser = await get_browser()
        except Exception as exc:
            logger.warning("web_search: no se pudo iniciar el navegador: %s", exc)

        async def search_engine(engine: str) -> tuple[str, dict[str, Any]]:
            if browser is None:
                return engine, {"status": "error", "reason": "browser_unavailable", "results": []}
            try:
                detailed = getattr(browser, "search_detailed", None)
                if detailed is None:
                    legacy_results = await browser.search(query, engine=engine, top_k=top_k)
                    return engine, {
                        "status": "results" if legacy_results else "empty_or_unrecognized_page",
                        "results": legacy_results,
                    }
                report = await detailed(query, engine=engine, top_k=top_k)
                return engine, report
            except Exception as exc:
                logger.warning("web_search: %s falló: %s", engine, exc)
                return engine, {"status": "error", "reason": str(exc), "results": []}

        provider_reports = dict(
            await asyncio.gather(*(search_engine(engine) for engine in self.ENGINES))
        )

        # DDG HTML is a separate access path used only when its rendered search
        # page returned no usable hits. Keep its outcome distinct in the report.
        if provider_reports["ddg"].get("status") != "results":
            headers = {
                "User-Agent": BROWSER_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            }
            try:
                response = await http_post(
                    DDG_HTML_URL,
                    data={"q": query},
                    headers=headers,
                    # Vía secundaria y best-effort: si el host no responde (típico
                    # cuando está filtrado en la red), esperar 25s en secuelencia
                    # quema el presupuesto entero y la diferencia entre "devuelve
                    # resultados" y "expira todo" es justo esta espera.
                    timeout=DDG_HTML_TIMEOUT,
                )
                if response.status_code >= 400:
                    provider_reports["ddg_html"] = {
                        "status": "error",
                        "reason": f"http_{response.status_code}",
                        "results": [],
                    }
                else:
                    fallback = parse_ddg_html(response.text)[:top_k]
                    fallback_status, fallback_reason = ddg_html_status(response.text, len(fallback))
                    provider_reports["ddg_html"] = {
                        "status": fallback_status,
                        "results": fallback,
                        **({"reason": fallback_reason} if fallback_reason else {}),
                    }
            except Exception as exc:
                provider_reports["ddg_html"] = {
                    "status": "error",
                    "reason": f"{type(exc).__name__}: {exc}",
                    "results": [],
                }

        # Fair interleaving prevents the first engine from consuming the whole
        # result budget; duplicate URLs keep every query/provider observation.
        rows: dict[str, dict[str, Any]] = {}
        provider_rows: list[tuple[str, list[dict[str, Any]]]] = []
        for engine, report in provider_reports.items():
            raw_rows = report.get("results", [])
            usable: list[dict[str, Any]] = []
            if isinstance(raw_rows, list):
                for hit in raw_rows:
                    if not isinstance(hit, dict):
                        continue
                    url = str(hit.get("url") or "").strip()
                    canonical = self._canonical_url(url)
                    if not canonical:
                        continue
                    usable.append({**hit, "url": url, "canonical_url": canonical})
            provider_rows.append((engine, usable))

        for rank in range(max((len(items) for _, items in provider_rows), default=0)):
            for engine, items in provider_rows:
                if rank >= len(items):
                    continue
                hit = items[rank]
                canonical = hit["canonical_url"]
                observation = {
                    "engine": engine,
                    "query": query,
                    "rank": rank + 1,
                }
                if canonical not in rows:
                    rows[canonical] = {
                        "title": str(hit.get("title") or ""),
                        "url": hit["url"],
                        "canonical_url": canonical,
                        "snippet": str(hit.get("snippet") or ""),
                        "observations": [observation],
                    }
                else:
                    row = rows[canonical]
                    row["observations"].append(observation)
                    if not row["title"] and hit.get("title"):
                        row["title"] = str(hit["title"])
                    if len(str(hit.get("snippet") or "")) > len(row["snippet"]):
                        row["snippet"] = str(hit["snippet"])

        merged = list(rows.values())[:top_k]
        diagnostics = {
            engine: {
                "status": str(report.get("status", "error")),
                "results": len(report.get("results", []))
                if isinstance(report.get("results"), list)
                else 0,
                **({"reason": str(report["reason"])[:240]} if report.get("reason") else {}),
            }
            for engine, report in provider_reports.items()
        }
        usable_provider = any(
            value["status"] in {"results", "no_results"} for value in diagnostics.values()
        )
        status = "COMPLETED" if merged else ("NO_RESULTS" if usable_provider else "UNAVAILABLE")
        return {
            "query": query,
            "status": status,
            "results": merged,
            "providers": diagnostics,
        }

    @staticmethod
    def _result_from_report(
        query: str, results: list[dict[str, Any]], metadata: dict[str, Any]
    ) -> CollectorResult:
        root = EntityNode.create(EntityType.ALIAS, query, f"Búsqueda: {query[:40]}")
        entities = [root]
        relations: list[RelationEdge] = []
        for hit in results:
            url = hit["url"]
            observations = hit.get("observations", [])
            engines = sorted({str(item["engine"]) for item in observations})
            queries = sorted({str(item["query"]) for item in observations})
            node = EntityNode.create(
                type=EntityType.SOCIAL_PROFILE
                if any(s in url.lower() for s in _SOCIAL_HOSTS)
                else EntityType.DOMAIN,
                value=url,
                label=f"Resultado: {hit.get('title', '')[:45]}",
                attributes={
                    "url": url,
                    "canonical_url": hit.get("canonical_url", url),
                    "title": hit.get("title", ""),
                    "snippet": str(hit.get("snippet") or "")[:500],
                    "search_engines": engines,
                    "queries": queries,
                    "observations": observations,
                    "source": "Web Search",
                },
                confidence=0.65,
            )
            entities.append(node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                    confidence=0.65,
                    attributes={"search_engines": engines, "queries": queries},
                )
            )
        payload = {"query": query, "results": results, **metadata}
        return CollectorResult(
            collector_name="web_search",
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(payload, ensure_ascii=False),
            metadata={"query": query, "results": len(results), **metadata},
        )

    async def collect(
        self, target: str, top_k: int = TOP_K_DEFAULT, **kwargs: Any
    ) -> CollectorResult:
        query = target.strip()
        if not query:
            raise ValueError("Consulta vacía")
        top_k = max(1, min(int(top_k), 20))
        report = await self._search_query(query, top_k)
        metadata = {
            "status": report["status"],
            "ok": report["status"] != "UNAVAILABLE",
            "providers": report["providers"],
        }
        return self._result_from_report(query, report["results"], metadata)

    async def collect_many(
        self,
        queries: list[str],
        top_k: int = 5,
        concurrency: int = 3,
    ) -> CollectorResult:
        """Run a bounded batch of distinct queries through all search engines."""
        clean: list[str] = []
        seen: set[str] = set()
        for query in queries:
            value = " ".join(str(query).split())
            if value and value.casefold() not in seen:
                seen.add(value.casefold())
                clean.append(value)
            if len(clean) >= 40:
                break
        if not clean:
            raise ValueError("Se requiere al menos una consulta no vacía")
        top_k = max(1, min(int(top_k), 20))
        semaphore = asyncio.Semaphore(max(1, min(int(concurrency), 5)))

        async def run(query: str) -> dict[str, Any]:
            async with semaphore:
                return await self._search_query(query, top_k)

        reports = await asyncio.gather(*(run(query) for query in clean))
        merged: dict[str, dict[str, Any]] = {}
        for report in reports:
            for hit in report["results"]:
                key = hit["canonical_url"]
                if key not in merged:
                    merged[key] = hit
                else:
                    current = merged[key]
                    current["observations"].extend(
                        item for item in hit["observations"] if item not in current["observations"]
                    )
                    if not current["title"] and hit["title"]:
                        current["title"] = hit["title"]
                    if len(hit["snippet"]) > len(current["snippet"]):
                        current["snippet"] = hit["snippet"]

        query_runs = [
            {
                "query": report["query"],
                "status": report["status"],
                "results": len(report["results"]),
                "providers": report["providers"],
            }
            for report in reports
        ]
        all_results = list(merged.values())
        provider_status: dict[str, dict[str, int]] = {}
        for report in reports:
            for engine, detail in report["providers"].items():
                counts = provider_status.setdefault(engine, {})
                state = detail["status"]
                counts[state] = counts.get(state, 0) + 1
        root_query = clean[0] if len(clean) == 1 else f"Búsqueda profunda: {clean[0][:100]}"
        any_results = any(report["results"] for report in reports)
        any_provider_success = any(
            detail["status"] in {"results", "no_results"}
            for report in reports
            for detail in report["providers"].values()
        )
        batch_metadata = {
            "status": "COMPLETED"
            if any_results
            else "NO_RESULTS"
            if any_provider_success
            else "UNAVAILABLE",
            "ok": any_provider_success,
            "queries_attempted": len(clean),
            "query_runs": query_runs,
            "provider_status": provider_status,
        }
        return self._result_from_report(root_query, all_results, batch_metadata)


class WebFetchCollector(BaseCollector):
    """Descarga una URL y extrae título + texto (máx 5MB, timeout 30s/120s)."""

    def __init__(self):
        super().__init__(name="web_fetch")

    async def collect(
        self,
        target: str,
        max_chars: int = FETCH_MAX_CHARS,
        timeout: int | float = FETCH_TIMEOUT_DEFAULT,
        **kwargs: Any,
    ) -> CollectorResult:
        url = target.strip()
        if not url.lower().startswith(("http://", "https://")):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": "Sólo se permite http(s)"}),
                metadata={"ok": False},
            )
        # C2: NetGuard antes de tocar la red (loopback, privada, link-local…).
        if ssrf_enforce() and (blocked := check_public_http_url(url)):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": f"Bloqueada por NetGuard: {blocked}"}),
                metadata={"ok": False},
            )
        timeout_s = max(1.0, min(float(timeout), FETCH_TIMEOUT_MAX))
        max_chars = max(1, min(int(max_chars), 100_000))

        title = ""
        text = ""

        # Navegador sigiloso in-process: renderiza JS y evita bloqueos básicos.
        try:
            from specter.stealth_browser import get_browser

            browser = await get_browser()
            snap = await browser.navigate_and_snapshot(url, timeout_s=timeout_s)
            title = snap.get("title", "")
            text = snap.get("text", "")
        except Exception as exc:
            logger.warning("web_fetch: navegador sigiloso no disponible (%s); fallback httpx", exc)
            title = ""
            text = ""

        if not text:
            try:
                headers = {"User-Agent": BROWSER_UA, "Accept-Language": "es-ES,es;q=0.9,en;q=0.8"}
                # P0: GET con impersonación TLS (curl_cffi); la huella JA4 ya no
                # delata a Python ante Cloudflare/DataDome en el fallback HTTP.
                resp = await http_get(url, headers=headers, timeout=timeout_s)
                if resp.status_code >= 400:
                    raise RuntimeError(f"HTTP {resp.status_code}")
                # C2: la cadena de redirects también pasa por NetGuard.
                if ssrf_enforce():
                    for hop in [*resp.history, resp]:
                        if blocked_hop := check_public_http_url(str(hop.url)):
                            raise ValueError(f"Redirect bloqueado por NetGuard: {blocked_hop}")
                body = resp.content
                ctype = resp.headers.get("content-type", "")
                if "image/" in ctype:
                    raise ValueError(f"La URL es una imagen ({ctype}), sin texto extraíble")
                length = resp.headers.get("content-length")
                if length and int(length) > FETCH_MAX_BYTES:
                    raise ValueError(f"Respuesta demasiado grande ({length} bytes, máx 5MB)")
                if len(body) > FETCH_MAX_BYTES:
                    raise ValueError(f"Respuesta demasiado grande ({len(body)} bytes, máx 5MB)")
                title, text = (
                    html_to_text(body)
                    if "html" in ctype or "<html" in body[:2000].decode("utf-8", "ignore").lower()
                    else ("", body.decode("utf-8", errors="replace"))
                )
            except Exception as exc:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=url,
                    raw_payload=json.dumps({"url": url, "error": str(exc)}),
                    metadata={"ok": False},
                )

        truncated = len(text) > max_chars
        host = urlparse(url).netloc.lower()
        favicon_hash = await _favicon_mmh3(url, timeout_s)
        domain_attrs: dict[str, Any] = {"source": "web_fetch"}
        if favicon_hash is not None:
            # Técnica Shodan: el hash del favicon pivota sitios clonados
            # (`http.favicon.hash:<n>` con key en Fase B).
            domain_attrs["favicon_mmh3"] = favicon_hash
        entities = [
            EntityNode.create(
                EntityType.DOMAIN, host or url, f"Fuente: {host or url}", attributes=domain_attrs
            )
        ]
        return CollectorResult(
            collector_name=self.name,
            source_target=url,
            entities=entities,
            relations=[],
            raw_payload=json.dumps(
                {
                    "url": url,
                    "title": title,
                    "chars_total": len(text),
                    "truncated": truncated,
                    "favicon_mmh3": favicon_hash,
                    "text": text[:max_chars],
                },
                ensure_ascii=False,
            ),
            metadata={"ok": True, "truncated": truncated, "chars": len(text), "title": title},
        )

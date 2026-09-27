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

import html as html_module
import json
import logging
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import unquote, urlparse

import httpx
from specter.collectors.base import BaseCollector
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
        async with httpx.AsyncClient(timeout=min(timeout_s, 10.0)) as client:
            resp = await client.get(
                fav_url, headers={"User-Agent": BROWSER_UA}, follow_redirects=True
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


_TITLE_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.DOTALL)
_SNIPPET_RE = re.compile(r'class="result__snippet"[^>]*>(.*?)</a>', re.DOTALL)
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


def parse_ddg_html(body: str) -> list[dict[str, str]]:
    """Extrae [{title, url, snippet}] del HTML de DuckDuckGo (sin API key)."""
    titles = _TITLE_RE.findall(body)
    snippets = _SNIPPET_RE.findall(body)
    results: list[dict[str, str]] = []
    for i, (redir, title_html) in enumerate(titles):
        url = _real_url(html_module.unescape(redir))
        title = _clean_text(title_html)
        if not url or not title:
            continue
        snippet = _clean_text(snippets[i]) if i < len(snippets) else ""
        results.append({"title": title, "url": url, "snippet": snippet})
    # Deduplicar por URL preservando orden.
    seen: set[str] = set()
    deduped = [r for r in results if not (r["url"] in seen or seen.add(r["url"]))]
    return deduped


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
    """Búsqueda web pasiva (DuckDuckGo, sin key): títulos + URLs + snippets."""

    def __init__(self):
        super().__init__(name="web_search")

    async def collect(
        self, target: str, top_k: int = TOP_K_DEFAULT, **kwargs: Any
    ) -> CollectorResult:
        query = target.strip()
        if not query:
            raise ValueError("Consulta vacía")
        top_k = max(1, min(int(top_k), 20))

        results: list[dict[str, str]] = []

        # Navegador sigiloso in-process (Playwright): Chromium real sin API key.
        # Si falla (o el sitio bloquea), el fallback DuckDuckGo HTML entra igual.
        try:
            from specter.stealth_browser import get_browser

            browser = await get_browser()
            results = await browser.search(query, engine="bing", top_k=top_k)
            if not results:
                # Google CAPTCHA-ea a headless: DDG HTML vía Chromium es el 2º intento.
                results = await browser.search(query, engine="ddg", top_k=top_k)
        except Exception as exc:
            logger.warning("web_search: navegador sigiloso no disponible (%s); fallback DDG", exc)
            results = []

        if not results:
            headers = {
                "User-Agent": BROWSER_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            }
            try:
                async with httpx.AsyncClient(timeout=SEARCH_TIMEOUT) as client:
                    resp = await client.post(DDG_HTML_URL, data={"q": query}, headers=headers)
                    resp.raise_for_status()
                    results = parse_ddg_html(resp.text)[:top_k]
            except Exception as exc:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=query,
                    raw_payload=json.dumps({"query": query, "error": str(exc)}),
                    metadata={"query": query, "results": 0, "ok": False},
                )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(EntityType.ALIAS, query, f"Búsqueda: {query[:40]}")
        entities.append(root)
        for hit in results:
            node = EntityNode.create(
                type=EntityType.SOCIAL_PROFILE
                if any(s in hit["url"] for s in _SOCIAL_HOSTS)
                else EntityType.DOMAIN,
                value=hit["url"],
                label=f"Resultado: {hit['title'][:45]}",
                attributes={
                    "url": hit["url"],
                    "title": hit["title"],
                    "snippet": hit["snippet"][:300],
                    "source": "Web Search",
                },
                confidence=0.8,
            )
            entities.append(node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                    confidence=0.8,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"query": query, "results": results}, ensure_ascii=False),
            metadata={"query": query, "results": len(results), "ok": True},
        )


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
                async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
                    resp = await client.get(url, headers=headers)
                    resp.raise_for_status()
                    # C2: la cadena de redirects también pasa por NetGuard.
                    if ssrf_enforce():
                        for hop in [*resp.history, resp]:
                            if blocked_hop := check_public_http_url(str(hop.url)):
                                raise ValueError(f"Redirect bloqueado por NetGuard: {blocked_hop}")
                    ctype = resp.headers.get("content-type", "")
                    if "image/" in ctype:
                        raise ValueError(f"La URL es una imagen ({ctype}), sin texto extraíble")
                    length = resp.headers.get("content-length")
                    if length and int(length) > FETCH_MAX_BYTES:
                        raise ValueError(f"Respuesta demasiado grande ({length} bytes, máx 5MB)")
                    body = resp.content
                    if len(body) > FETCH_MAX_BYTES:
                        raise ValueError("Respuesta demasiado grande (máx 5MB)")
                    title, text = (
                        html_to_text(body)
                        if "html" in ctype
                        or "<html" in body[:2000].decode("utf-8", "ignore").lower()
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

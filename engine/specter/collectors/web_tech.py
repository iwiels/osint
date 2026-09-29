"""
SpecterOSINT - Identificación de tecnología web (frameworks, servidores, headers, cookies, errores).

Inspirado en SpiderFoot: sfp_webframework, sfp_webserver, sfp_strangeheaders,
sfp_cookie, sfp_errors. Adaptado a la arquitectura desktop.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from specter.collectors.base import BaseCollector
from specter.httpx_transport import http_get
from specter.netguard import check_public_http_url, ssrf_enforce
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
)

logger = logging.getLogger("specter.collectors.web_tech")

_TIMEOUT = 15.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+identificacion de tecnologia)"}

# Headers estándar (para detectar los no estándar)
_STANDARD_HEADERS = {
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "accept-datetime",
    "authorization",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "date",
    "expect",
    "from",
    "host",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "max-forwards",
    "origin",
    "pragma",
    "proxy-authorization",
    "range",
    "referer",
    "te",
    "transfer-encoding",
    "user-agent",
    "upgrade",
    "via",
    "warning",
    "x-requested-with",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-csrf-token",
    "x-xsrf-token",
}

# Patrones de frameworks
_FRAMEWORK_PATTERNS: dict[str, re.Pattern[str]] = {
    "jQuery": re.compile(r"jquery[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "React": re.compile(r"react[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Angular": re.compile(r"angular[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Vue.js": re.compile(r"vue[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Bootstrap": re.compile(r"bootstrap[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Tailwind CSS": re.compile(r"tailwind", re.IGNORECASE),
    "Foundation": re.compile(r"foundation[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Ember.js": re.compile(r"ember[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Backbone.js": re.compile(r"backbone[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Knockout.js": re.compile(r"knockout[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "D3.js": re.compile(r"d3[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Three.js": re.compile(r"three[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Moment.js": re.compile(r"moment[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Lodash": re.compile(r"lodash[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Underscore.js": re.compile(r"underscore[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Prototype": re.compile(r"prototype[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "MooTools": re.compile(r"mootools[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Dojo": re.compile(r"dojo[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Ext JS": re.compile(r"ext[.-]?js[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "YUI": re.compile(r"yui[.-]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
}

# Patrones de servidores web (desde headers)
_SERVER_PATTERNS: dict[str, re.Pattern[str]] = {
    "Apache": re.compile(r"apache[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Nginx": re.compile(r"nginx[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "IIS": re.compile(r"microsoft-iis[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "LiteSpeed": re.compile(r"litespeed", re.IGNORECASE),
    "Caddy": re.compile(r"caddy", re.IGNORECASE),
    "Tomcat": re.compile(r"apache-coyote|tomcat", re.IGNORECASE),
    "Jetty": re.compile(r"jetty[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Node.js": re.compile(r"node\.js[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Express": re.compile(r"express[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Gunicorn": re.compile(r"gunicorn[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "uWSGI": re.compile(r"uwsgi[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Cherokee": re.compile(r"cherokee[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "Hiawatha": re.compile(r"hiawatha[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
    "lighttpd": re.compile(r"lighttpd[/\s]?(\d+\.\d+\.\d+)?", re.IGNORECASE),
}

# Patrones de errores
_ERROR_PATTERNS: dict[str, re.Pattern[str]] = {
    "SQL Error": re.compile(
        r"(?:sql syntax|mysql error|postgresql error|oracle error|"
        r"sqlite error|sqlserver error|odbc error|jdbc error)",
        re.IGNORECASE,
    ),
    "PHP Error": re.compile(
        r"(?:fatal error|parse error|warning:|notice:|deprecated:|"
        r"php error|php warning|php notice)",
        re.IGNORECASE,
    ),
    "ASP.NET Error": re.compile(
        r"(?:system\.web|asp\.net|stack trace|exception details|"
        r"source error|compilation error)",
        re.IGNORECASE,
    ),
    "Java Error": re.compile(
        r"(?:java\.lang\.|exception in thread|at java\.|"
        r"caused by:|nested exception)",
        re.IGNORECASE,
    ),
    "Python Error": re.compile(
        r"(?:traceback \(most recent call last\):|"
        r"attributeerror:|importerror:|keyerror:|valueerror:|"
        r"typeerror:|nameerror:|indexerror:)",
        re.IGNORECASE,
    ),
    "Ruby Error": re.compile(
        r"(?:nomethoderror|argumenterror|nameerror|typeerror|"
        r"loaderror|syntaxerror)",
        re.IGNORECASE,
    ),
    "Node.js Error": re.compile(
        r"(?:referenceerror:|typeerror:|syntaxerror:|rangeerror:|"
        r"urierror:|internal/server error)",
        re.IGNORECASE,
    ),
    "WordPress Error": re.compile(
        r"(?:wordpress|wp-content|wp-includes|there has been a "
        r"critical error on this website)",
        re.IGNORECASE,
    ),
    "Drupal Error": re.compile(
        r"(?:drupal|drupalerror|the website encountered an unexpected error)",
        re.IGNORECASE,
    ),
    "Joomla Error": re.compile(
        r"(?:joomla|joomlaerror|joomla! error)",
        re.IGNORECASE,
    ),
}


class WebFrameworkIdentifierCollector(BaseCollector):
    """Identificador de frameworks web (jQuery, React, Angular, Vue, etc.)."""

    def __init__(self) -> None:
        super().__init__(name="web_framework_identifier")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        url = target.strip()
        if not url.lower().startswith(("http://", "https://")):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": "Sólo se permite http(s)"}),
                metadata={"ok": False},
            )

        if ssrf_enforce() and (blocked := check_public_http_url(url)):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": f"Bloqueada por NetGuard: {blocked}"}),
                metadata={"ok": False},
            )

        try:
            resp = await http_get(url, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=url,
                    raw_payload=json.dumps({"url": url, "error": f"HTTP {resp.status_code}"}),
                    metadata={"ok": False},
                )
            content = resp.text
        except Exception as exc:
            logger.debug("web_framework: error descargando %s: %s", url, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found: dict[str, str] = {}

        for framework, pattern in _FRAMEWORK_PATTERNS.items():
            match = pattern.search(content)
            if match:
                version = match.group(1) if match.groups() and match.group(1) else "unknown"
                found[framework] = version
                node = EntityNode.create(
                    EntityType.ALIAS,
                    framework,
                    f"Framework: {framework} {version}",
                    attributes={
                        "source": "web_framework_identifier",
                        "framework": framework,
                        "version": version,
                    },
                    confidence=0.85,
                )
                entities.append(node)

        return CollectorResult(
            collector_name=self.name,
            source_target=url,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"url": url, "frameworks": found}, ensure_ascii=False),
            metadata={"ok": True, "frameworks_found": len(found)},
        )


class WebServerIdentifierCollector(BaseCollector):
    """Identificador de servidores web desde headers HTTP."""

    def __init__(self) -> None:
        super().__init__(name="web_server_identifier")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        url = target.strip()
        if not url.lower().startswith(("http://", "https://")):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": "Sólo se permite http(s)"}),
                metadata={"ok": False},
            )

        if ssrf_enforce() and (blocked := check_public_http_url(url)):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": f"Bloqueada por NetGuard: {blocked}"}),
                metadata={"ok": False},
            )

        try:
            resp = await http_get(url, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=url,
                    raw_payload=json.dumps({"url": url, "error": f"HTTP {resp.status_code}"}),
                    metadata={"ok": False},
                )
            headers = dict(resp.headers)
        except Exception as exc:
            logger.debug("web_server: error descargando %s: %s", url, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found: dict[str, str] = {}

        # Buscar en header Server
        server_header = headers.get("server", "")
        if server_header:
            for server, pattern in _SERVER_PATTERNS.items():
                match = pattern.search(server_header)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else "unknown"
                    found[server] = version
                    node = EntityNode.create(
                        EntityType.ALIAS,
                        server,
                        f"Servidor: {server} {version}",
                        attributes={
                            "source": "web_server_identifier",
                            "server": server,
                            "version": version,
                            "server_header": server_header,
                        },
                        confidence=0.95,
                    )
                    entities.append(node)

        # Buscar en otros headers (X-Powered-By, etc.)
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            for server, pattern in _SERVER_PATTERNS.items():
                match = pattern.search(powered_by)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else "unknown"
                    if server not in found:
                        found[server] = version
                        node = EntityNode.create(
                            EntityType.ALIAS,
                            server,
                            f"Servidor: {server} {version}",
                            attributes={
                                "source": "web_server_identifier",
                                "server": server,
                                "version": version,
                                "x_powered_by": powered_by,
                            },
                            confidence=0.9,
                        )
                        entities.append(node)

        return CollectorResult(
            collector_name=self.name,
            source_target=url,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"url": url, "servers": found}, ensure_ascii=False),
            metadata={"ok": True, "servers_found": len(found)},
        )


class StrangeHeadersCollector(BaseCollector):
    """Identificador de headers HTTP no estándar."""

    def __init__(self) -> None:
        super().__init__(name="strange_headers")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        url = target.strip()
        if not url.lower().startswith(("http://", "https://")):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": "Sólo se permite http(s)"}),
                metadata={"ok": False},
            )

        if ssrf_enforce() and (blocked := check_public_http_url(url)):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": f"Bloqueada por NetGuard: {blocked}"}),
                metadata={"ok": False},
            )

        try:
            resp = await http_get(url, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=url,
                    raw_payload=json.dumps({"url": url, "error": f"HTTP {resp.status_code}"}),
                    metadata={"ok": False},
                )
            headers = dict(resp.headers)
        except Exception as exc:
            logger.debug("strange_headers: error descargando %s: %s", url, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        strange: dict[str, str] = {}

        for header_name, header_value in headers.items():
            if header_name.lower() not in _STANDARD_HEADERS:
                strange[header_name] = header_value
                node = EntityNode.create(
                    EntityType.ALIAS,
                    header_name,
                    f"Header: {header_name}",
                    attributes={
                        "source": "strange_headers",
                        "header_name": header_name,
                        "header_value": header_value,
                    },
                    confidence=0.7,
                )
                entities.append(node)

        return CollectorResult(
            collector_name=self.name,
            source_target=url,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"url": url, "strange_headers": strange}, ensure_ascii=False),
            metadata={"ok": True, "strange_headers_found": len(strange)},
        )


class CookieExtractorCollector(BaseCollector):
    """Extractor de cookies de HTTP headers."""

    def __init__(self) -> None:
        super().__init__(name="cookie_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        url = target.strip()
        if not url.lower().startswith(("http://", "https://")):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": "Sólo se permite http(s)"}),
                metadata={"ok": False},
            )

        if ssrf_enforce() and (blocked := check_public_http_url(url)):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": f"Bloqueada por NetGuard: {blocked}"}),
                metadata={"ok": False},
            )

        try:
            resp = await http_get(url, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=url,
                    raw_payload=json.dumps({"url": url, "error": f"HTTP {resp.status_code}"}),
                    metadata={"ok": False},
                )
            headers = dict(resp.headers)
        except Exception as exc:
            logger.debug("cookie_extractor: error descargando %s: %s", url, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        cookies: dict[str, str] = {}

        # Buscar cookies en Set-Cookie
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            # Múltiples cookies pueden estar separadas por coma
            for cookie in set_cookie.split(","):
                cookie = cookie.strip()
                if "=" in cookie:
                    name, _, value = cookie.partition("=")
                    name = name.strip()
                    value = value.split(";")[0].strip()  # Quitar atributos
                    if name:
                        cookies[name] = value
                        node = EntityNode.create(
                            EntityType.ALIAS,
                            name,
                            f"Cookie: {name}",
                            attributes={
                                "source": "cookie_extractor",
                                "cookie_name": name,
                                "cookie_value": value,
                            },
                            confidence=0.8,
                        )
                        entities.append(node)

        return CollectorResult(
            collector_name=self.name,
            source_target=url,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"url": url, "cookies": cookies}, ensure_ascii=False),
            metadata={"ok": True, "cookies_found": len(cookies)},
        )


class ErrorStringExtractorCollector(BaseCollector):
    """Extractor de errores SQL, PHP, etc. de contenido web."""

    def __init__(self) -> None:
        super().__init__(name="error_string_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        url = target.strip()
        if not url.lower().startswith(("http://", "https://")):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": "Sólo se permite http(s)"}),
                metadata={"ok": False},
            )

        if ssrf_enforce() and (blocked := check_public_http_url(url)):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": f"Bloqueada por NetGuard: {blocked}"}),
                metadata={"ok": False},
            )

        try:
            resp = await http_get(url, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=url,
                    raw_payload=json.dumps({"url": url, "error": f"HTTP {resp.status_code}"}),
                    metadata={"ok": False},
                )
            content = resp.text
        except Exception as exc:
            logger.debug("error_string: error descargando %s: %s", url, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found: dict[str, list[str]] = {}

        for error_type, pattern in _ERROR_PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                # Deduplicar y limitar
                unique_matches = sorted(set(matches))[:5]
                found[error_type] = unique_matches
                for match in unique_matches:
                    node = EntityNode.create(
                        EntityType.ALIAS,
                        match,
                        f"Error {error_type}: {match[:50]}",
                        attributes={
                            "source": "error_string_extractor",
                            "error_type": error_type,
                            "error_message": match,
                        },
                        confidence=0.75,
                    )
                    entities.append(node)

        total = sum(len(v) for v in found.values())
        return CollectorResult(
            collector_name=self.name,
            source_target=url,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"url": url, "errors": found}, ensure_ascii=False),
            metadata={"ok": True, "errors_found": total, "error_types": list(found.keys())},
        )

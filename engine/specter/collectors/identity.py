"""
WraithOSINT - Identity & Social Footprint Collectors
Colectores para investigación de nombres de usuario (patrón Sherlock/WhatsMyName) y correos electrónicos.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import sys
import types
from typing import Any
from urllib.parse import quote

import dns.resolver
import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.identity")


def _ensure_maigret_compat() -> None:
    if "cgi" not in sys.modules:
        cgi = types.ModuleType("cgi")
        cgi.parse_header = lambda line: (line, {})
        sys.modules["cgi"] = cgi
    if "aiohttp_socks" not in sys.modules:
        socks = types.ModuleType("aiohttp_socks")

        class DummyProxyConnector:
            @classmethod
            def from_url(cls, *args: Any, **kwargs: Any) -> None:
                return None

        socks.ProxyConnector = DummyProxyConnector
        sys.modules["aiohttp_socks"] = socks
    if "python_socks" not in sys.modules:
        ps = types.ModuleType("python_socks")
        ps._errors = types.SimpleNamespace(
            ProxyConnectionError=Exception,
            ProxyTimeoutError=Exception,
            ProxyError=Exception,
        )
        sys.modules["python_socks"] = ps
        sys.modules["python_socks._errors"] = ps._errors


def is_maigret_available() -> bool:
    try:
        _ensure_maigret_compat()
        import maigret  # noqa: F401
        from maigret.result import QueryStatus  # noqa: F401
        from maigret.sites import SitesInformation  # noqa: F401

        return True
    except Exception:
        return False


def is_holehe_available() -> bool:
    try:
        import holehe  # noqa: F401
        import holehe.core  # noqa: F401

        return True
    except Exception:
        return False


def _get_run_maigret() -> Any:
    _ensure_maigret_compat()
    from maigret.maigret import maigret as run_maigret

    return run_maigret


class SilentQueryNotify:
    """Silencia las salidas por consola de Maigret."""

    def start(self, username: str, id_type: str = "username") -> None:
        pass

    def update(self, result: Any, is_similar: bool = False) -> None:
        pass

    def finish(self) -> None:
        pass


_MAIGRET_SITES_CACHE: dict[str, Any] | None = None


def _load_maigret_sites() -> dict[str, Any]:
    global _MAIGRET_SITES_CACHE
    if _MAIGRET_SITES_CACHE is not None:
        return _MAIGRET_SITES_CACHE
    if not is_maigret_available():
        return {}
    try:
        import maigret

        data_path = os.path.join(os.path.dirname(maigret.__file__), "resources", "data.json")
        if not os.path.exists(data_path):
            return {}
        with open(data_path, encoding="utf-8") as f:
            raw = json.load(f)
        _MAIGRET_SITES_CACHE = raw.get("sites", {})
        return _MAIGRET_SITES_CACHE
    except Exception:
        return {}


DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "tempmail.com",
    "trashmail.com",
    "sharklasers.com",
    "dispostable.com",
    "yopmail.com",
}

PLATFORM_DEFINITIONS = [
    {
        "name": "GitHub",
        "url": "https://api.github.com/users/{username}",
        "profile_url": "https://github.com/{username}",
        "check_type": "status_code",
        "valid_status": 200,
        "category": "Code/Tech",
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "profile_url": "https://gitlab.com/{username}",
        "check_type": "status_code",
        "valid_status": 200,
        "category": "Code/Tech",
    },
    {
        "name": "HackerNews",
        "url": "https://hacker-news.firebaseio.com/v0/user/{username}.json",
        "profile_url": "https://news.ycombinator.com/user?id={username}",
        "check_type": "json_not_null",
        "category": "Discussion/Tech",
    },
    {
        "name": "DockerHub",
        "url": "https://hub.docker.com/v2/users/{username}",
        "profile_url": "https://hub.docker.com/u/{username}",
        "check_type": "status_code",
        "valid_status": 200,
        "category": "DevOps",
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
        "profile_url": "https://keybase.io/{username}",
        "check_type": "keybase_json",
        "category": "Crypto/Identity",
    },
    {
        "name": "Telegram",
        "url": "https://t.me/{username}",
        "profile_url": "https://t.me/{username}",
        "check_type": "telegram_body",
        "category": "Messaging",
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{username}/about.json",
        "profile_url": "https://reddit.com/user/{username}",
        "check_type": "reddit_json",
        "category": "Social Media",
    },
]

import unicodedata  # noqa: E402  (constantes de módulo arriba; ver NOTA)

from specter import config as specter_config  # noqa: E402

WMN_SITES: list[dict[str, Any]] = []


def _load_wmn_sites() -> list[dict[str, Any]]:
    """Carga diferida del dataset WMN (call-time, no import-time)."""
    global WMN_SITES
    if WMN_SITES:
        return WMN_SITES
    path = specter_config.wmn_data_path()
    if path.exists():
        try:
            WMN_SITES = json.loads(path.read_text(encoding="utf-8")).get("sites", [])
        except Exception:
            WMN_SITES = []
    return WMN_SITES


def is_wmn_match(site: dict[str, Any], response_code: int, response_text: str) -> bool:
    e_code = site.get("e_code")
    e_str = site.get("e_string")
    m_code = site.get("m_code")
    m_str = site.get("m_string")

    if m_code and response_code == m_code:
        return False
    if m_str and m_str in response_text:
        return False
    if e_code and response_code != e_code:
        return False
    if e_str and e_str not in response_text:
        return False

    if e_code or e_str:
        return True
    return response_code == 200


class UsernameInvestigator(BaseCollector):
    def __init__(self):
        super().__init__(name="username_investigator")

    async def _check_platform(
        self, client: httpx.AsyncClient, platform: dict[str, Any], username: str
    ) -> dict[str, Any] | None:
        encoded_user = quote(username)
        req_url = platform["url"].format(username=encoded_user)
        prof_url = platform["profile_url"].format(username=encoded_user)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }

        try:
            resp = await client.get(req_url, headers=headers, follow_redirects=True)
            ctype = platform["check_type"]

            if ctype == "status_code" and resp.status_code == platform["valid_status"]:
                return {
                    "platform": platform["name"],
                    "url": prof_url,
                    "category": platform["category"],
                    "status": "EXISTS",
                }
            elif ctype == "json_not_null" and resp.status_code == 200:
                data = resp.json()
                if data is not None:
                    return {
                        "platform": platform["name"],
                        "url": prof_url,
                        "category": platform["category"],
                        "status": "EXISTS",
                        "extra": data if isinstance(data, dict) else {},
                    }
            elif ctype == "keybase_json" and resp.status_code == 200:
                data = resp.json()
                them = data.get("them", [])
                if them and them[0] is not None:
                    return {
                        "platform": platform["name"],
                        "url": prof_url,
                        "category": platform["category"],
                        "status": "EXISTS",
                    }
            elif ctype == "telegram_body" and resp.status_code == 200:
                # Telegram devuelve 200 aún si no existe, pero sin el botón 'Send Message' o con 'tgme_page_action'
                if "tgme_page_action" in resp.text and "View in Telegram" in resp.text:
                    return {
                        "platform": platform["name"],
                        "url": prof_url,
                        "category": platform["category"],
                        "status": "EXISTS",
                    }
            elif ctype == "reddit_json" and resp.status_code == 200:
                data = resp.json()
                if "data" in data and not data.get("data", {}).get("is_suspended"):
                    return {
                        "platform": platform["name"],
                        "url": prof_url,
                        "category": platform["category"],
                        "status": "EXISTS",
                    }
        except Exception:
            return None
        return None

    async def _check_wmn_site(
        self, client: httpx.AsyncClient, site: dict[str, Any], username: str, sem: asyncio.Semaphore
    ) -> dict[str, Any] | None:
        async with sem:
            # Nota: algunos uri_check del dataset público wmn-data.json traen
            # api_key de terceros (p.ej. Disqus): es la clave PÚBLICA del
            # upstream, parte inerte de la URL. Nunca se trata como credencial
            # propia ni se lee como secreto.
            url = site["uri_check"].replace("{account}", quote(username))
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            }
            if "headers" in site and isinstance(site["headers"], dict):
                headers.update(site["headers"])

            try:
                resp = await client.get(url, headers=headers, timeout=3.5, follow_redirects=True)
                if is_wmn_match(site, resp.status_code, resp.text):
                    pretty_url = site.get("uri_pretty", url).replace("{account}", quote(username))
                    return {
                        "platform": site["name"],
                        "url": pretty_url,
                        "category": site.get("cat", "other"),
                        "status": "EXISTS",
                    }
            except Exception:
                return None
        return None

    async def collect_fast(self, username: str) -> list[dict[str, Any]]:
        """Solo las 7 plataformas rápidas (sin WMN): para pivotes baratos.

        La usa el pivote email→username: 717 sitios por cada email sería
        abusivo con los proveedores; 7 checks curados bastan como señal.
        """
        raw = username.strip().lstrip("@")
        if not raw or len(raw) > 64:
            return []
        found: list[dict[str, Any]] = []
        seen: set[str] = set()
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
        async with httpx.AsyncClient(limits=limits, timeout=4.0) as client:
            results = await asyncio.gather(
                *[self._check_platform(client, p, raw) for p in PLATFORM_DEFINITIONS],
                return_exceptions=True,
            )
            for res in results:
                if isinstance(res, dict) and res.get("status") == "EXISTS":
                    url = res.get("url")
                    if url not in seen:
                        seen.add(url)
                        res["matched_username"] = raw
                        found.append(res)
        return found

    async def collect(
        self, target: str, use_maigret: bool = False, **kwargs: Any
    ) -> CollectorResult:
        raw_username = target.strip().lstrip("@")
        norm_username = unicodedata.normalize("NFKD", raw_username)
        # Un handle puramente numérico no es un alias elegido: muchas
        # plataformas asignan IDs secuenciales y cualquier número "existe"
        # (Dailymotion, ImageShack, Vivino...). Se marca y se baja la
        # confianza en vez de registrarlo a 0.95 como identidad atribuida.
        is_numeric = raw_username.isdigit()
        profile_confidence = 0.5 if is_numeric else 0.95

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        primary_alias_node = EntityNode.create(
            type=EntityType.ALIAS,
            value=raw_username,
            label=f"Alias: @{raw_username}",
        )
        entities.append(primary_alias_node)

        usernames_to_scan = [raw_username]
        if norm_username != raw_username:
            norm_alias_node = EntityNode.create(
                type=EntityType.ALIAS,
                value=norm_username,
                label=f"Normalized Alias: @{norm_username}",
                attributes={"homoglyph_of": raw_username},
            )
            entities.append(norm_alias_node)
            relations.append(
                RelationEdge(
                    source_id=primary_alias_node.id,
                    target_id=norm_alias_node.id,
                    relation_type=RelationType.USES_ALIAS,
                    attributes={"normalization": "Unicode NFKD"},
                )
            )
            usernames_to_scan.append(norm_username)

        found_profiles: list[dict[str, Any]] = []
        seen_urls = set()
        sem = asyncio.Semaphore(50)

        limits = httpx.Limits(max_connections=60, max_keepalive_connections=20)
        async with httpx.AsyncClient(limits=limits, timeout=4.0) as client:
            for u in usernames_to_scan:
                tasks = [self._check_platform(client, p, u) for p in PLATFORM_DEFINITIONS]
                wmn_sites = _load_wmn_sites()
                if wmn_sites:
                    tasks.extend([self._check_wmn_site(client, s, u, sem) for s in wmn_sites])

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, dict) and res.get("status") == "EXISTS":
                        url = res.get("url")
                        if url not in seen_urls:
                            seen_urls.add(url)
                            res["matched_username"] = u
                            found_profiles.append(res)

        for prof in found_profiles:
            plat_name = prof["platform"]
            url = prof["url"]
            matched_u = prof.get("matched_username", raw_username)

            parent_alias_id = (
                primary_alias_node.id
                if matched_u == raw_username
                else f"alias:{norm_username.lower()}"
            )

            prof_node = EntityNode.create(
                type=EntityType.SOCIAL_PROFILE,
                value=url,
                label=f"{plat_name}: @{matched_u}",
                attributes={
                    "platform": plat_name,
                    "url": url,
                    "category": prof.get("category"),
                    "matched_username": matched_u,
                    **(
                        {
                            "numeric_handle_warning": (
                                "Identificador puramente numérico: probable ID "
                                "secuencial asignado por la plataforma, no alias "
                                "elegido. Validar con un número de control antes "
                                "de atribuir."
                            )
                        }
                        if is_numeric
                        else {}
                    ),
                },
                confidence=profile_confidence,
            )
            entities.append(prof_node)
            relations.append(
                RelationEdge(
                    source_id=parent_alias_id,
                    target_id=prof_node.id,
                    relation_type=RelationType.REGISTERED_WITH,
                    confidence=profile_confidence,
                )
            )

        maigret_meta: dict[str, Any] = {}
        if use_maigret and is_maigret_available():
            try:
                mh = MaigretHunter(
                    timeout=kwargs.get("maigret_timeout", 25.0),
                    top_sites_limit=kwargs.get("top_sites_limit", 100),
                    site_list=kwargs.get("site_list"),
                )
                mres = await mh.collect(raw_username, **kwargs)
                maigret_meta = mres.metadata
                existing_ids = {e.id for e in entities}
                for e in mres.entities:
                    if e.id not in existing_ids:
                        entities.append(e)
                        existing_ids.add(e.id)
                existing_edges = {r.edge_id for r in relations}
                for r in mres.relations:
                    if r.edge_id not in existing_edges:
                        relations.append(r)
                        existing_edges.add(r.edge_id)
            except Exception as exc:
                logger.warning(f"Error integrating Maigret in UsernameInvestigator: {exc}")
                maigret_meta = {"maigret_error": str(exc), "maigret_fallback": True}

        return CollectorResult(
            collector_name=self.name,
            source_target=raw_username,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"target_alias": raw_username, "matches": found_profiles}, indent=2
            ),
            metadata={
                "platforms_checked": len(PLATFORM_DEFINITIONS) + len(WMN_SITES),
                "matches_found": len(found_profiles),
                "unicode_normalized": norm_username != raw_username,
                "numeric_target": is_numeric,
                **({"maigret": maigret_meta} if use_maigret else {}),
            },
        )


class EmailInvestigator(BaseCollector):
    def __init__(self):
        super().__init__(name="email_investigator")

    async def collect(
        self, target: str, use_holehe: bool = False, **kwargs: Any
    ) -> CollectorResult:
        email = target.strip().lower()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        intel_report: dict[str, Any] = {"email": email}

        # 1. Validación de Sintaxis
        is_valid_syntax = bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))
        intel_report["valid_syntax"] = is_valid_syntax

        email_node = EntityNode.create(
            type=EntityType.EMAIL,
            value=email,
            label=f"Email: {email}",
            attributes={"syntax_valid": is_valid_syntax},
        )
        entities.append(email_node)

        if not is_valid_syntax:
            return CollectorResult(
                collector_name=self.name,
                source_target=email,
                entities=entities,
                relations=relations,
                raw_payload=json.dumps(intel_report, indent=2),
                metadata={"valid": False},
            )

        local_part, domain_part = email.split("@", 1)

        # Entidad para el alias local
        alias_node = EntityNode.create(
            type=EntityType.ALIAS,
            value=local_part,
            label=f"Alias: @{local_part}",
        )
        entities.append(alias_node)
        relations.append(
            RelationEdge(
                source_id=alias_node.id,
                target_id=email_node.id,
                relation_type=RelationType.USES_ALIAS,
            )
        )

        # Entidad para el dominio
        domain_node = EntityNode.create(
            type=EntityType.DOMAIN,
            value=domain_part,
            label=f"Domain: {domain_part}",
        )
        entities.append(domain_node)
        relations.append(
            RelationEdge(
                source_id=email_node.id,
                target_id=domain_node.id,
                relation_type=RelationType.HOSTED_ON,
            )
        )

        # Chequeo de proveedor desechable
        is_disposable = domain_part in DISPOSABLE_DOMAINS
        intel_report["is_disposable_domain"] = is_disposable
        email_node.attributes["disposable"] = is_disposable

        # 2. Resolución MX
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.5
            answers = await asyncio.to_thread(resolver.resolve, domain_part, "MX")
            mx_hosts = [r.exchange.to_text().rstrip(".") for r in answers]
            intel_report["mx_records"] = mx_hosts
        except Exception as e:
            intel_report["mx_records"] = []
            intel_report["mx_error"] = str(e)

        # 3. Hashes Criptográficos para correlación de filtraciones y Gravatar
        md5_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
        sha256_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
        intel_report["hashes"] = {"md5": md5_hash, "sha256": sha256_hash}

        # 4. Comprobación pasiva de Gravatar
        gravatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.head(gravatar_url)
                if resp.status_code == 200:
                    intel_report["has_gravatar"] = True
                    grav_node = EntityNode.create(
                        type=EntityType.SOCIAL_PROFILE,
                        value=f"https://gravatar.com/{md5_hash}",
                        label="Gravatar Profile",
                        attributes={"has_avatar": True, "avatar_url": gravatar_url},
                    )
                    entities.append(grav_node)
                    relations.append(
                        RelationEdge(
                            source_id=email_node.id,
                            target_id=grav_node.id,
                            relation_type=RelationType.ASSOCIATED_WITH,
                        )
                    )
                else:
                    intel_report["has_gravatar"] = False
        except Exception:
            intel_report["has_gravatar"] = False

        # 5. Pivote email→username (holehe-lite): el local-part se chequea en
        #    las 7 plataformas rápidas. Es señal (conf 0.7), no atribución.
        try:
            local_part = email.split("@")[0]
            pivot = await UsernameInvestigator().collect_fast(local_part)
            intel_report["username_pivot"] = [p["url"] for p in pivot]
            for prof in pivot:
                prof_node = EntityNode.create(
                    type=EntityType.SOCIAL_PROFILE,
                    value=prof["url"],
                    label=f"{prof['platform']}: @{local_part}",
                    attributes={
                        "platform": prof["platform"],
                        "url": prof["url"],
                        "via": "email-username-pivot",
                    },
                    confidence=0.7,
                )
                entities.append(prof_node)
                relations.append(
                    RelationEdge(
                        source_id=email_node.id,
                        target_id=prof_node.id,
                        relation_type=RelationType.USES_ALIAS,
                        confidence=0.7,
                    )
                )
        except Exception as exc:
            intel_report["username_pivot_error"] = str(exc)[:200]

        holehe_meta: dict[str, Any] = {}
        if use_holehe and is_holehe_available():
            try:
                hh = HoleheHunter(
                    timeout=kwargs.get("holehe_timeout", 15.0),
                    services=kwargs.get("services"),
                )
                hres = await hh.collect(email, **kwargs)
                holehe_meta = hres.metadata
                existing_ids = {e.id for e in entities}
                for e in hres.entities:
                    if e.id not in existing_ids:
                        entities.append(e)
                        existing_ids.add(e.id)
                existing_edges = {r.edge_id for r in relations}
                for r in hres.relations:
                    if r.edge_id not in existing_edges:
                        relations.append(r)
                        existing_edges.add(r.edge_id)
            except Exception as exc:
                logger.warning(f"Error integrating Holehe in EmailInvestigator: {exc}")
                holehe_meta = {"holehe_error": str(exc), "holehe_fallback": True}

        return CollectorResult(
            collector_name=self.name,
            source_target=email,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(intel_report, indent=2),
            metadata={
                "has_mx": len(intel_report.get("mx_records", [])) > 0,
                **({"holehe": holehe_meta} if use_holehe else {}),
            },
        )


class MaigretHunter(BaseCollector):
    """
    Colector de huella de identidad basado en el motor Maigret (5,900+ sitios soportados).
    Identifica perfiles, biografías, avatares, correos e identificadores correlacionados.
    """

    def __init__(
        self,
        timeout: float = 25.0,
        top_sites_limit: int = 100,
        site_list: list[str] | None = None,
        enable_recursive: bool = False,
        max_connections: int = 50,
    ):
        super().__init__(name="maigret_hunter")
        self.timeout = timeout
        self.top_sites_limit = top_sites_limit
        self.site_list = site_list
        self.enable_recursive = enable_recursive
        self.max_connections = max_connections

    def _parse_profile_data(
        self,
        site_name: str,
        raw_username: str,
        site_res: dict[str, Any],
        alias_node: EntityNode,
        entities: list[EntityNode],
        relations: list[RelationEdge],
    ) -> None:
        url = site_res.get("url_user") or site_res.get("url")
        if not url:
            return

        status_val = site_res.get("status")
        ids_data: dict[str, Any] = {}
        if hasattr(status_val, "ids_data") and isinstance(status_val.ids_data, dict):
            ids_data = status_val.ids_data
        elif isinstance(site_res.get("ids_data"), dict):
            ids_data = site_res["ids_data"]

        ids_usernames: dict[str, Any] = {}
        if isinstance(site_res.get("ids_usernames"), dict):
            ids_usernames.update(site_res["ids_usernames"])
        if hasattr(status_val, "ids_usernames") and isinstance(status_val.ids_usernames, dict):
            ids_usernames.update(status_val.ids_usernames)

        bio = (
            ids_data.get("bio")
            or ids_data.get("description")
            or site_res.get("bio")
            or site_res.get("description")
        )
        avatar = (
            ids_data.get("avatar")
            or ids_data.get("avatar_url")
            or ids_data.get("image")
            or site_res.get("avatar_url")
            or site_res.get("avatar")
        )
        real_name = (
            ids_data.get("name")
            or ids_data.get("fullname")
            or ids_data.get("realname")
            or site_res.get("fullname")
            or site_res.get("name")
        )
        found_email = ids_data.get("email") or site_res.get("email")

        prof_attrs: dict[str, Any] = {
            "platform": site_name,
            "url": url,
            "status": "EXISTS",
            "category": site_res.get("category", "social"),
        }
        if site_res.get("rank"):
            prof_attrs["rank"] = site_res["rank"]
        if bio:
            prof_attrs["bio"] = bio
        if avatar:
            prof_attrs["avatar_url"] = avatar

        prof_node = EntityNode.create(
            type=EntityType.SOCIAL_PROFILE,
            value=url,
            label=f"{site_name}: @{raw_username}",
            attributes=prof_attrs,
            confidence=0.95,
        )
        entities.append(prof_node)
        relations.append(
            RelationEdge(
                source_id=alias_node.id,
                target_id=prof_node.id,
                relation_type=RelationType.HAS_ACCOUNT,
                confidence=0.95,
                attributes={"platform": site_name},
            )
        )

        if real_name and isinstance(real_name, str) and real_name.strip():
            person_node = EntityNode.create(
                type=EntityType.PERSON,
                value=real_name.strip(),
                label=f"Person: {real_name.strip()}",
                attributes={"discovered_on": site_name, "source_profile": url},
                confidence=0.85,
            )
            entities.append(person_node)
            relations.append(
                RelationEdge(
                    source_id=prof_node.id,
                    target_id=person_node.id,
                    relation_type=RelationType.OWNS,
                    confidence=0.85,
                    attributes={"platform": site_name},
                )
            )
            relations.append(
                RelationEdge(
                    source_id=alias_node.id,
                    target_id=person_node.id,
                    relation_type=RelationType.LINKED_TO,
                    confidence=0.85,
                    attributes={"discovered_via": site_name},
                )
            )

        if found_email and isinstance(found_email, str) and "@" in found_email:
            em_clean = found_email.strip().lower()
            email_node = EntityNode.create(
                type=EntityType.EMAIL,
                value=em_clean,
                label=f"Email: {em_clean}",
                attributes={"discovered_on": site_name, "source_profile": url},
                confidence=0.9,
            )
            entities.append(email_node)
            relations.append(
                RelationEdge(
                    source_id=prof_node.id,
                    target_id=email_node.id,
                    relation_type=RelationType.LINKED_TO,
                    confidence=0.9,
                    attributes={"platform": site_name},
                )
            )

        if isinstance(ids_usernames, dict):
            for linked_u, id_type in ids_usernames.items():
                if linked_u and str(linked_u).lower() != raw_username.lower():
                    linked_node = EntityNode.create(
                        type=EntityType.ALIAS,
                        value=str(linked_u),
                        label=f"Linked Alias: @{linked_u}",
                        attributes={"discovered_on": site_name, "id_type": str(id_type)},
                        confidence=0.8,
                    )
                    entities.append(linked_node)
                    relations.append(
                        RelationEdge(
                            source_id=prof_node.id,
                            target_id=linked_node.id,
                            relation_type=RelationType.LINKED_TO,
                            confidence=0.8,
                            attributes={"platform": site_name, "id_type": str(id_type)},
                        )
                    )

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        raw_username = target.strip().lstrip("@")
        if not raw_username:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload="{}",
                metadata={"valid": False, "error": "Empty username"},
            )

        if not is_maigret_available():
            logger.warning("Maigret is not installed; falling back to UsernameInvestigator")
            fallback_res = await UsernameInvestigator().collect(target, **kwargs)
            fallback_res.metadata["maigret_fallback"] = True
            return fallback_res

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        alias_node = EntityNode.create(
            type=EntityType.ALIAS,
            value=raw_username,
            label=f"Alias: @{raw_username}",
        )
        entities.append(alias_node)

        all_sites = _load_maigret_sites()
        selected_sites: dict[str, Any] = {}

        if self.site_list:
            filter_set = {s.lower() for s in self.site_list}
            for name, data in all_sites.items():
                if name.lower() in filter_set:
                    selected_sites[name] = data
        elif self.top_sites_limit and self.top_sites_limit > 0:
            sorted_items = sorted(
                all_sites.items(),
                key=lambda x: x[1].get("rank") if x[1].get("rank") else 999999999,
            )
            selected_sites = dict(sorted_items[: self.top_sites_limit])
        else:
            selected_sites = all_sites

        raw_results: dict[str, Any] = {}
        timed_out = False
        try:
            run_fn = _get_run_maigret()
            notify = SilentQueryNotify()
            maigret_logger = logging.getLogger("specter.maigret")
            search_coro = run_fn(
                username=raw_username,
                site_data=selected_sites,
                query_notify=notify,
                logger=maigret_logger,
                timeout=self.timeout,
                recursive_search=self.enable_recursive,
                max_connections=self.max_connections,
            )
            raw_results = await asyncio.wait_for(search_coro, timeout=self.timeout + 5.0)
        except TimeoutError:
            logger.warning("Maigret search timed out")
            timed_out = True
        except Exception as exc:
            logger.warning(f"Maigret search encountered error: {exc}")
            fallback_res = await UsernameInvestigator().collect(target, **kwargs)
            fallback_res.metadata["maigret_error"] = str(exc)
            fallback_res.metadata["maigret_fallback"] = True
            return fallback_res

        matches_found = 0
        if isinstance(raw_results, dict):
            for site_name, site_res in raw_results.items():
                if not isinstance(site_res, dict):
                    continue
                status_val = site_res.get("status")
                is_claimed = False
                if str(status_val) == "CLAIMED" or getattr(status_val, "name", "") == "CLAIMED":
                    is_claimed = True
                elif hasattr(status_val, "status"):
                    inner_st = status_val.status
                    if str(inner_st) == "CLAIMED" or getattr(inner_st, "name", "") == "CLAIMED":
                        is_claimed = True
                elif site_res.get("claimed") is True or site_res.get("exists") is True:
                    is_claimed = True

                if is_claimed:
                    matches_found += 1
                    self._parse_profile_data(
                        site_name, raw_username, site_res, alias_node, entities, relations
                    )

        if matches_found == 0 and timed_out:
            logger.info("No profiles found during timeout; falling back to UsernameInvestigator")
            fallback_res = await UsernameInvestigator().collect(target, **kwargs)
            fallback_res.metadata["maigret_timeout"] = True
            fallback_res.metadata["maigret_fallback"] = True
            return fallback_res

        return CollectorResult(
            collector_name=self.name,
            source_target=raw_username,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"target_alias": raw_username, "matches_count": matches_found}, indent=2
            ),
            metadata={
                "sites_checked": len(selected_sites),
                "matches_found": matches_found,
                "timeout": timed_out,
            },
        )


class HoleheHunter(BaseCollector):
    """
    Colector de registro de correo basado en Holehe (120+ servicios).
    Verifica existencia de cuenta mediante endpoints de registro y recuperación de contraseña.
    """

    def __init__(
        self,
        timeout: float = 15.0,
        max_connections: int = 25,
        services: list[str] | None = None,
    ):
        super().__init__(name="holehe_hunter")
        self.timeout = timeout
        self.max_connections = max_connections
        self.services = services

    async def _run_holehe_checks(self, email: str) -> list[dict[str, Any]]:
        import holehe.core

        modules = holehe.core.import_submodules("holehe.modules")
        websites = holehe.core.get_functions(modules)
        if self.services:
            svc_set = {s.lower() for s in self.services}
            websites = [w for w in websites if getattr(w, "__name__", "").lower() in svc_set]

        out: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(self.max_connections)
        limits = httpx.Limits(max_connections=self.max_connections, max_keepalive_connections=10)

        async with httpx.AsyncClient(limits=limits, timeout=self.timeout) as client:

            async def _check_one(fn: Any) -> None:
                async with sem:
                    try:
                        await asyncio.wait_for(fn(email, client, out), timeout=self.timeout)
                    except Exception as e:
                        fn_name = getattr(fn, "__name__", "unknown")
                        out.append(
                            {
                                "name": fn_name,
                                "domain": f"{fn_name}.com",
                                "rateLimit": True,
                                "exists": False,
                                "error": str(e),
                            }
                        )

            tasks = [_check_one(w) for w in websites]
            await asyncio.gather(*tasks, return_exceptions=True)

        return sorted(out, key=lambda x: x.get("name", ""))

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        email = target.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return CollectorResult(
                collector_name=self.name,
                source_target=email,
                entities=[],
                relations=[],
                raw_payload=json.dumps({"email": email, "error": "Invalid email syntax"}),
                metadata={"valid": False, "error": "Invalid email syntax"},
            )

        if not is_holehe_available():
            logger.warning("Holehe is not available; falling back to EmailInvestigator")
            fallback_res = await EmailInvestigator().collect(email, **kwargs)
            fallback_res.metadata["holehe_fallback"] = True
            return fallback_res

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        email_node = EntityNode.create(
            type=EntityType.EMAIL,
            value=email,
            label=f"Email: {email}",
            attributes={"syntax_valid": True},
        )
        entities.append(email_node)

        raw_results: list[dict[str, Any]] = []
        timed_out = False
        try:
            raw_results = await asyncio.wait_for(
                self._run_holehe_checks(email), timeout=self.timeout + 5.0
            )
        except TimeoutError:
            logger.warning("Holehe execution timed out")
            timed_out = True
        except Exception as exc:
            logger.warning(f"Holehe execution error: {exc}")
            fallback_res = await EmailInvestigator().collect(email, **kwargs)
            fallback_res.metadata["holehe_error"] = str(exc)
            fallback_res.metadata["holehe_fallback"] = True
            return fallback_res

        services_checked = 0
        rate_limited_count = 0
        matches_found = 0

        for item in raw_results:
            services_checked += 1
            if item.get("rateLimit"):
                rate_limited_count += 1
            if item.get("exists") is True:
                matches_found += 1
                name = item.get("name", "unknown")
                domain = item.get("domain", f"{name}.com")
                url = f"https://{domain}"
                prof_node = EntityNode.create(
                    type=EntityType.SOCIAL_PROFILE,
                    value=url,
                    label=f"{name.title()}: {email}",
                    attributes={
                        "platform": name,
                        "domain": domain,
                        "exists": True,
                        "rate_limit": False,
                        "recovery_email": item.get("emailrecovery"),
                        "phone_hint": item.get("phoneNumber"),
                        "others": item.get("others"),
                        "method": item.get("method"),
                    },
                    confidence=0.95,
                )
                entities.append(prof_node)
                relations.append(
                    RelationEdge(
                        source_id=email_node.id,
                        target_id=prof_node.id,
                        relation_type=RelationType.REGISTERED_ON,
                        confidence=0.95,
                        attributes={"platform": name, "domain": domain},
                    )
                )

        if matches_found == 0 and timed_out:
            logger.info(
                "No holehe profiles found during timeout; falling back to EmailInvestigator"
            )
            fallback_res = await EmailInvestigator().collect(email, **kwargs)
            fallback_res.metadata["holehe_timeout"] = True
            fallback_res.metadata["holehe_fallback"] = True
            return fallback_res

        return CollectorResult(
            collector_name=self.name,
            source_target=email,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"email": email, "results": raw_results}, indent=2),
            metadata={
                "services_checked": services_checked,
                "matches_found": matches_found,
                "rate_limited_count": rate_limited_count,
                "timeout": timed_out,
            },
        )


class IdentityCollector(BaseCollector):
    """
    Colector unificado de identidad que orquesta investigaciones
    de nombre de usuario (Maigret + WhatsMyName) y de email (Holehe + MX/Gravatar).
    """

    def __init__(
        self,
        maigret_timeout: float = 25.0,
        maigret_top_sites: int = 100,
        holehe_timeout: float = 15.0,
        holehe_max_connections: int = 25,
    ):
        super().__init__(name="identity_collector")
        self.maigret_timeout = maigret_timeout
        self.maigret_top_sites = maigret_top_sites
        self.holehe_timeout = holehe_timeout
        self.holehe_max_connections = holehe_max_connections

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        cleaned = target.strip()
        if "@" in cleaned and not cleaned.startswith("@"):
            return await self.investigate_email(cleaned, **kwargs)
        return await self.investigate_username(cleaned, **kwargs)

    async def investigate_username(self, username: str, **kwargs: Any) -> CollectorResult:
        clean_user = username.strip().lstrip("@")
        built_in_res = await UsernameInvestigator().collect(clean_user, **kwargs)

        entities_by_id = {e.id: e for e in built_in_res.entities}
        relations_by_key = {r.edge_id: r for r in built_in_res.relations}

        use_maigret = kwargs.get("use_maigret", True)
        maigret_metadata: dict[str, Any] = {}
        if use_maigret:
            try:
                maigret_hunter = MaigretHunter(
                    timeout=kwargs.get("maigret_timeout", self.maigret_timeout),
                    top_sites_limit=kwargs.get("top_sites_limit", self.maigret_top_sites),
                    site_list=kwargs.get("site_list"),
                )
                maigret_res = await maigret_hunter.collect(clean_user, **kwargs)
                maigret_metadata = maigret_res.metadata
                for e in maigret_res.entities:
                    if e.id not in entities_by_id:
                        entities_by_id[e.id] = e
                    else:
                        entities_by_id[e.id].attributes.update(e.attributes)
                for r in maigret_res.relations:
                    if r.edge_id not in relations_by_key:
                        relations_by_key[r.edge_id] = r
            except Exception as exc:
                maigret_metadata = {"maigret_error": str(exc), "maigret_fallback": True}

        all_entities = list(entities_by_id.values())
        all_relations = list(relations_by_key.values())
        return CollectorResult(
            collector_name=self.name,
            source_target=clean_user,
            entities=all_entities,
            relations=all_relations,
            raw_payload=json.dumps(
                {
                    "target": clean_user,
                    "built_in_metadata": built_in_res.metadata,
                    "maigret_metadata": maigret_metadata,
                },
                indent=2,
            ),
            metadata={
                **built_in_res.metadata,
                "maigret_enabled": use_maigret and is_maigret_available(),
                **maigret_metadata,
                "total_entities": len(all_entities),
                "total_relations": len(all_relations),
            },
        )

    async def investigate_email(self, email: str, **kwargs: Any) -> CollectorResult:
        clean_email = email.strip().lower()
        use_holehe = kwargs.get("use_holehe", False)
        email_options = {key: value for key, value in kwargs.items() if key != "use_holehe"}
        # El wrapper hace una única consulta Holehe más abajo, con sus propios
        # límites de concurrencia; evitar que EmailInvestigator la repita.
        built_in_res = await EmailInvestigator().collect(
            clean_email, use_holehe=False, **email_options
        )

        entities_by_id = {e.id: e for e in built_in_res.entities}
        relations_by_key = {r.edge_id: r for r in built_in_res.relations}

        holehe_metadata: dict[str, Any] = {}
        if use_holehe:
            try:
                holehe_hunter = HoleheHunter(
                    timeout=kwargs.get("holehe_timeout", self.holehe_timeout),
                    max_connections=kwargs.get(
                        "holehe_max_connections", self.holehe_max_connections
                    ),
                    services=kwargs.get("services"),
                )
                holehe_res = await holehe_hunter.collect(clean_email, **kwargs)
                holehe_metadata = holehe_res.metadata
                for e in holehe_res.entities:
                    if e.id not in entities_by_id:
                        entities_by_id[e.id] = e
                    else:
                        entities_by_id[e.id].attributes.update(e.attributes)
                for r in holehe_res.relations:
                    if r.edge_id not in relations_by_key:
                        relations_by_key[r.edge_id] = r
            except Exception as exc:
                holehe_metadata = {"holehe_error": str(exc), "holehe_fallback": True}

        all_entities = list(entities_by_id.values())
        all_relations = list(relations_by_key.values())
        return CollectorResult(
            collector_name=self.name,
            source_target=clean_email,
            entities=all_entities,
            relations=all_relations,
            raw_payload=json.dumps(
                {
                    "target": clean_email,
                    "built_in_metadata": built_in_res.metadata,
                    "holehe_metadata": holehe_metadata,
                },
                indent=2,
            ),
            metadata={
                **built_in_res.metadata,
                "holehe_enabled": use_holehe and is_holehe_available(),
                **holehe_metadata,
                "total_entities": len(all_entities),
                "total_relations": len(all_relations),
            },
        )


__all__ = [
    "PLATFORM_DEFINITIONS",
    "is_wmn_match",
    "is_maigret_available",
    "is_holehe_available",
    "UsernameInvestigator",
    "EmailInvestigator",
    "MaigretHunter",
    "HoleheHunter",
    "IdentityCollector",
]

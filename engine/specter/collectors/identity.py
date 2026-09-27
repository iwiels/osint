"""
SpecterOSINT - Identity & Social Footprint Collectors
Colectores para investigación de nombres de usuario (patrón Sherlock/WhatsMyName) y correos electrónicos.
"""

import asyncio
import hashlib
import json
import re
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

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
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
            },
        )


class EmailInvestigator(BaseCollector):
    def __init__(self):
        super().__init__(name="email_investigator")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
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

        return CollectorResult(
            collector_name=self.name,
            source_target=email,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(intel_report, indent=2),
            metadata={"has_mx": len(intel_report.get("mx_records", [])) > 0},
        )

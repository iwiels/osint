"""
SpecterOSINT - Subdomain Takeover Checker.

Verifica si los subdominios de un objetivo son vulnerables a takeover:
un subdominio que resuelve DNS pero cuyo servicio asociado está disponible
(no reclamado) permite a un atacante tomar control del mismo.

Servicios soportados: AWS S3, GitHub Pages, Heroku, Azure, DigitalOcean,
GitLab, WordPress, Tumblr, Shopify, Fastly, Ghost, Pantheon, Surge,
Netlify, Vercel, Firebase.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
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

logger = logging.getLogger("specter.collectors.subdomain_takeover")

_TIMEOUT = 10.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+subdomain-takeover)"}


@dataclass(frozen=True)
class TakeoverService:
    """Definición de un servicio vulnerable a subdomain takeover."""

    name: str
    pattern: str
    cname_suffix: str
    check_url: str
    available_indicators: tuple[str, ...]


# Catálogo de servicios vulnerables a takeover
TAKEOVER_SERVICES: tuple[TakeoverService, ...] = (
    TakeoverService(
        name="aws_s3",
        pattern=r"\.s3\.amazonaws\.com$",
        cname_suffix=".s3.amazonaws.com",
        check_url="https://{subdomain}.s3.amazonaws.com",
        available_indicators=("NoSuchBucket", "The specified bucket does not exist"),
    ),
    TakeoverService(
        name="github_pages",
        pattern=r"\.github\.io$",
        cname_suffix=".github.io",
        check_url="https://{subdomain}",
        available_indicators=("404", "There isn't a GitHub Pages site here"),
    ),
    TakeoverService(
        name="heroku",
        pattern=r"\.herokuapp\.com$",
        cname_suffix=".herokuapp.com",
        check_url="https://{subdomain}.herokuapp.com",
        available_indicators=("No such app", "herokucdn.com/error-pages/no-such-app.html"),
    ),
    TakeoverService(
        name="azure_blob",
        pattern=r"\.blob\.core\.windows\.net$",
        cname_suffix=".blob.core.windows.net",
        check_url="https://{subdomain}.blob.core.windows.net",
        available_indicators=("BlobNotFound", "The specified blob does not exist"),
    ),
    TakeoverService(
        name="digitalocean",
        pattern=r"\.digitaloceanspaces\.com$",
        cname_suffix=".digitaloceanspaces.com",
        check_url="https://{subdomain}.digitaloceanspaces.com",
        available_indicators=("NoSuchBucket", "The specified bucket does not exist"),
    ),
    TakeoverService(
        name="gitlab_pages",
        pattern=r"\.gitlab\.io$",
        cname_suffix=".gitlab.io",
        check_url="https://{subdomain}",
        available_indicators=("404", "The page you're looking for could not be found"),
    ),
    TakeoverService(
        name="wordpress",
        pattern=r"\.wordpress\.com$",
        cname_suffix=".wordpress.com",
        check_url="https://{subdomain}.wordpress.com",
        available_indicators=("Do you want to register", "this site is currently private"),
    ),
    TakeoverService(
        name="tumblr",
        pattern=r"\.tumblr\.com$",
        cname_suffix=".tumblr.com",
        check_url="https://{subdomain}.tumblr.com",
        available_indicators=("404", "There's nothing here"),
    ),
    TakeoverService(
        name="shopify",
        pattern=r"\.myshopify\.com$",
        cname_suffix=".myshopify.com",
        check_url="https://{subdomain}.myshopify.com",
        available_indicators=("Sorry, this shop is currently unavailable", "not found"),
    ),
    TakeoverService(
        name="fastly",
        pattern=r"\.fastly\.net$",
        cname_suffix=".fastly.net",
        check_url="https://{subdomain}.fastly.net",
        available_indicators=("Fastly error: unknown domain", "domain is not configured"),
    ),
    TakeoverService(
        name="ghost",
        pattern=r"\.ghost\.io$",
        cname_suffix=".ghost.io",
        check_url="https://{subdomain}.ghost.io",
        available_indicators=("404", "The thing you were looking for is no longer here"),
    ),
    TakeoverService(
        name="pantheon",
        pattern=r"\.pantheonsite\.io$",
        cname_suffix=".pantheonsite.io",
        check_url="https://{subdomain}.pantheonsite.io",
        available_indicators=("404", "The gods are wise"),
    ),
    TakeoverService(
        name="surge",
        pattern=r"\.surge\.sh$",
        cname_suffix=".surge.sh",
        check_url="https://{subdomain}.surge.sh",
        available_indicators=("404", "project not found"),
    ),
    TakeoverService(
        name="netlify",
        pattern=r"\.netlify\.app$",
        cname_suffix=".netlify.app",
        check_url="https://{subdomain}.netlify.app",
        available_indicators=("404", "Not Found", "The site you're looking for is not here"),
    ),
    TakeoverService(
        name="vercel",
        pattern=r"\.vercel\.app$",
        cname_suffix=".vercel.app",
        check_url="https://{subdomain}.vercel.app",
        available_indicators=("404", "The deployment could not be found on Vercel"),
    ),
    TakeoverService(
        name="firebase",
        pattern=r"\.firebaseapp\.com$",
        cname_suffix=".firebaseapp.com",
        check_url="https://{subdomain}.firebaseapp.com",
        available_indicators=("404", "Site Not Found"),
    ),
)


def _match_service(subdomain: str) -> TakeoverService | None:
    """Identifica el servicio asociado a un subdominio."""
    for service in TAKEOVER_SERVICES:
        if re.search(service.pattern, subdomain, re.IGNORECASE):
            return service
    return None


async def _check_takeover(
    client: httpx.AsyncClient, subdomain: str, service: TakeoverService
) -> bool:
    """Verifica si un subdominio está vulnerable a takeover para un servicio."""
    url = service.check_url.format(subdomain=quote(subdomain))
    try:
        resp = await client.get(url, headers=_UA, follow_redirects=True)
        body = resp.text.lower()
        for indicator in service.available_indicators:
            if indicator.lower() in body:
                return True
        # Algunos servicios devuelven 404 con body vacío
        if resp.status_code == 404 and len(body) < 100:
            return True
    except Exception:
        return False
    return False


class SubdomainTakeoverCollector(BaseCollector):
    """Verifica si subdominios son vulnerables a subdomain takeover."""

    def __init__(self) -> None:
        super().__init__(name="subdomain_takeover")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        """
        Verifica subdominios del objetivo contra el catálogo de servicios.

        El target puede ser un dominio (se verifican subdominios comunes) o
        una lista de subdominios separados por comas.
        """
        target_clean = target.strip().lower()

        # Si el target contiene comas o espacios, tratar como lista de subdominios
        if "," in target_clean or " " in target_clean:
            subdomains = [
                s.strip()
                for s in re.split(r"[,\s]+", target_clean)
                if s.strip() and "." in s.strip()
            ]
        else:
            # Generar subdominios comunes para verificar
            subdomains = self._generate_subdomains(target_clean)

        if not subdomains:
            return CollectorResult(
                collector_name=self.name,
                source_target=target_clean,
                raw_payload=json.dumps({"target": target_clean, "subdomains": []}),
                metadata={"ok": True, "vulnerable": 0, "checked": 0},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        vulnerable: list[dict[str, str]] = []
        checked = 0

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            tasks = []
            for subdomain in subdomains:
                service = _match_service(subdomain)
                if service:
                    tasks.append((subdomain, service, _check_takeover(client, subdomain, service)))
                    checked += 1

            if tasks:
                results = await asyncio.gather(*[t[2] for t in tasks], return_exceptions=True)
                for (subdomain, service, _), result in zip(tasks, results, strict=True):
                    if isinstance(result, Exception):
                        continue
                    if result:
                        vulnerable.append({"subdomain": subdomain, "service": service.name})
                        sub_node = EntityNode.create(
                            EntityType.SUBDOMAIN,
                            subdomain,
                            f"Vulnerable: {subdomain}",
                            attributes={
                                "service": service.name,
                                "vulnerable": True,
                                "source": "subdomain_takeover",
                            },
                            confidence=0.85,
                        )
                        entities.append(sub_node)
                        relations.append(
                            RelationEdge(
                                source_id=sub_node.id,
                                target_id=f"domain:{target_clean}",
                                relation_type=RelationType.VULNERABLE_TO,
                                attributes={"service": service.name},
                            )
                        )

        return CollectorResult(
            collector_name=self.name,
            source_target=target_clean,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "target": target_clean,
                    "checked": checked,
                    "vulnerable": vulnerable,
                },
                ensure_ascii=False,
            ),
            metadata={
                "ok": True,
                "checked": checked,
                "vulnerable": len(vulnerable),
            },
        )

    def _generate_subdomains(self, domain: str) -> list[str]:
        """Genera subdominios comunes para verificar takeover."""
        common_prefixes = [
            "www",
            "mail",
            "ftp",
            "admin",
            "blog",
            "shop",
            "api",
            "dev",
            "staging",
            "test",
            "app",
            "portal",
            "vpn",
            "remote",
            "email",
            "cloud",
            "cdn",
            "static",
            "media",
            "images",
        ]
        return [f"{prefix}.{domain}" for prefix in common_prefixes]

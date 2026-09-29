"""
SpecterOSINT - Similar Domain Finders
Detecta dominios similares (typosquatting) y variantes en otros TLDs.

- SimilarDomainFinderCollector: genera variaciones del dominio base
  (omisión, duplicación, sustitución de caracteres) y verifica su existencia.
- TLDSearchCollector: busca el mismo nombre de dominio en diferentes TLDs.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import dns.asyncresolver
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.similar_domains")

_TIMEOUT = 10.0
_CONCURRENCY = 20

# Caracteres que suelen sustituirse en typosquatting
_NEAR_CHARS: dict[str, tuple[str, ...]] = {
    "a": ("4", "s"),
    "b": ("v", "n", "6"),
    "c": ("x", "v", "8"),
    "d": ("s", "f"),
    "e": ("w", "r", "3"),
    "f": ("d", "g"),
    "g": ("f", "h"),
    "h": ("g", "j", "n"),
    "i": ("o", "u", "1"),
    "j": ("k", "h", "i"),
    "k": ("l", "j"),
    "l": ("i", "1", "k"),
    "m": ("n",),
    "n": ("m",),
    "o": ("p", "i", "0"),
    "p": ("o", "q"),
    "r": ("t", "e"),
    "s": ("a", "d", "5"),
    "t": ("7", "y", "z", "r"),
    "u": ("v", "i", "y", "z"),
    "v": ("u", "c", "b"),
    "w": ("v", "q", "e"),
    "x": ("z", "y", "c"),
    "y": ("z", "x"),
    "z": ("y", "x"),
    "0": ("o",),
    "1": ("l",),
    "2": ("5",),
    "3": ("e",),
    "4": ("a",),
    "5": ("s",),
    "6": ("b",),
    "7": ("t",),
    "8": ("b",),
    "9": (),
}

# TLDs comunes para búsqueda
_COMMON_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "io",
    "co",
    "info",
    "biz",
    "me",
    "tv",
    "cc",
    "xyz",
    "online",
    "site",
    "tech",
    "store",
    "app",
    "dev",
    "ai",
    "cloud",
    "us",
    "uk",
    "de",
    "fr",
    "es",
    "it",
    "nl",
    "ru",
    "cn",
    "jp",
    "br",
    "au",
    "ca",
    "mx",
    "ar",
    "cl",
    "co.uk",
    "com.ar",
    "com.mx",
    "com.br",
)


def _split_domain(domain: str) -> tuple[str, str]:
    """Separa el dominio en (nombre, TLD). Retorna (domain, '') si no hay TLD."""
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return domain, ""


def _generate_omissions(domain: str) -> list[str]:
    """Genera variaciones omitiendo un carácter."""
    variations: list[str] = []
    for i in range(len(domain)):
        variations.append(domain[:i] + domain[i + 1 :])
    return variations


def _generate_duplicates(domain: str) -> list[str]:
    """Genera variaciones duplicando un carácter."""
    variations: list[str] = []
    for i in range(len(domain)):
        variations.append(domain[: i + 1] + domain[i] + domain[i + 1 :])
    return variations


def _generate_substitutions(domain: str) -> list[str]:
    """Genera variaciones sustituyendo caracteres por similares."""
    variations: list[str] = []
    for i, char in enumerate(domain):
        replacements = _NEAR_CHARS.get(char.lower(), ())
        for repl in replacements:
            variations.append(domain[:i] + repl + domain[i + 1 :])
    return variations


def _generate_all_variations(domain: str) -> set[str]:
    """Genera todas las variaciones posibles del dominio."""
    variations: set[str] = set()
    variations.update(_generate_omissions(domain))
    variations.update(_generate_duplicates(domain))
    variations.update(_generate_substitutions(domain))
    # Eliminar el dominio original y variaciones vacías
    variations.discard(domain)
    variations.discard("")
    return variations


async def _check_domain_exists(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
) -> tuple[str, bool]:
    """Verifica si un dominio existe resolviendo DNS."""
    async with semaphore:
        try:
            await resolver.resolve(domain, "A")
            return domain, True
        except Exception:
            return domain, False


class SimilarDomainFinderCollector(BaseCollector):
    """Busca dominios similares (typosquatting) a un dominio base.

    Genera variaciones del dominio (omisión de caracteres, duplicación,
    sustitución de caracteres similares) y verifica cuáles existen.
    """

    def __init__(self) -> None:
        super().__init__(name="similar_domains")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower().rstrip(".")
        name, tld = _split_domain(domain)
        base_tld = tld or "com"

        # Generar variaciones
        variations = _generate_all_variations(name)
        # Reconstruir con el TLD base
        candidate_domains = [f"{v}.{base_tld}" for v in variations]

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found_domains: list[dict[str, Any]] = []

        # Nodo raíz
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"Dominio: {domain}",
            attributes={"source": "similar_domains"},
        )
        entities.append(root)

        # Resolver variaciones concurrentemente
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        semaphore = asyncio.Semaphore(_CONCURRENCY)
        tasks = [_check_domain_exists(d, resolver, semaphore) for d in candidate_domains]
        results = await asyncio.gather(*tasks)

        for candidate, exists in results:
            if exists:
                node = EntityNode.create(
                    EntityType.DOMAIN,
                    candidate,
                    f"Dominio similar: {candidate}",
                    attributes={
                        "source": "similar_domains",
                        "variation_type": "typosquatting",
                        "base_domain": domain,
                    },
                    confidence=0.7,
                )
                entities.append(node)
                relations.append(
                    RelationEdge(
                        source_id=node.id,
                        target_id=root.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
                found_domains.append({"domain": candidate, "type": "typosquatting"})

        metadata: dict[str, Any] = {
            "ok": True,
            "domain": domain,
            "variations_checked": len(candidate_domains),
            "domains_found": len(found_domains),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "variations_checked": len(candidate_domains),
                    "found": found_domains,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )


class TLDSearchCollector(BaseCollector):
    """Busca el mismo nombre de dominio en diferentes TLDs.

    Verifica la existencia del dominio base en TLDs comunes.
    """

    def __init__(self) -> None:
        super().__init__(name="tld_search")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower().rstrip(".")
        name, original_tld = _split_domain(domain)

        # TLDs a verificar (excluir el original)
        tlds_to_check = [t for t in _COMMON_TLDS if t != original_tld]

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found_domains: list[dict[str, Any]] = []

        # Nodo raíz
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"Dominio: {domain}",
            attributes={"source": "tld_search"},
        )
        entities.append(root)

        # Resolver concurrentemente
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0

        semaphore = asyncio.Semaphore(_CONCURRENCY)
        tasks = [
            _check_domain_exists(f"{name}.{tld}", resolver, semaphore) for tld in tlds_to_check
        ]
        results = await asyncio.gather(*tasks)

        for tld, (candidate, exists) in zip(tlds_to_check, results, strict=True):
            if exists:
                node = EntityNode.create(
                    EntityType.DOMAIN,
                    candidate,
                    f"Dominio en .{tld}: {candidate}",
                    attributes={
                        "source": "tld_search",
                        "tld": tld,
                        "base_domain": domain,
                    },
                    confidence=0.8,
                )
                entities.append(node)
                relations.append(
                    RelationEdge(
                        source_id=node.id,
                        target_id=root.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
                found_domains.append({"domain": candidate, "tld": tld})

        metadata: dict[str, Any] = {
            "ok": True,
            "domain": domain,
            "tlds_checked": len(tlds_to_check),
            "domains_found": len(found_domains),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "tlds_checked": len(tlds_to_check),
                    "found": found_domains,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )

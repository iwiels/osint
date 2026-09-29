"""
SpecterOSINT - Social Media Collectors
Colectores de plataformas de social media (gratuitos, sin API key).

Cada colector extrae información pública de perfiles en plataformas
como Twitter, Flickr, SlideShare, MySpace, Venmo y Keybase.
"""

from __future__ import annotations

import json
import logging
import re
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

logger = logging.getLogger("specter.collectors.social_media")

_TIMEOUT = 15.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+social-media)"}


async def _fetch(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    """Fetch URL y retorna JSON o None en caso de error."""
    try:
        resp = await client.get(url, headers=_UA, timeout=_TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        logger.debug("Error fetching %s: %s", url, exc)
    return None


async def _fetch_text(client: httpx.AsyncClient, url: str) -> str | None:
    """Fetch URL y retorna texto o None en caso de error."""
    try:
        resp = await client.get(url, headers=_UA, timeout=_TIMEOUT)
        if resp.status_code == 200:
            return resp.text
    except Exception as exc:
        logger.debug("Error fetching %s: %s", url, exc)
    return None


class TwitterCollector(BaseCollector):
    """Twitter (gratis, sin key).

    Recibe un username y extrae: nombre, bio, ubicación, seguidores,
    tweets recientes. Retorna entidades SOCIAL_PROFILE y PERSON.
    """

    def __init__(self) -> None:
        super().__init__(name="twitter")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        username = target.strip().lstrip("@")
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        async with httpx.AsyncClient() as client:
            # Usar nitter como alternativa gratuita a Twitter
            url = f"https://nitter.net/{username}"
            text = await _fetch_text(client, url)

            if not text:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=target,
                    entities=entities,
                    relations=relations,
                    raw_payload=None,
                    metadata={
                        "ok": False,
                        "error": "No se pudo obtener el perfil de Twitter",
                    },
                )

            # Extraer información del perfil
            name_match = re.search(r'<a class="fullname"[^>]*>([^<]+)</a>', text)
            bio_match = re.search(r'<div class="bio"[^>]*>([^<]+)</div>', text)
            location_match = re.search(r'<div class="location"[^>]*>([^<]+)</div>', text)
            followers_match = re.search(
                r'<span class="followers">[^<]*<strong>(\d+)</strong>', text
            )

            full_name = name_match.group(1).strip() if name_match else username
            bio = bio_match.group(1).strip() if bio_match else ""
            location = location_match.group(1).strip() if location_match else ""
            followers = int(followers_match.group(1)) if followers_match else 0

            # Crear nodo de perfil social
            profile_url = f"https://twitter.com/{username}"
            profile_node = EntityNode.create(
                EntityType.SOCIAL_PROFILE,
                profile_url,
                f"Twitter: @{username}",
                attributes={
                    "source": "twitter",
                    "username": username,
                    "full_name": full_name,
                    "bio": bio,
                    "location": location,
                    "followers": followers,
                    "platform": "Twitter",
                },
                confidence=0.9,
            )
            entities.append(profile_node)

            # Crear nodo de PERSON si se encontró nombre completo
            if full_name and full_name != username:
                person_node = EntityNode.create(
                    EntityType.PERSON,
                    full_name,
                    full_name,
                    attributes={
                        "source": "twitter",
                        "username": username,
                        "location": location,
                    },
                    confidence=0.8,
                )
                entities.append(person_node)
                relations.append(
                    RelationEdge(
                        source_id=person_node.id,
                        target_id=profile_node.id,
                        relation_type=RelationType.HAS_ACCOUNT,
                    )
                )

            # Crear nodo de ubicación si se encontró
            if location:
                location_node = EntityNode.create(
                    EntityType.GEO_LOCATION,
                    location,
                    location,
                    attributes={"source": "twitter", "platform": "Twitter"},
                    confidence=0.7,
                )
                entities.append(location_node)
                relations.append(
                    RelationEdge(
                        source_id=profile_node.id,
                        target_id=location_node.id,
                        relation_type=RelationType.LOCATED_AT,
                    )
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "platform": "Twitter",
            "username": username,
            "full_name": full_name,
            "followers": followers,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=text[:5000] if text else None,
            metadata=metadata,
        )


class FlickrCollector(BaseCollector):
    """Flickr (gratis, sin key).

    Recibe un dominio o email y busca en Flickr.
    Retorna entidades SOCIAL_PROFILE.
    """

    def __init__(self) -> None:
        super().__init__(name="flickr")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        async with httpx.AsyncClient() as client:
            # Buscar en Flickr por texto
            search_url = f"https://www.flickr.com/search/?text={quote(target)}"
            text = await _fetch_text(client, search_url)

            if not text:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=target,
                    entities=entities,
                    relations=relations,
                    raw_payload=None,
                    metadata={
                        "ok": False,
                        "error": "No se pudo buscar en Flickr",
                    },
                )

            # Extraer perfiles de Flickr
            profile_pattern = r'href="(https://www\.flickr\.com/photos/[^"]+)"'
            profiles = re.findall(profile_pattern, text)

            seen: set[str] = set()
            for profile_url in profiles[:10]:
                if profile_url in seen:
                    continue
                seen.add(profile_url)

                username = profile_url.rstrip("/").split("/")[-1]
                profile_node = EntityNode.create(
                    EntityType.SOCIAL_PROFILE,
                    profile_url,
                    f"Flickr: {username}",
                    attributes={
                        "source": "flickr",
                        "username": username,
                        "platform": "Flickr",
                        "search_query": target,
                    },
                    confidence=0.7,
                )
                entities.append(profile_node)

        metadata: dict[str, Any] = {
            "ok": True,
            "platform": "Flickr",
            "search_query": target,
            "profiles_found": len(entities),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=text[:5000] if text else None,
            metadata=metadata,
        )


class SlideShareCollector(BaseCollector):
    """SlideShare (gratis, sin key).

    Recibe un nombre de usuario y extrae: nombre, ubicación, presentaciones.
    Retorna entidades SOCIAL_PROFILE y PERSON.
    """

    def __init__(self) -> None:
        super().__init__(name="slideshare")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        username = target.strip()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        async with httpx.AsyncClient() as client:
            url = f"https://www.slideshare.net/{username}"
            text = await _fetch_text(client, url)

            if not text:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=target,
                    entities=entities,
                    relations=relations,
                    raw_payload=None,
                    metadata={
                        "ok": False,
                        "error": "No se pudo obtener el perfil de SlideShare",
                    },
                )

            # Extraer nombre del perfil
            name_match = re.search(r'<meta property="slideshare:name"\s+content="([^"]+)"', text)
            location_match = re.search(
                r'<meta property="slideshare:location"\s+content="([^"]+)"', text
            )

            full_name = name_match.group(1).strip() if name_match else username
            location = location_match.group(1).strip() if location_match else ""

            # Crear nodo de perfil social
            profile_url = f"https://www.slideshare.net/{username}"
            profile_node = EntityNode.create(
                EntityType.SOCIAL_PROFILE,
                profile_url,
                f"SlideShare: {username}",
                attributes={
                    "source": "slideshare",
                    "username": username,
                    "full_name": full_name,
                    "location": location,
                    "platform": "SlideShare",
                },
                confidence=0.9,
            )
            entities.append(profile_node)

            # Crear nodo de PERSON si se encontró nombre completo
            if full_name and full_name != username:
                person_node = EntityNode.create(
                    EntityType.PERSON,
                    full_name,
                    full_name,
                    attributes={
                        "source": "slideshare",
                        "username": username,
                        "location": location,
                    },
                    confidence=0.8,
                )
                entities.append(person_node)
                relations.append(
                    RelationEdge(
                        source_id=person_node.id,
                        target_id=profile_node.id,
                        relation_type=RelationType.HAS_ACCOUNT,
                    )
                )

            # Crear nodo de ubicación si se encontró
            if location:
                location_node = EntityNode.create(
                    EntityType.GEO_LOCATION,
                    location,
                    location,
                    attributes={"source": "slideshare", "platform": "SlideShare"},
                    confidence=0.7,
                )
                entities.append(location_node)
                relations.append(
                    RelationEdge(
                        source_id=profile_node.id,
                        target_id=location_node.id,
                        relation_type=RelationType.LOCATED_AT,
                    )
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "platform": "SlideShare",
            "username": username,
            "full_name": full_name,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=text[:5000] if text else None,
            metadata=metadata,
        )


class MySpaceCollector(BaseCollector):
    """MySpace (gratis, sin key).

    Recibe un username y extrae: nombre, ubicación, perfil.
    Retorna entidades SOCIAL_PROFILE y PERSON.
    """

    def __init__(self) -> None:
        super().__init__(name="myspace")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        username = target.strip()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        async with httpx.AsyncClient() as client:
            url = f"https://myspace.com/{username}"
            text = await _fetch_text(client, url)

            if not text:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=target,
                    entities=entities,
                    relations=relations,
                    raw_payload=None,
                    metadata={
                        "ok": False,
                        "error": "No se pudo obtener el perfil de MySpace",
                    },
                )

            # Extraer información del perfil
            name_match = re.search(r"<h1[^>]*>([^<]+)</h1>", text)
            location_match = re.search(
                r'<div class="location_[^"]+" data-display-text="([^"]+)"', text
            )

            full_name = name_match.group(1).strip() if name_match else username
            location = location_match.group(1).strip() if location_match else ""

            # Crear nodo de perfil social
            profile_url = f"https://myspace.com/{username}"
            profile_node = EntityNode.create(
                EntityType.SOCIAL_PROFILE,
                profile_url,
                f"MySpace: {username}",
                attributes={
                    "source": "myspace",
                    "username": username,
                    "full_name": full_name,
                    "location": location,
                    "platform": "MySpace",
                },
                confidence=0.9,
            )
            entities.append(profile_node)

            # Crear nodo de PERSON si se encontró nombre completo
            if full_name and full_name != username:
                person_node = EntityNode.create(
                    EntityType.PERSON,
                    full_name,
                    full_name,
                    attributes={
                        "source": "myspace",
                        "username": username,
                        "location": location,
                    },
                    confidence=0.8,
                )
                entities.append(person_node)
                relations.append(
                    RelationEdge(
                        source_id=person_node.id,
                        target_id=profile_node.id,
                        relation_type=RelationType.HAS_ACCOUNT,
                    )
                )

            # Crear nodo de ubicación si se encontró
            if location:
                location_node = EntityNode.create(
                    EntityType.GEO_LOCATION,
                    location,
                    location,
                    attributes={"source": "myspace", "platform": "MySpace"},
                    confidence=0.7,
                )
                entities.append(location_node)
                relations.append(
                    RelationEdge(
                        source_id=profile_node.id,
                        target_id=location_node.id,
                        relation_type=RelationType.LOCATED_AT,
                    )
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "platform": "MySpace",
            "username": username,
            "full_name": full_name,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=text[:5000] if text else None,
            metadata=metadata,
        )


class VenmoCollector(BaseCollector):
    """Venmo (gratis, sin key).

    Recibe un username y extrae: nombre, perfil.
    Retorna entidades SOCIAL_PROFILE y PERSON.
    """

    def __init__(self) -> None:
        super().__init__(name="venmo")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        username = target.strip()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        async with httpx.AsyncClient() as client:
            # API pública de Venmo
            url = f"https://api.venmo.com/v1/users/{username}"
            data = await _fetch(client, url)

            if not data or "data" not in data:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=target,
                    entities=entities,
                    relations=relations,
                    raw_payload=None,
                    metadata={
                        "ok": False,
                        "error": "No se pudo obtener el perfil de Venmo",
                    },
                )

            user_data = data["data"]
            display_name = user_data.get("display_name", "")
            first_name = user_data.get("first_name", "")
            last_name = user_data.get("last_name", "")

            # Construir nombre completo si no hay display_name
            if not display_name and first_name and last_name:
                display_name = f"{first_name} {last_name}"

            # Crear nodo de perfil social
            profile_url = f"https://venmo.com/{username}"
            profile_node = EntityNode.create(
                EntityType.SOCIAL_PROFILE,
                profile_url,
                f"Venmo: {username}",
                attributes={
                    "source": "venmo",
                    "username": username,
                    "display_name": display_name,
                    "platform": "Venmo",
                },
                confidence=0.9,
            )
            entities.append(profile_node)

            # Crear nodo de PERSON si se encontró nombre
            if display_name:
                person_node = EntityNode.create(
                    EntityType.PERSON,
                    display_name,
                    display_name,
                    attributes={
                        "source": "venmo",
                        "username": username,
                    },
                    confidence=0.8,
                )
                entities.append(person_node)
                relations.append(
                    RelationEdge(
                        source_id=person_node.id,
                        target_id=profile_node.id,
                        relation_type=RelationType.HAS_ACCOUNT,
                    )
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "platform": "Venmo",
            "username": username,
            "display_name": display_name,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False)[:5000] if data else None,
            metadata=metadata,
        )


class KeybaseCollector(BaseCollector):
    """Keybase (gratis, sin key).

    Recibe un username y extrae: nombre, claves PGP, perfiles sociales.
    Retorna entidades SOCIAL_PROFILE y PERSON.
    """

    def __init__(self) -> None:
        super().__init__(name="keybase")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        username = target.strip()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        async with httpx.AsyncClient() as client:
            # API pública de Keybase
            url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}"
            data = await _fetch(client, url)

            if not data or data.get("status", {}).get("code") != 0:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=target,
                    entities=entities,
                    relations=relations,
                    raw_payload=None,
                    metadata={
                        "ok": False,
                        "error": "No se pudo obtener el perfil de Keybase",
                    },
                )

            them = data.get("them", [])
            if not them:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=target,
                    entities=entities,
                    relations=relations,
                    raw_payload=None,
                    metadata={
                        "ok": False,
                        "error": "Usuario no encontrado en Keybase",
                    },
                )

            user = them[0]
            basics = user.get("basics", {})
            profile = user.get("profile", {})
            proofs = user.get("proofs_summary", {}).get("all", [])

            # Extraer información básica
            kb_username = basics.get("username", username)
            full_name = profile.get("full_name", "")
            location = profile.get("location", "")

            # Crear nodo de perfil social
            profile_url = f"https://keybase.io/{kb_username}"
            profile_node = EntityNode.create(
                EntityType.SOCIAL_PROFILE,
                profile_url,
                f"Keybase: {kb_username}",
                attributes={
                    "source": "keybase",
                    "username": kb_username,
                    "full_name": full_name,
                    "location": location,
                    "platform": "Keybase",
                },
                confidence=0.9,
            )
            entities.append(profile_node)

            # Crear nodo de PERSON si se encontró nombre completo
            if full_name:
                person_node = EntityNode.create(
                    EntityType.PERSON,
                    full_name,
                    full_name,
                    attributes={
                        "source": "keybase",
                        "username": kb_username,
                        "location": location,
                    },
                    confidence=0.8,
                )
                entities.append(person_node)
                relations.append(
                    RelationEdge(
                        source_id=person_node.id,
                        target_id=profile_node.id,
                        relation_type=RelationType.HAS_ACCOUNT,
                    )
                )

            # Crear nodo de ubicación si se encontró
            if location:
                location_node = EntityNode.create(
                    EntityType.GEO_LOCATION,
                    location,
                    location,
                    attributes={"source": "keybase", "platform": "Keybase"},
                    confidence=0.7,
                )
                entities.append(location_node)
                relations.append(
                    RelationEdge(
                        source_id=profile_node.id,
                        target_id=location_node.id,
                        relation_type=RelationType.LOCATED_AT,
                    )
                )

            # Crear nodos para perfiles sociales vinculados
            for proof in proofs:
                proof_type = proof.get("proof_type", "")
                service_url = proof.get("service_url", "")
                if proof_type and service_url:
                    social_node = EntityNode.create(
                        EntityType.SOCIAL_PROFILE,
                        service_url,
                        f"{proof_type}: {service_url}",
                        attributes={
                            "source": "keybase",
                            "proof_type": proof_type,
                            "platform": proof_type,
                            "username": kb_username,
                        },
                        confidence=0.8,
                    )
                    entities.append(social_node)
                    relations.append(
                        RelationEdge(
                            source_id=profile_node.id,
                            target_id=social_node.id,
                            relation_type=RelationType.LINKED_TO,
                        )
                    )

        metadata: dict[str, Any] = {
            "ok": True,
            "platform": "Keybase",
            "username": kb_username,
            "full_name": full_name,
            "social_profiles": len(proofs),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False)[:5000] if data else None,
            metadata=metadata,
        )

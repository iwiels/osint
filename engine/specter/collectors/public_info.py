"""
WraithOSINT - Public Information Collectors
Fuentes de información pública para enriquecimiento forense.

- PasteBinSearchCollector: búsqueda de pastes relacionados con un dominio/email.
- WikipediaEditsCollector: ediciones de Wikipedia desde una IP o username.
- ZoneHDefacementCollector: verificación de defacement en Zone-H.
- PGPKeyServerCollector: búsqueda de claves PGP en servidores de claves.
- HostingProviderIdentifierCollector: identificación de proveedores de hosting.
- TORExitNodeCollector: verificación de nodos de salida Tor.
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
)

logger = logging.getLogger("specter.collectors.public_info")

_TIMEOUT = 15.0
_UA = {"User-Agent": "WraithOSINT/0.3 (+forense, key en boveda local)"}

# Patrones de proveedores de hosting conocidos
_HOSTING_PATTERNS: dict[str, tuple[str, ...]] = {
    "Amazon AWS": ("amazonaws.com", "aws.amazon.com", "ec2-", "elb-"),
    "Microsoft Azure": ("azure.com", "cloudapp.azure.com", "azurewebsites.net"),
    "Google Cloud": ("googleusercontent.com", "cloud.google.com", "gcp."),
    "DigitalOcean": ("digitalocean.com", "do-spaces."),
    "Linode": ("linode.com", "linodeobjects.com"),
    "Vultr": ("vultr.com", "vultrusercontent.com"),
    "Hetzner": ("hetzner.com", "hetzner.de", "your-server.de"),
    "OVH": ("ovh.com", "ovh.net", "ovhcloud.com"),
    "Cloudflare": ("cloudflare.com", "cloudflare.net"),
    "Akamai": ("akamai.com", "akamaiedge.net", "akamaitechnologies.com"),
    "Fastly": ("fastly.net", "fastlylb.net"),
    "Alibaba Cloud": ("aliyuncs.com", "aliyun.com"),
    "IBM Cloud": ("ibm.com", "softlayer.com"),
    "Oracle Cloud": ("oraclecloud.com", "oracle.com"),
}


class PasteBinSearchCollector(BaseCollector):
    """Búsqueda en PasteBin usando Google Custom Search.

    Busca pastes relacionados con un dominio o email.
    """

    def __init__(self) -> None:
        super().__init__(name="pastebin_search")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        query = target.strip()
        # Usar búsqueda web como proxy (Google Custom Search requiere API key)
        url = f"https://www.google.com/search?q=site:pastebin.com+{quote(query)}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        paste_urls: list[str] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=query,
                raw_payload=json.dumps({"target": query, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc)},
            )

        # Extraer URLs de pastebin del HTML
        pattern = r"https?://pastebin\.com/(?:raw/)?[a-zA-Z0-9]+"
        matches = re.findall(pattern, html)
        paste_urls = list(dict.fromkeys(matches))  # preservar orden, eliminar duplicados

        # Crear entidades ALIAS para cada paste encontrado
        for paste_url in paste_urls[:20]:
            node = EntityNode.create(
                EntityType.ALIAS,
                paste_url,
                f"Paste: {paste_url}",
                attributes={
                    "source": "pastebin_search",
                    "target": query,
                    "url": paste_url,
                },
                confidence=0.6,
            )
            entities.append(node)

        metadata: dict[str, Any] = {
            "ok": True,
            "target": query,
            "pastes_found": len(paste_urls),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "target": query,
                    "pastes": paste_urls,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )


class WikipediaEditsCollector(BaseCollector):
    """Ediciones de Wikipedia desde una IP o username.

    API: https://en.wikipedia.org/w/api.php?action=query&list=usercontribs
    """

    def __init__(self) -> None:
        super().__init__(name="wikipedia_edits")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        username = target.strip()
        url = (
            "https://en.wikipedia.org/w/api.php?"
            "action=query&list=usercontribs&ucuser="
            f"{quote(username)}&uclimit=50&format=json"
        )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        articles: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=username,
                raw_payload=json.dumps({"target": username, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc)},
            )

        # Procesar contribuciones
        contribs = data.get("query", {}).get("usercontribs", [])
        for contrib in contribs:
            title = contrib.get("title", "")
            if not title:
                continue

            article = {
                "title": title,
                "timestamp": contrib.get("timestamp", ""),
                "comment": contrib.get("comment", ""),
                "revid": contrib.get("revid"),
            }
            articles.append(article)

            node = EntityNode.create(
                EntityType.ALIAS,
                title,
                f"Artículo: {title}",
                attributes={
                    "source": "wikipedia_edits",
                    "editor": username,
                    "timestamp": article["timestamp"],
                    "comment": article["comment"],
                    "revid": article["revid"],
                },
                confidence=0.7,
            )
            entities.append(node)

        metadata: dict[str, Any] = {
            "ok": True,
            "editor": username,
            "articles_found": len(articles),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=username,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "editor": username,
                    "articles": articles,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )


class ZoneHDefacementCollector(BaseCollector):
    """Verificación de defacement en Zone-H.

    API: https://www.zone-h.org/archive/{domain}
    """

    def __init__(self) -> None:
        super().__init__(name="zoneh_defacement")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://www.zone-h.org/archive/{quote(domain)}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        defacements: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                html = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc)},
            )

        # Buscar indicadores de defacement en el HTML
        # Zone-H muestra una tabla con registros si hay defacements
        if "defacement" in html.lower() or "hacked" in html.lower():
            # Extraer entradas de defacement (patrón simplificado)
            pattern = r"defaced[^<]*|hacked by[^<]*"
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches[:10]:
                defacements.append({"description": match.strip()})

            # Crear entidad ALIAS para el registro de defacement
            node = EntityNode.create(
                EntityType.ALIAS,
                f"zoneh:{domain}",
                f"Defacement en Zone-H: {domain}",
                attributes={
                    "source": "zoneh_defacement",
                    "domain": domain,
                    "defacements": defacements,
                },
                confidence=0.8,
            )
            entities.append(node)

        metadata: dict[str, Any] = {
            "ok": True,
            "domain": domain,
            "defacements_found": len(defacements),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "defacements": defacements,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )


class PGPKeyServerCollector(BaseCollector):
    """Búsqueda de claves PGP en servidores de claves.

    API: https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index
    """

    def __init__(self) -> None:
        super().__init__(name="pgp_keyserver")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        email = target.strip()
        url = f"https://keyserver.ubuntu.com/pks/lookup?search={quote(email)}&op=index"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        keys: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=email,
                raw_payload=json.dumps({"email": email, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc)},
            )

        # El servidor de claves retorna un índice de claves en texto plano
        # Formato: pub:algorithm:keysize:keyid:creation:expiration:flags
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("pub:"):
                parts = line.split(":")
                if len(parts) >= 4:
                    key_info = {
                        "algorithm": parts[1],
                        "key_id": parts[3],
                        "creation": parts[4] if len(parts) > 4 else "",
                        "expiration": parts[5] if len(parts) > 5 else "",
                    }
                    keys.append(key_info)

                    node = EntityNode.create(
                        EntityType.ALIAS,
                        key_info["key_id"],
                        f"Clave PGP: {key_info['key_id']}",
                        attributes={
                            "source": "pgp_keyserver",
                            "email": email,
                            "algorithm": key_info["algorithm"],
                            "key_id": key_info["key_id"],
                            "creation": key_info["creation"],
                            "expiration": key_info["expiration"],
                        },
                        confidence=0.7,
                    )
                    entities.append(node)

        metadata: dict[str, Any] = {
            "ok": True,
            "email": email,
            "keys_found": len(keys),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=email,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "email": email,
                    "keys": keys,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )


class HostingProviderIdentifierCollector(BaseCollector):
    """Identificación de proveedores de hosting a partir de una IP.

    Usa patrones de reverse DNS y rangos conocidos.
    """

    def __init__(self) -> None:
        super().__init__(name="hosting_provider")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        providers: list[dict[str, Any]] = []

        # Intentar reverse DNS
        try:
            import socket

            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = ""

        # Buscar coincidencias con patrones conocidos
        if hostname:
            for provider, patterns in _HOSTING_PATTERNS.items():
                if any(pattern in hostname.lower() for pattern in patterns):
                    providers.append(
                        {
                            "provider": provider,
                            "hostname": hostname,
                            "confidence": 0.8,
                        }
                    )

                    node = EntityNode.create(
                        EntityType.ORGANIZATION,
                        provider,
                        f"Proveedor: {provider}",
                        attributes={
                            "source": "hosting_provider",
                            "ip": ip,
                            "hostname": hostname,
                        },
                        confidence=0.8,
                    )
                    entities.append(node)
                    break

        # Si no se encontró por hostname, crear entidad desconocida
        if not providers:
            node = EntityNode.create(
                EntityType.ORGANIZATION,
                "unknown",
                "Proveedor desconocido",
                attributes={
                    "source": "hosting_provider",
                    "ip": ip,
                    "hostname": hostname or "N/A",
                },
                confidence=0.3,
            )
            entities.append(node)

        metadata: dict[str, Any] = {
            "ok": True,
            "ip": ip,
            "hostname": hostname or "N/A",
            "providers_found": len(providers),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "providers": providers,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )


class TORExitNodeCollector(BaseCollector):
    """Verificación de nodos de salida Tor.

    API: https://check.torproject.org/torbulkexitlist
    """

    def __init__(self) -> None:
        super().__init__(name="tor_exit_node")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()
        url = "https://check.torproject.org/torbulkexitlist"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        is_exit_node = False

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc)},
            )

        # La lista es una IP por línea
        exit_nodes = {line.strip() for line in text.splitlines() if line.strip()}
        is_exit_node = ip in exit_nodes

        # Crear entidad IP_ADDRESS con el estado
        node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"IP: {ip}",
            attributes={
                "source": "tor_exit_node",
                "is_tor_exit": is_exit_node,
            },
            confidence=1.0 if is_exit_node else 0.5,
        )
        entities.append(node)

        metadata: dict[str, Any] = {
            "ok": True,
            "ip": ip,
            "is_tor_exit_node": is_exit_node,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "ip": ip,
                    "is_tor_exit_node": is_exit_node,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )

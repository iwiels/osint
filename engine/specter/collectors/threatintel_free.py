"""
WraithOSINT - Threat Intel gratuitos adicionales (Fase A extendida).

Fuentes gratuitas sin API key (excepto AbuseIPDB que es opcional):
- AlienVaultOTX: pulsos, malware y URLs asociadas a un dominio
- ThreatCrowd: votos, URLs, malware y emails
- ThreatMiner: subdominios, IPs, malware y pasivos DNS
- PhishTank: verificación de dominios de phishing conocidos
- OpenPhish: URLs de phishing activas
- MalwarePatrol: listas de IPs/dominios maliciosos
- Spamhaus Zen: listas de spam por IP
- Blocklist.de: IPs maliciosas conocidas
- DroneBL: estado de IP en listas negras
"""

from __future__ import annotations

import ipaddress
import json
import logging
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

logger = logging.getLogger("specter.collectors.threatintel_free")

_TIMEOUT = 12.0
_UA = {"User-Agent": "WraithOSINT/0.3 (+threatintel-free)"}


def _collector_key(vault_name: str) -> str | None:
    """Key de la bóveda local o su env equivalente. None = no configurada."""
    import os

    from specter import secrets as vault

    env_var = vault.ALLOWED_SECRETS.get(vault_name, "")
    return os.environ.get(env_var) or vault.get_secret(vault_name) or None


def _missing_key_result(name: str, target: str, vault_name: str) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        source_target=target,
        raw_payload=json.dumps({"target": target, "skipped": f"requiere {vault_name}"}),
        metadata={"ok": False, "requires_key": vault_name},
    )


def _is_routable_ip(target: str) -> bool:
    """Las fuentes externas no aportan nada sobre IPs privadas."""
    try:
        return ipaddress.ip_address(target.strip()).is_global
    except ValueError:
        return True


class AlienVaultOTXCollector(BaseCollector):
    """AlienVault OTX: pulsos, malware y URLs asociadas a un dominio."""

    def __init__(self) -> None:
        super().__init__(name="alienvault_otx")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{quote(domain)}/general"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"OTX: {domain}",
            attributes={"source": "alienvault_otx"},
        )
        entities.append(root)

        pulse_count = int(data.get("pulse_info", {}).get("count", 0))
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:10]:
            pulse_name = str(pulse.get("name", ""))
            if not pulse_name:
                continue
            pulse_node = EntityNode.create(
                EntityType.ALIAS,
                pulse_name,
                f"Pulso: {pulse_name}",
                attributes={
                    "pulse_id": pulse.get("id"),
                    "created": pulse.get("created"),
                    "source": "alienvault_otx",
                },
                confidence=0.7,
            )
            entities.append(pulse_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=pulse_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        for url_entry in data.get("url_list", [])[:20]:
            url_value = str(url_entry.get("url", ""))
            if not url_value:
                continue
            url_node = EntityNode.create(
                EntityType.ALIAS,
                url_value,
                f"URL: {url_value[:80]}",
                attributes={"date": url_entry.get("date"), "source": "alienvault_otx"},
                confidence=0.7,
            )
            entities.append(url_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=url_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "pulses": pulse_count}, ensure_ascii=False),
            metadata={"ok": True, "pulses": pulse_count},
        )


class ThreatCrowdCollector(BaseCollector):
    """ThreatCrowd: votos, URLs, malware y emails asociados a un dominio."""

    def __init__(self) -> None:
        super().__init__(name="threatcrowd")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        if data.get("response_code") != "1":
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps(
                    {"domain": domain, "response_code": data.get("response_code")}
                ),
                metadata={"ok": True, "found": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"ThreatCrowd: {domain}",
            attributes={"source": "threatcrowd"},
        )
        entities.append(root)

        votes = data.get("votes", 0)
        for url_entry in data.get("urls", [])[:20]:
            url_value = str(url_entry)
            if not url_value:
                continue
            url_node = EntityNode.create(
                EntityType.ALIAS,
                url_value,
                f"URL: {url_value[:80]}",
                attributes={"source": "threatcrowd"},
                confidence=0.7,
            )
            entities.append(url_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=url_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        for email in data.get("emails", [])[:10]:
            email_value = str(email)
            if not email_value:
                continue
            email_node = EntityNode.create(
                EntityType.EMAIL,
                email_value,
                f"Email: {email_value}",
                attributes={"source": "threatcrowd"},
                confidence=0.7,
            )
            entities.append(email_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=email_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "votes": votes}, ensure_ascii=False),
            metadata={"ok": True, "found": True, "votes": votes},
        )


class ThreatMinerCollector(BaseCollector):
    """ThreatMiner: subdominios, IPs, malware y pasivos DNS."""

    def __init__(self) -> None:
        super().__init__(name="threatminer")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://api.threatminer.org/v2/domain.php?q={quote(domain)}&rt=1"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        if data.get("status_code") != "200":
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "status": data.get("status_code")}),
                metadata={"ok": True, "found": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"ThreatMiner: {domain}",
            attributes={"source": "threatminer"},
        )
        entities.append(root)

        results = data.get("results", [])
        for subdomain in results[:30]:
            sub_value = str(subdomain)
            if not sub_value:
                continue
            sub_node = EntityNode.create(
                EntityType.SUBDOMAIN,
                sub_value,
                f"Subdominio: {sub_value}",
                attributes={"source": "threatminer"},
                confidence=0.8,
            )
            entities.append(sub_node)
            relations.append(
                RelationEdge(
                    source_id=sub_node.id,
                    target_id=root.id,
                    relation_type=RelationType.SUBDOMAIN_OF,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"domain": domain, "subdomains": len(results)}, ensure_ascii=False
            ),
            metadata={"ok": True, "found": True, "subdomains": len(results)},
        )


class PhishTankCollector(BaseCollector):
    """PhishTank: verifica si un dominio es phishing conocido."""

    def __init__(self) -> None:
        super().__init__(name="phishtank")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = "https://checkurl.phishtank.com/checkurl/"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    url,
                    data={"url": domain, "format": "json"},
                    headers=_UA,
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        in_database = bool(data.get("in_database", False))
        is_valid = bool(data.get("valid", False))
        phish = in_database and is_valid

        node = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"PhishTank: {domain}",
            attributes={
                "in_database": in_database,
                "valid": is_valid,
                "phish_id": data.get("phish_id"),
                "source": "phishtank",
            },
            confidence=0.9 if phish else 0.6,
        )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=[node],
            relations=[],
            raw_payload=json.dumps({"domain": domain, "phishing": phish}, ensure_ascii=False),
            metadata={"ok": True, "phishing": phish},
        )


class OpenPhishCollector(BaseCollector):
    """OpenPhish: URLs de phishing activas."""

    def __init__(self) -> None:
        super().__init__(name="openphish")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = "https://openphish.com/feed.txt"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        matching_urls: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if domain in line.lower():
                matching_urls.append(line)

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"OpenPhish: {domain}",
            attributes={"source": "openphish"},
        )
        entities.append(root)

        for url_value in matching_urls[:20]:
            url_node = EntityNode.create(
                EntityType.ALIAS,
                url_value,
                f"Phishing URL: {url_value[:80]}",
                attributes={"source": "openphish"},
                confidence=0.9,
            )
            entities.append(url_node)
            relations.append(
                RelationEdge(
                    source_id=root.id,
                    target_id=url_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"domain": domain, "matches": len(matching_urls)}, ensure_ascii=False
            ),
            metadata={"ok": True, "matches": len(matching_urls)},
        )


class MalwarePatrolCollector(BaseCollector):
    """MalwarePatrol: listas de IPs/dominios maliciosos."""

    def __init__(self) -> None:
        super().__init__(name="malwarepatrol")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = "https://www.malwarepatrol.net/cgi-bin/download.cgi"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        found = domain in text.lower()
        matching_lines: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if domain in line.lower():
                matching_lines.append(line)

        node = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"MalwarePatrol: {domain}",
            attributes={"listed": found, "source": "malwarepatrol"},
            confidence=0.9 if found else 0.5,
        )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=[node],
            relations=[],
            raw_payload=json.dumps({"domain": domain, "listed": found}, ensure_ascii=False),
            metadata={"ok": True, "listed": found},
        )


class SpamhausCollector(BaseCollector):
    """Spamhaus Zen: listas de spam por IP."""

    def __init__(self) -> None:
        super().__init__(name="spamhaus")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()
        if not _is_routable_ip(ip):
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "skipped": "IP no pública"}),
                metadata={"ok": False},
            )
        url = f"https://api.spamhaus.org/api/v1/zen/{quote(ip)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "error": str(exc)}),
                metadata={"ok": False},
            )

        listed = bool(data.get("listed", False))
        lists = data.get("lists", [])

        node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"Spamhaus: {ip}",
            attributes={
                "listed": listed,
                "lists": lists,
                "source": "spamhaus",
            },
            confidence=0.9 if listed else 0.6,
        )

        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=[node],
            relations=[],
            raw_payload=json.dumps(
                {"ip": ip, "listed": listed, "lists": lists}, ensure_ascii=False
            ),
            metadata={"ok": True, "listed": listed},
        )


class BlocklistCollector(BaseCollector):
    """Blocklist.de: IPs maliciosas conocidas."""

    def __init__(self) -> None:
        super().__init__(name="blocklist_de")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()
        if not _is_routable_ip(ip):
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "skipped": "IP no pública"}),
                metadata={"ok": False},
            )
        url = "https://lists.blocklist.de/lists/all.txt"
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
                metadata={"ok": False},
            )

        listed = False
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line == ip:
                listed = True
                break

        node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"Blocklist.de: {ip}",
            attributes={"listed": listed, "source": "blocklist_de"},
            confidence=0.9 if listed else 0.6,
        )

        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=[node],
            relations=[],
            raw_payload=json.dumps({"ip": ip, "listed": listed}, ensure_ascii=False),
            metadata={"ok": True, "listed": listed},
        )


class DroneBLCollector(BaseCollector):
    """DroneBL: estado de IP en listas negras."""

    def __init__(self) -> None:
        super().__init__(name="dronebl")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()
        if not _is_routable_ip(ip):
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "skipped": "IP no pública"}),
                metadata={"ok": False},
            )
        url = f"https://dronebl.org/api/lookup?ip={quote(ip)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "error": str(exc)}),
                metadata={"ok": False},
            )

        listed = bool(data.get("listed", False))
        categories = data.get("categories", [])

        node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"DroneBL: {ip}",
            attributes={
                "listed": listed,
                "categories": categories,
                "source": "dronebl",
            },
            confidence=0.9 if listed else 0.6,
        )

        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=[node],
            relations=[],
            raw_payload=json.dumps(
                {"ip": ip, "listed": listed, "categories": categories}, ensure_ascii=False
            ),
            metadata={"ok": True, "listed": listed},
        )


class AbuseIPDBFreeCollector(BaseCollector):
    """AbuseIPDB: score de abuso 0-100 (requiere key, opcional)."""

    def __init__(self) -> None:
        super().__init__(name="abuseipdb_free")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("abuseipdb_api_key")
        ip = target.strip()
        if key is None:
            return _missing_key_result(self.name, ip, "abuseipdb_api_key")
        if not _is_routable_ip(ip):
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "skipped": "IP no pública"}),
                metadata={"ok": False},
            )
        url = "https://api.abuseipdb.com/api/v2/check"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    url,
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    headers={**_UA, "Key": key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "error": str(exc)}),
                metadata={"ok": False},
            )

        score = int(data.get("abuseConfidenceScore", 0))
        node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"AbuseIPDB: {ip} ({score})",
            attributes={
                "abuse_score": score,
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "source": "abuseipdb",
            },
            confidence=0.85 if score >= 25 else 0.6,
        )
        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=[node],
            relations=[],
            raw_payload=json.dumps({"ip": ip, "abuse_score": score}),
            metadata={"ok": True, "abuse_score": score},
        )

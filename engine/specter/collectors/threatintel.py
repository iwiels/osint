"""
SpecterOSINT - Threat Intel sin API key (Fase A Maltego-gap).

Fuentes gratuitas sin autenticación, las mismas que usan SpiderFoot,
theHarvester y las máquinas de Maltego CE como pivotes iniciales:

- Shodan InternetDB: IP -> puertos/CPE/vulns/hostnames/tags (1 llamada, sin key)
- ThreatFox (abuse.ch): IOC (ip/dominio/hash/url) -> familia malware/confianza
- urlscan.io search: dominio/IP -> URLs observadas, IPs, países (búsqueda pública)
- HackerTarget reverse-IP: IP -> dominios co-hospedados (tier gratuito)
- Wayback CDX: dominio -> historial de URLs (foco en rutas sensibles)

Ninguna requiere key: encajan en el modelo "free primero" del engine. Las que
sí piden key (VirusTotal, Shodan full, GreyNoise, urlscan submit) van en Fase B
detrás de la bóveda (`specter.secrets`).
"""

from __future__ import annotations

import ipaddress
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

logger = logging.getLogger("specter.collectors.threatintel")

_TIMEOUT = 12.0
# ASCII estricto: httpx codifica los headers en ASCII y una tilde tumba el request.
_UA = {"User-Agent": "SpecterOSINT/0.2 (+forense, key en boveda local)"}


def _collector_key(vault_name: str) -> str | None:
    """Key de la bóveda local o su env equivalente. None = no configurada.

    Regla Fase B: sin key el colector se omite (ok=False, requires_key) y el
    agente ni lo intenta: solo se habilita desde la UI de ajustes.
    """
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
    """Las fuentes externas no aportan nada sobre IPs privadas: se omiten."""
    try:
        return ipaddress.ip_address(target.strip()).is_global
    except ValueError:
        return True  # dominios/hashes: los resuelve la API remota


def _threat_confidence(level: Any) -> float:
    mapping = {"high": 0.9, "medium": 0.7, "low": 0.5}
    if isinstance(level, str):
        return mapping.get(level.lower(), 0.6)
    if isinstance(level, (int, float)):
        return max(0.0, min(1.0, float(level) / 100.0))
    return 0.6


class InternetDBCollector(BaseCollector):
    """Shodan InternetDB: huella de exposición de una IP sin API key."""

    def __init__(self):
        super().__init__(name="internetdb")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()
        if not _is_routable_ip(ip):
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "skipped": "IP no pública"}),
                metadata={"ok": False},
            )
        url = f"https://internetdb.shodan.io/{quote(ip)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=ip,
                        raw_payload=json.dumps({"ip": ip, "present": False}),
                        metadata={"ok": True, "present": False},
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        ip_node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"IP: {ip}",
            attributes={
                "ports": data.get("ports", []),
                "cpes": data.get("cpes", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", []),
                "source": "internetdb",
            },
        )
        entities.append(ip_node)
        for host in data.get("hostnames", [])[:20]:
            host_node = EntityNode.create(
                EntityType.DOMAIN, host, f"Host: {host}", attributes={"source": "internetdb"}
            )
            entities.append(host_node)
            relations.append(
                RelationEdge(
                    source_id=host_node.id,
                    target_id=ip_node.id,
                    relation_type=RelationType.RESOLVES_TO,
                )
            )
        for cve in data.get("vulns", [])[:20]:
            cve_node = EntityNode.create(
                EntityType.ALIAS,
                cve,
                f"CVE: {cve}",
                attributes={"source": "internetdb"},
                confidence=0.9,
            )
            entities.append(cve_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=cve_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False),
            metadata={
                "ok": True,
                "ports": len(data.get("ports", [])),
                "vulns": len(data.get("vulns", [])),
            },
        )


class ThreatFoxCollector(BaseCollector):
    """Abuse.ch ThreatFox: ¿este IOC es infraestructura maliciosa conocida?"""

    def __init__(self):
        super().__init__(name="threatfox")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ioc = target.strip()
        url = "https://threatfox-api.abuse.ch/api/v1/"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    url, json={"query": "search_ioc", "search_term": ioc}, headers=_UA
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ioc,
                raw_payload=json.dumps({"ioc": ioc, "error": str(exc)}),
                metadata={"ok": False},
            )
        if data.get("query_status") != "ok" or not data.get("data"):
            return CollectorResult(
                collector_name=self.name,
                source_target=ioc,
                raw_payload=json.dumps(
                    {"ioc": ioc, "query_status": data.get("query_status", "no_result")}
                ),
                metadata={"ok": True, "malicious": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        ioc_node = EntityNode.create(
            EntityType.ALIAS, ioc, f"IOC: {ioc}", attributes={"source": "threatfox"}
        )
        entities.append(ioc_node)
        for row in data["data"][:10]:
            malware = str(row.get("malware", "unknown"))
            conf = _threat_confidence(row.get("confidence_level"))
            fam = EntityNode.create(
                EntityType.ALIAS,
                malware,
                f"Malware: {malware}",
                attributes={
                    "threat_type": row.get("threat_type"),
                    "reporter": row.get("reporter"),
                    "first_seen": row.get("first_seen"),
                    "source": "threatfox",
                },
                confidence=conf,
            )
            entities.append(fam)
            relations.append(
                RelationEdge(
                    source_id=ioc_node.id,
                    target_id=fam.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=ioc,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False),
            metadata={"ok": True, "malicious": True, "matches": len(data["data"])},
        )


class UrlscanCollector(BaseCollector):
    """urlscan.io search público: URLs/IPs observadas para un dominio o IP."""

    def __init__(self):
        super().__init__(name="urlscan")

    async def collect(self, target: str, size: int = 20, **kwargs: Any) -> CollectorResult:
        query = target.strip()
        size = max(1, min(int(size), 100))
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(query)}&size={size}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=query,
                raw_payload=json.dumps({"query": query, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN, query, f"Dominio: {query}", attributes={"source": "urlscan"}
        )
        entities.append(root)
        seen_ips: set[str] = set()
        for item in data.get("results", [])[:size]:
            page = item.get("page", {})
            page_url = str(page.get("url", ""))[:300]
            page_ip = str(page.get("ip", ""))
            if page_url:
                url_node = EntityNode.create(
                    EntityType.ALIAS,
                    page_url,
                    f"URL: {page_url[:80]}",
                    attributes={
                        "country": page.get("country"),
                        "source": "urlscan",
                    },
                    confidence=0.8,
                )
                entities.append(url_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=url_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            if page_ip and page_ip not in seen_ips:
                seen_ips.add(page_ip)
                ip_node = EntityNode.create(
                    EntityType.IP_ADDRESS,
                    page_ip,
                    f"IP: {page_ip}",
                    attributes={"country": page.get("country"), "source": "urlscan"},
                    confidence=0.8,
                )
                entities.append(ip_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=ip_node.id,
                        relation_type=RelationType.RESOLVES_TO,
                    )
                )
        return CollectorResult(
            collector_name=self.name,
            source_target=query,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"query": query, "total": data.get("total", 0)}, ensure_ascii=False
            ),
            metadata={"ok": True, "observed_urls": len(entities) - 1 - len(seen_ips)},
        )


class HackertargetCollector(BaseCollector):
    """HackerTarget reverse-IP gratuito: dominios co-hospedados (pivote clásico)."""

    def __init__(self):
        super().__init__(name="hackertarget_reverse")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()
        if not _is_routable_ip(ip):
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "skipped": "IP no pública"}),
                metadata={"ok": False},
            )
        url = f"https://api.hackertarget.com/reverseiplookup/?q={quote(ip)}"
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
        if "error" in text.lower() or "no records" in text.lower():
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "note": text[:200]}),
                metadata={"ok": True, "cohosted": 0},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        ip_node = EntityNode.create(
            EntityType.IP_ADDRESS, ip, f"IP: {ip}", attributes={"source": "hackertarget"}
        )
        entities.append(ip_node)
        count = 0
        for line in text.splitlines():
            host = line.strip().lower()
            if not host or " " in host or "." not in host:
                continue
            host_node = EntityNode.create(
                EntityType.DOMAIN,
                host,
                f"Co-hospedado: {host}",
                attributes={"source": "hackertarget"},
                confidence=0.8,
            )
            entities.append(host_node)
            relations.append(
                RelationEdge(
                    source_id=host_node.id,
                    target_id=ip_node.id,
                    relation_type=RelationType.RESOLVES_TO,
                )
            )
            count += 1
            if count >= 100:
                break
        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"ip": ip, "cohosted": count}, ensure_ascii=False),
            metadata={"ok": True, "cohosted": count},
        )


class WaybackCollector(BaseCollector):
    """Wayback CDX: historial de URLs de un dominio (foco en rutas sensibles)."""

    _SENSITIVE = (
        "admin",
        "backup",
        "bak",
        ".zip",
        ".sql",
        ".env",
        ".git",
        "wp-",
        "phpmyadmin",
        "login",
        "config",
        "test",
        "dev",
        "staging",
    )

    def __init__(self):
        super().__init__(name="wayback")

    async def collect(self, target: str, limit: int = 200, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        limit = max(10, min(int(limit), 1000))
        url = (
            "http://web.archive.org/cdx/search/cdx"
            f"?url={quote(domain)}/*&output=json&fl=timestamp,original,statuscode,mimetype"
            f"&collapse=urlkey&limit={limit}"
        )
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                rows = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )
        if not isinstance(rows, list) or len(rows) < 2:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "snapshots": 0}),
                metadata={"ok": True, "snapshots": 0},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN, domain, f"Dominio: {domain}", attributes={"source": "wayback"}
        )
        entities.append(root)
        stamps: list[str] = []
        interesting = 0
        for row in rows[1:]:
            if not isinstance(row, list) or len(row) < 2:
                continue
            stamp, original = str(row[0]), str(row[1])[:300]
            stamps.append(stamp)
            lowered = original.lower()
            if any(sig in lowered for sig in self._SENSITIVE):
                interesting += 1
                if interesting > 30:
                    continue
                url_node = EntityNode.create(
                    EntityType.ALIAS,
                    original,
                    f"Histórica: {original[:80]}",
                    attributes={"first_seen_wayback": stamp, "source": "wayback"},
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
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "snapshots": len(stamps),
                    "first": min(stamps) if stamps else None,
                    "last": max(stamps) if stamps else None,
                },
                ensure_ascii=False,
            ),
            metadata={
                "ok": True,
                "snapshots": len(stamps),
                "interesting_urls": interesting,
            },
        )


# ---------------------------------------------------------------------------
# Fase B: fuentes con API key (bóveda local o env). Sin key se omiten.
# ---------------------------------------------------------------------------


class VirusTotalCollector(BaseCollector):
    """VirusTotal v3: reputación de IP/dominio/hash (tier free: 4 req/min)."""

    def __init__(self):
        super().__init__(name="virustotal")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("virustotal_api_key")
        value = target.strip()
        if key is None:
            return _missing_key_result(self.name, value, "virustotal_api_key")
        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            endpoint = f"files/{value}"
        elif _is_routable_ip(value) and re.fullmatch(r"[0-9a-fA-F:.]+", value):
            try:
                ipaddress.ip_address(value)
                endpoint = f"ip_addresses/{value}"
            except ValueError:
                endpoint = f"domains/{value}"
        else:
            endpoint = f"domains/{value}"
        headers = {**_UA, "x-apikey": key}
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/{endpoint}", headers=headers
                )
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=value,
                        raw_payload=json.dumps({"target": value, "present": False}),
                        metadata={"ok": True, "present": False},
                    )
                resp.raise_for_status()
                attrs = resp.json().get("data", {}).get("attributes", {})
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"target": value, "error": str(exc)}),
                metadata={"ok": False},
            )

        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        node = EntityNode.create(
            EntityType.ALIAS,
            value,
            f"VT: {value}",
            attributes={
                "reputation": attrs.get("reputation"),
                "malicious": malicious,
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "categories": attrs.get("categories", {}),
                "source": "virustotal",
            },
            confidence=0.9 if malicious else 0.7,
        )
        entities.append(node)
        for host in (attrs.get("resolutions") or [])[:10]:
            host_name = host.get("hostname") if isinstance(host, dict) else None
            if not host_name:
                continue
            host_node = EntityNode.create(
                EntityType.DOMAIN,
                host_name,
                f"Resuelve: {host_name}",
                attributes={"source": "virustotal"},
                confidence=0.8,
            )
            entities.append(host_node)
            relations.append(
                RelationEdge(
                    source_id=node.id,
                    target_id=host_node.id,
                    relation_type=RelationType.RESOLVES_TO,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=value,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"target": value, "stats": stats, "reputation": attrs.get("reputation")},
                ensure_ascii=False,
            ),
            metadata={"ok": True, "malicious": malicious},
        )


class ShodanCollector(BaseCollector):
    """Shodan API: host completo + búsqueda por favicon hash (Fase A→B)."""

    def __init__(self):
        super().__init__(name="shodan")

    async def collect(
        self, target: str, favicon_hash: int | None = None, **kwargs: Any
    ) -> CollectorResult:
        key = _collector_key("shodan_api_key")
        value = target.strip()
        if key is None:
            return _missing_key_result(self.name, value, "shodan_api_key")
        params: dict[str, Any] = {"key": key}
        if favicon_hash is not None:
            url = "https://api.shodan.io/shodan/host/search"
            params["query"] = f"http.favicon.hash:{int(favicon_hash)}"
        else:
            url = f"https://api.shodan.io/shodan/host/{quote(value)}"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, params=params, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=value,
                        raw_payload=json.dumps({"target": value, "present": False}),
                        metadata={"ok": True, "present": False},
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"target": value, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        if favicon_hash is not None:
            for match in data.get("matches", [])[:20]:
                ip = str(match.get("ip_str", ""))
                if not ip:
                    continue
                ip_node = EntityNode.create(
                    EntityType.IP_ADDRESS,
                    ip,
                    f"Mismo favicon: {ip}",
                    attributes={"source": "shodan", "favicon_mmh3": int(favicon_hash)},
                    confidence=0.75,
                )
                entities.append(ip_node)
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                entities=entities,
                relations=relations,
                raw_payload=json.dumps(
                    {"favicon_mmh3": favicon_hash, "total": data.get("total", 0)}
                ),
                metadata={"ok": True, "matches": len(entities)},
            )
        node = EntityNode.create(
            EntityType.IP_ADDRESS,
            value,
            f"Shodan: {value}",
            attributes={
                "ports": data.get("ports", []),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "os": data.get("os"),
                "country": data.get("country_name"),
                "vulns": list((data.get("vulns") or {}).keys())[:20],
                "source": "shodan",
            },
        )
        entities.append(node)
        for host in data.get("hostnames", [])[:20]:
            host_node = EntityNode.create(
                EntityType.DOMAIN, host, f"Host: {host}", attributes={"source": "shodan"}
            )
            entities.append(host_node)
            relations.append(
                RelationEdge(
                    source_id=host_node.id,
                    target_id=node.id,
                    relation_type=RelationType.RESOLVES_TO,
                )
            )
        return CollectorResult(
            collector_name=self.name,
            source_target=value,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"target": value, "ports": data.get("ports", []), "org": data.get("org")}
            ),
            metadata={"ok": True, "ports": len(data.get("ports", []))},
        )


class GreyNoiseCollector(BaseCollector):
    """GreyNoise Community: ¿esta IP es ruido masivo (RIOT) o escaneo?"""

    def __init__(self):
        super().__init__(name="greynoise")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("greynoise_api_key")
        ip = target.strip()
        if key is None:
            return _missing_key_result(self.name, ip, "greynoise_api_key")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"https://api.greynoise.io/v3/community/{quote(ip)}",
                    headers={**_UA, "key": key},
                )
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=ip,
                        raw_payload=json.dumps({"ip": ip, "noise": False}),
                        metadata={"ok": True, "noise": False},
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "error": str(exc)}),
                metadata={"ok": False},
            )
        node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"GreyNoise: {ip}",
            attributes={
                "noise": data.get("noise"),
                "riot": data.get("riot"),
                "classification": data.get("classification"),
                "name": data.get("name"),
                "link": data.get("link"),
                "last_seen": data.get("last_seen"),
                "source": "greynoise",
            },
            confidence=0.85,
        )
        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=[node],
            relations=[],
            raw_payload=json.dumps(
                {
                    "ip": ip,
                    "noise": data.get("noise"),
                    "classification": data.get("classification"),
                }
            ),
            metadata={"ok": True, "noise": bool(data.get("noise"))},
        )


class AbuseIPDBCollector(BaseCollector):
    """AbuseIPDB: score de abuso 0-100 + reportes (tier free con key)."""

    def __init__(self):
        super().__init__(name="abuseipdb")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("abuseipdb_api_key")
        ip = target.strip()
        if key is None:
            return _missing_key_result(self.name, ip, "abuseipdb_api_key")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
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


class HunterCollector(BaseCollector):
    """Hunter.io: verificación de email + búsqueda de emails por dominio."""

    def __init__(self):
        super().__init__(name="hunter")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("hunter_api_key")
        value = target.strip()
        if key is None:
            return _missing_key_result(self.name, value, "hunter_api_key")
        is_email = "@" in value
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                if is_email:
                    resp = await client.get(
                        "https://api.hunter.io/v2/email-verifier",
                        params={"email": value, "api_key": key},
                        headers=_UA,
                    )
                    resp.raise_for_status()
                    data = resp.json().get("data", {})
                else:
                    resp = await client.get(
                        "https://api.hunter.io/v2/domain-search",
                        params={"domain": value, "api_key": key, "limit": 10},
                        headers=_UA,
                    )
                    resp.raise_for_status()
                    data = resp.json().get("data", {})
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"target": value, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        if is_email:
            node = EntityNode.create(
                EntityType.EMAIL,
                value,
                f"Hunter: {value}",
                attributes={
                    "status": data.get("status"),
                    "score": data.get("score"),
                    "regexp": data.get("regexp"),
                    "gibberish": data.get("gibberish"),
                    "sources": len(data.get("sources", [])),
                    "source": "hunter",
                },
                confidence=0.85 if data.get("status") == "valid" else 0.6,
            )
            entities.append(node)
            meta: dict[str, Any] = {"ok": True, "status": data.get("status")}
        else:
            root = EntityNode.create(
                EntityType.DOMAIN, value, f"Hunter: {value}", attributes={"source": "hunter"}
            )
            entities.append(root)
            for item in data.get("emails", [])[:10]:
                email_value = str(item.get("value", ""))
                if not email_value:
                    continue
                email_node = EntityNode.create(
                    EntityType.EMAIL,
                    email_value,
                    f"{item.get('first_name', '')} {item.get('last_name', '')} ({item.get('position', '')})".strip(),
                    attributes={
                        "first_name": item.get("first_name"),
                        "last_name": item.get("last_name"),
                        "position": item.get("position"),
                        "confidence_hunter": item.get("confidence"),
                        "source": "hunter",
                    },
                    confidence=0.8,
                )
                entities.append(email_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=email_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            meta = {"ok": True, "emails": len(entities) - 1}
        return CollectorResult(
            collector_name=self.name,
            source_target=value,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"target": value, "data": data}, ensure_ascii=False)[:4000],
            metadata=meta,
        )

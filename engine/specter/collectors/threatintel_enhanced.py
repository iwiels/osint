"""
WraithOSINT - Threat Intelligence Enhanced Collectors
Colectores avanzados con soporte para degradación elegante y calificación OTAN (Almirantazgo):
- ShodanCollector (API completa o fallback automático a Shodan InternetDB sin key)
- CensysCollector (Inspección de hosts, servicios y certificados SSL/TLS)
- VirusTotalCollector (Reputación de seguridad para IPs, dominios y archivos)
- HaveIBeenPwnedCollector (Verificación de exposición en brechas de datos conocidas)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from typing import Any
from urllib.parse import quote

import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.admiralty import assess_evidence, rate_source
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.threatintel_enhanced")

_TIMEOUT = 12.0
_UA = {"User-Agent": "WraithOSINT/0.3 (+threatintel-enhanced)"}


def _collector_key(vault_name: str) -> str | None:
    """Obtiene la clave desde os.environ o desde la bóveda local de secretos."""
    from specter import secrets as vault

    env_var = vault.ALLOWED_SECRETS.get(vault_name, "")
    val = (os.environ.get(env_var) if env_var else None) or vault.get_secret(vault_name)
    if val and str(val).strip():
        return str(val).strip()
    return None


def _missing_key_result(name: str, target: str, key_name: str) -> CollectorResult:
    """Degradación elegante limpia ante clave faltante sin lanzar excepciones."""
    return CollectorResult(
        collector_name=name,
        source_target=target,
        raw_payload=json.dumps({"target": target, "skipped": f"requiere {key_name}"}),
        metadata={
            "ok": False,
            "requires_key": key_name,
            "admiralty": rate_source(name),
        },
    )


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def _is_routable_ip(target: str) -> bool:
    """Verifica si es una dirección IP globalmente enrutable."""
    try:
        return ipaddress.ip_address(target.strip()).is_global
    except ValueError:
        return True


class ShodanCollector(BaseCollector):
    """
    Shodan Collector con degradación elegante de 2 niveles:
    1. Si existe SHODAN_API_KEY: consulta el host completo o favicon hash vía API REST oficial.
    2. Si NO existe key: degrada automáticamente a la API pública y gratuita de Shodan
       (InternetDB: https://internetdb.shodan.io/{ip}) sin requerir credenciales ni fallar.
    Genera nodos (IP_ADDRESS, ASN, GEO_LOCATION, CVE, PORT, DOMAIN) y aristas
    (HOSTED_ON, LOCATED_IN, VULNERABLE_TO, RUNS_PORT, RESOLVES_TO).
    """

    def __init__(self, name: str = "shodan"):
        super().__init__(name=name)

    async def collect(
        self, target: str, favicon_hash: int | None = None, **kwargs: Any
    ) -> CollectorResult:
        value = target.strip()
        key = _collector_key("shodan_api_key")

        # Chequeo de IP privada / no enrutable
        if _is_ip(value) and not _is_routable_ip(value):
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"ip": value, "skipped": "IP no pública"}),
                metadata={
                    "ok": False,
                    "skipped": "IP no pública",
                    "admiralty": rate_source(self.name),
                },
            )

        # Si hay clave configurada: ejecución vía Shodan API completa
        if key is not None:
            return await self._collect_keyed(value, key=key, favicon_hash=favicon_hash)

        # Si NO hay clave: fallback / degradación elegante a Shodan InternetDB
        return await self._collect_internetdb_fallback(value)

    async def _collect_keyed(
        self, value: str, key: str, favicon_hash: int | None = None
    ) -> CollectorResult:
        params: dict[str, Any] = {"key": key}
        if favicon_hash is not None:
            url = "https://api.shodan.io/shodan/host/search"
            params["query"] = f"http.favicon.hash:{int(favicon_hash)}"
        else:
            url = f"https://api.shodan.io/shodan/host/{quote(value)}"

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, params=params, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=value,
                        raw_payload=json.dumps({"target": value, "present": False}),
                        metadata={
                            "ok": True,
                            "present": False,
                            "admiralty": rate_source(self.name),
                        },
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("Shodan API request failed for %s: %s", value, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"target": value, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc), "admiralty": rate_source(self.name)},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        if favicon_hash is not None:
            for match in data.get("matches", [])[:30]:
                ip_str = str(match.get("ip_str", "")).strip()
                if not ip_str:
                    continue
                ip_match_node = EntityNode.create(
                    EntityType.IP_ADDRESS,
                    ip_str,
                    f"Favicon Match: {ip_str}",
                    attributes={"source": "shodan", "favicon_mmh3": int(favicon_hash)},
                    confidence=0.8,
                )
                entities.append(ip_match_node)
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                entities=entities,
                relations=relations,
                raw_payload=json.dumps(
                    {"favicon_mmh3": favicon_hash, "total": data.get("total", 0)},
                    ensure_ascii=False,
                ),
                metadata={
                    "ok": True,
                    "matches": len(entities),
                    "api_key_used": True,
                    "admiralty": rate_source(self.name),
                    "admiralty_grade": assess_evidence(
                        self.name, confidence=0.8, entity_type="IP_ADDRESS"
                    ).grade,
                },
            )

        # Extracción completa de host
        ip = str(data.get("ip_str", value)).strip()
        ports = data.get("ports", [])
        org = data.get("org")
        isp = data.get("isp")
        os_info = data.get("os")
        country = data.get("country_name")
        country_code = data.get("country_code")
        city = data.get("city")
        lat = data.get("latitude")
        lon = data.get("longitude")
        asn_val = data.get("asn")

        # Vulns puede venir como dict o como lista
        vulns_raw = data.get("vulns", [])
        if isinstance(vulns_raw, dict):
            vulns = list(vulns_raw.keys())
        elif isinstance(vulns_raw, list):
            vulns = [str(v) for v in vulns_raw]
        else:
            vulns = []

        # Extraer servicios y banners por puerto
        service_banners: dict[int, dict[str, Any]] = {}
        for item in data.get("data", []):
            p = item.get("port")
            if p is not None:
                service_banners[p] = {
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "transport": item.get("transport", "tcp"),
                    "banner": str(item.get("data", ""))[:200],
                }

        # 1. Nodo principal de la dirección IP
        ip_node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"IP: {ip}",
            attributes={
                "ports": ports,
                "org": org,
                "isp": isp,
                "os": os_info,
                "country": country,
                "city": city,
                "vulns": vulns[:50],
                "source": "shodan",
                "tier": "api",
            },
            confidence=0.9,
        )
        entities.append(ip_node)

        # 2. Nodo ASN y arista HOSTED_ON
        if asn_val:
            asn_str = str(asn_val).strip()
            if not asn_str.upper().startswith("AS"):
                asn_str = f"AS{asn_str}"
            asn_node = EntityNode.create(
                EntityType.ASN,
                asn_str,
                f"ASN: {asn_str}",
                attributes={"org": org, "source": "shodan"},
                confidence=0.9,
            )
            entities.append(asn_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=asn_node.id,
                    relation_type=RelationType.HOSTED_ON,
                )
            )

        # 3. Nodo GEO_LOCATION y arista LOCATED_IN
        if lat is not None and lon is not None:
            geo_val = f"{lat},{lon}"
            geo_label = f"Geo: {city}, {country}" if (city or country) else f"Geo: {geo_val}"
            geo_node = EntityNode.create(
                EntityType.GEO_LOCATION,
                geo_val,
                geo_label,
                attributes={
                    "latitude": lat,
                    "longitude": lon,
                    "city": city,
                    "country": country,
                    "country_code": country_code,
                    "source": "shodan",
                },
                confidence=0.85,
            )
            entities.append(geo_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=geo_node.id,
                    relation_type=RelationType.LOCATED_IN,
                )
            )
        elif city or country:
            geo_val = f"{city or ''},{country or ''}".strip(",")
            geo_node = EntityNode.create(
                EntityType.GEO_LOCATION,
                geo_val,
                f"Geo: {geo_val}",
                attributes={"city": city, "country": country, "source": "shodan"},
                confidence=0.75,
            )
            entities.append(geo_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=geo_node.id,
                    relation_type=RelationType.LOCATED_IN,
                )
            )

        # 4. Nodos CVE y aristas VULNERABLE_TO
        for cve in vulns[:50]:
            cve_str = str(cve).strip().upper()
            cve_node = EntityNode.create(
                EntityType.CVE,
                cve_str,
                f"CVE: {cve_str}",
                attributes={"source": "shodan"},
                confidence=0.9,
            )
            entities.append(cve_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=cve_node.id,
                    relation_type=RelationType.VULNERABLE_TO,
                )
            )

        # 5. Nodos PORT y aristas RUNS_PORT
        for port in ports[:50]:
            p_meta = service_banners.get(port, {})
            port_val = f"{ip}:{port}"
            port_label = (
                f"Port {port} ({p_meta['product']})" if p_meta.get("product") else f"Port: {port}"
            )
            port_node = EntityNode.create(
                EntityType.PORT,
                port_val,
                port_label,
                attributes={
                    "port": port,
                    "transport": p_meta.get("transport", "tcp"),
                    "product": p_meta.get("product"),
                    "version": p_meta.get("version"),
                    "banner": p_meta.get("banner"),
                    "source": "shodan",
                },
                confidence=0.9,
            )
            entities.append(port_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=port_node.id,
                    relation_type=RelationType.RUNS_PORT,
                )
            )

        # 6. Nodos DOMAIN y aristas RESOLVES_TO
        for host in data.get("hostnames", [])[:30]:
            host_str = str(host).strip().lower()
            if not host_str:
                continue
            host_node = EntityNode.create(
                EntityType.DOMAIN,
                host_str,
                f"Host: {host_str}",
                attributes={"source": "shodan"},
                confidence=0.85,
            )
            entities.append(host_node)
            relations.append(
                RelationEdge(
                    source_id=host_node.id,
                    target_id=ip_node.id,
                    relation_type=RelationType.RESOLVES_TO,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=value,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False),
            metadata={
                "ok": True,
                "api_key_used": True,
                "degraded": False,
                "ports": len(ports),
                "vulns": len(vulns),
                "admiralty": rate_source(self.name),
                "admiralty_grade": assess_evidence(
                    self.name, confidence=0.9, entity_type="IP_ADDRESS"
                ).grade,
            },
        )

    async def _collect_internetdb_fallback(self, value: str) -> CollectorResult:
        """Degradación a Shodan InternetDB (público, sin key)."""
        url = f"https://internetdb.shodan.io/{quote(value)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=value,
                        raw_payload=json.dumps({"ip": value, "present": False}),
                        metadata={
                            "ok": True,
                            "present": False,
                            "degraded": True,
                            "source": "internetdb",
                            "admiralty": rate_source(self.name),
                        },
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("InternetDB fallback request failed for %s: %s", value, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"ip": value, "error": str(exc)}),
                metadata={
                    "ok": False,
                    "degraded": True,
                    "error": str(exc),
                    "admiralty": rate_source(self.name),
                },
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        ip = str(data.get("ip", value)).strip()
        ports = data.get("ports", [])
        cpes = data.get("cpes", [])
        vulns = data.get("vulns", [])
        tags = data.get("tags", [])
        hostnames = data.get("hostnames", [])

        # 1. IP Node
        ip_node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"IP: {ip}",
            attributes={
                "ports": ports,
                "cpes": cpes,
                "vulns": vulns,
                "tags": tags,
                "source": "internetdb",
                "tier": "free",
            },
            confidence=0.85,
        )
        entities.append(ip_node)

        # 2. CVE Nodes y aristas VULNERABLE_TO
        for cve in vulns[:30]:
            cve_str = str(cve).strip().upper()
            cve_node = EntityNode.create(
                EntityType.CVE,
                cve_str,
                f"CVE: {cve_str}",
                attributes={"source": "internetdb"},
                confidence=0.85,
            )
            entities.append(cve_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=cve_node.id,
                    relation_type=RelationType.VULNERABLE_TO,
                )
            )

        # 3. PORT Nodes y aristas RUNS_PORT
        for port in ports[:50]:
            port_node = EntityNode.create(
                EntityType.PORT,
                f"{ip}:{port}",
                f"Port: {port}",
                attributes={"port": port, "source": "internetdb"},
                confidence=0.85,
            )
            entities.append(port_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=port_node.id,
                    relation_type=RelationType.RUNS_PORT,
                )
            )

        # 4. DOMAIN Nodes y aristas RESOLVES_TO
        for host in hostnames[:30]:
            host_str = str(host).strip().lower()
            if not host_str:
                continue
            host_node = EntityNode.create(
                EntityType.DOMAIN,
                host_str,
                f"Host: {host_str}",
                attributes={"source": "internetdb"},
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

        return CollectorResult(
            collector_name=self.name,
            source_target=value,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False),
            metadata={
                "ok": True,
                "api_key_used": False,
                "degraded": True,
                "source": "internetdb",
                "ports": len(ports),
                "vulns": len(vulns),
                "admiralty": rate_source(self.name),
                "admiralty_grade": assess_evidence(
                    self.name, confidence=0.85, entity_type="IP_ADDRESS"
                ).grade,
            },
        )


class CensysCollector(BaseCollector):
    """
    Censys Collector v2 con degradación elegante ante ausencia de credenciales.
    Requiere CENSYS_API_ID y CENSYS_API_SECRET.
    Consulta información de host y certificados TLS/SSL, extrayendo huellas SHA256,
    emisores, vigencias y nombres de dominio asociados.
    Genera nodos (SSL_CERTIFICATE, DOMAIN, IP_ADDRESS) y aristas (ASSOCIATED_WITH, RESOLVES_TO).
    """

    def __init__(self, name: str = "censys"):
        super().__init__(name=name)

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        value = target.strip()
        api_id = _collector_key("censys_api_id")
        api_secret = _collector_key("censys_api_secret")

        if not api_id or not api_secret:
            return _missing_key_result(self.name, value, "censys_api_id / censys_api_secret")

        auth = httpx.BasicAuth(api_id, api_secret)
        is_ip_target = _is_ip(value)

        if is_ip_target:
            url = f"https://search.censys.io/api/v2/hosts/{quote(value)}"
        else:
            url = f"https://search.censys.io/api/v2/certificates/search?q={quote(value)}"

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, auth=auth, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=value,
                        raw_payload=json.dumps({"target": value, "present": False}),
                        metadata={
                            "ok": True,
                            "present": False,
                            "admiralty": rate_source(self.name),
                        },
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("Censys API request failed for %s: %s", value, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"target": value, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc), "admiralty": rate_source(self.name)},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        if is_ip_target:
            result = data.get("result", {})
            ip = str(result.get("ip", value)).strip()
            services = result.get("services", [])
            asn_info = result.get("autonomous_system", {})
            loc_info = result.get("location", {})

            # 1. IP Node
            ip_node = EntityNode.create(
                EntityType.IP_ADDRESS,
                ip,
                f"IP: {ip}",
                attributes={
                    "services_count": len(services),
                    "asn": asn_info.get("asn"),
                    "as_name": asn_info.get("name"),
                    "country": loc_info.get("country"),
                    "city": loc_info.get("city"),
                    "source": "censys",
                },
                confidence=0.9,
            )
            entities.append(ip_node)

            # ASN si está presente
            asn_num = asn_info.get("asn")
            if asn_num:
                asn_node = EntityNode.create(
                    EntityType.ASN,
                    f"AS{asn_num}",
                    f"ASN: AS{asn_num}",
                    attributes={"name": asn_info.get("name"), "source": "censys"},
                    confidence=0.9,
                )
                entities.append(asn_node)
                relations.append(
                    RelationEdge(
                        source_id=ip_node.id,
                        target_id=asn_node.id,
                        relation_type=RelationType.HOSTED_ON,
                    )
                )

            # Extraer certificados de los servicios TLS
            for s in services:
                port = s.get("port")
                tls_data = s.get("tls", {})
                certs_data = tls_data.get("certificates", {})
                leaf = certs_data.get("leaf_data", {})
                sha256 = (
                    leaf.get("fingerprint_sha256")
                    or s.get("certificate_sha256")
                    or s.get("certificate")
                )

                if sha256 and isinstance(sha256, str):
                    issuer = leaf.get("issuer", {})
                    validity = leaf.get("validity", {})
                    names = leaf.get("names", [])

                    cert_node = EntityNode.create(
                        EntityType.SSL_CERTIFICATE,
                        sha256,
                        f"Cert: {sha256[:16]}...",
                        attributes={
                            "fingerprint_sha256": sha256,
                            "port": port,
                            "issuer": issuer,
                            "validity": validity,
                            "names": names,
                            "source": "censys",
                        },
                        confidence=0.9,
                    )
                    entities.append(cert_node)
                    relations.append(
                        RelationEdge(
                            source_id=ip_node.id,
                            target_id=cert_node.id,
                            relation_type=RelationType.ASSOCIATED_WITH,
                        )
                    )

                    # Dominios asociados al certificado
                    for dname in names[:20]:
                        dname_clean = str(dname).strip().lower()
                        if not dname_clean:
                            continue
                        domain_node = EntityNode.create(
                            EntityType.DOMAIN,
                            dname_clean,
                            f"Domain: {dname_clean}",
                            attributes={"source": "censys"},
                            confidence=0.85,
                        )
                        entities.append(domain_node)
                        relations.append(
                            RelationEdge(
                                source_id=cert_node.id,
                                target_id=domain_node.id,
                                relation_type=RelationType.ASSOCIATED_WITH,
                            )
                        )
                        relations.append(
                            RelationEdge(
                                source_id=domain_node.id,
                                target_id=ip_node.id,
                                relation_type=RelationType.RESOLVES_TO,
                            )
                        )

            meta = {
                "ok": True,
                "services": len(services),
                "admiralty": rate_source(self.name),
                "admiralty_grade": assess_evidence(
                    self.name, confidence=0.9, entity_type="IP_ADDRESS"
                ).grade,
            }
        else:
            # Búsqueda por certificado o dominio
            hits = data.get("result", {}).get("hits", [])
            domain_node = EntityNode.create(
                EntityType.DOMAIN,
                value,
                f"Domain: {value}",
                attributes={"source": "censys"},
                confidence=0.9,
            )
            entities.append(domain_node)

            for hit in hits[:15]:
                sha256 = hit.get("fingerprint_sha256")
                if not sha256:
                    continue
                cert_node = EntityNode.create(
                    EntityType.SSL_CERTIFICATE,
                    sha256,
                    f"Cert: {sha256[:16]}...",
                    attributes={
                        "fingerprint_sha256": sha256,
                        "issuer_dn": hit.get("issuer_dn"),
                        "validity": hit.get("validity", {}),
                        "names": hit.get("names", []),
                        "source": "censys",
                    },
                    confidence=0.9,
                )
                entities.append(cert_node)
                relations.append(
                    RelationEdge(
                        source_id=cert_node.id,
                        target_id=domain_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )

            meta = {
                "ok": True,
                "hits": len(hits),
                "admiralty": rate_source(self.name),
                "admiralty_grade": assess_evidence(
                    self.name, confidence=0.9, entity_type="DOMAIN"
                ).grade,
            }

        return CollectorResult(
            collector_name=self.name,
            source_target=value,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False)[:6000],
            metadata=meta,
        )


class VirusTotalCollector(BaseCollector):
    """
    VirusTotal v3 Collector con degradación elegante.
    Requiere VIRUSTOTAL_API_KEY.
    Evalúa la reputación de seguridad de una dirección IP, dominio o hash de archivo.
    Agrega atributos de votos maliciosos, sospechosos y categorías de detección.
    """

    def __init__(self, name: str = "virustotal"):
        super().__init__(name=name)

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("virustotal_api_key")
        value = target.strip()

        if key is None:
            return _missing_key_result(self.name, value, "virustotal_api_key")

        if re.fullmatch(r"[0-9a-fA-F]{64}", value):
            endpoint = f"files/{value}"
            entity_type = EntityType.FILE_ARTIFACT
        elif _is_ip(value):
            endpoint = f"ip_addresses/{value}"
            entity_type = EntityType.IP_ADDRESS
        else:
            endpoint = f"domains/{value}"
            entity_type = EntityType.DOMAIN

        headers = {**_UA, "x-apikey": key}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/{endpoint}", headers=headers
                )
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=value,
                        raw_payload=json.dumps({"target": value, "present": False}),
                        metadata={
                            "ok": True,
                            "present": False,
                            "admiralty": rate_source(self.name),
                        },
                    )
                resp.raise_for_status()
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
        except Exception as exc:
            logger.warning("VirusTotal API request failed for %s: %s", value, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=value,
                raw_payload=json.dumps({"target": value, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc), "admiralty": rate_source(self.name)},
            )

        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        reputation = attrs.get("reputation", 0)
        categories = attrs.get("categories", {})

        confidence = 0.9 if malicious > 0 else 0.75
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        root_node = EntityNode.create(
            entity_type,
            value,
            f"VT: {value}",
            attributes={
                "reputation": reputation,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "categories": categories,
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
                "source": "virustotal",
            },
            confidence=confidence,
        )
        entities.append(root_node)

        # Resoluciones observadas (IPs <-> Dominios)
        for host in (attrs.get("resolutions") or [])[:15]:
            if not isinstance(host, dict):
                continue
            host_name = host.get("hostname")
            ip_address = host.get("ip_address")

            if host_name and entity_type == EntityType.IP_ADDRESS:
                host_node = EntityNode.create(
                    EntityType.DOMAIN,
                    str(host_name),
                    f"Resuelve: {host_name}",
                    attributes={"source": "virustotal"},
                    confidence=0.8,
                )
                entities.append(host_node)
                relations.append(
                    RelationEdge(
                        source_id=host_node.id,
                        target_id=root_node.id,
                        relation_type=RelationType.RESOLVES_TO,
                    )
                )
            elif ip_address and entity_type == EntityType.DOMAIN:
                ip_node = EntityNode.create(
                    EntityType.IP_ADDRESS,
                    str(ip_address),
                    f"Resuelve a: {ip_address}",
                    attributes={"source": "virustotal"},
                    confidence=0.8,
                )
                entities.append(ip_node)
                relations.append(
                    RelationEdge(
                        source_id=root_node.id,
                        target_id=ip_node.id,
                        relation_type=RelationType.RESOLVES_TO,
                    )
                )

        return CollectorResult(
            collector_name=self.name,
            source_target=value,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"target": value, "stats": stats, "reputation": reputation},
                ensure_ascii=False,
            ),
            metadata={
                "ok": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "reputation": reputation,
                "admiralty": rate_source(self.name),
                "admiralty_grade": assess_evidence(
                    self.name, confidence=confidence, entity_type=entity_type.value
                ).grade,
            },
        )


class HaveIBeenPwnedCollector(BaseCollector):
    """
    HaveIBeenPwned Collector (v3 API) con degradación elegante.
    Requiere HIBP_API_KEY.
    Verifica si una cuenta de correo electrónico ha sido expuesta en filtraciones de datos conocidas.
    Genera nodos (EMAIL, BREACH) y aristas (EXPOSED_IN).
    """

    def __init__(self, name: str = "haveibeenpwned"):
        super().__init__(name=name)

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        email = target.strip().lower()

        if "@" not in email:
            return CollectorResult(
                collector_name=self.name,
                source_target=email,
                raw_payload=json.dumps({"target": email, "skipped": "Formato de email inválido"}),
                metadata={
                    "ok": False,
                    "error": "target debe ser una direccion de email válida",
                    "admiralty": rate_source(self.name),
                },
            )

        key = _collector_key("hibp_api_key")
        if key is None:
            return _missing_key_result(self.name, email, "hibp_api_key")

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
        headers = {
            **_UA,
            "hibp-api-key": key,
        }

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 404:
                    # Sin brechas conocidas registradas
                    email_node = EntityNode.create(
                        EntityType.EMAIL,
                        email,
                        f"Email: {email}",
                        attributes={"pwned": False, "breach_count": 0, "source": "haveibeenpwned"},
                        confidence=0.95,
                    )
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=email,
                        entities=[email_node],
                        relations=[],
                        raw_payload=json.dumps({"email": email, "breaches": []}),
                        metadata={
                            "ok": True,
                            "pwned": False,
                            "breaches": 0,
                            "admiralty": rate_source(self.name),
                            "admiralty_grade": assess_evidence(
                                self.name, confidence=0.95, entity_type="EMAIL"
                            ).grade,
                        },
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("HaveIBeenPwned API request failed for %s: %s", email, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=email,
                raw_payload=json.dumps({"email": email, "error": str(exc)}),
                metadata={"ok": False, "error": str(exc), "admiralty": rate_source(self.name)},
            )

        if not isinstance(data, list):
            data = []

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        # 1. Nodo del correo
        email_node = EntityNode.create(
            EntityType.EMAIL,
            email,
            f"Email: {email} (Expuesto)",
            attributes={
                "pwned": True,
                "breach_count": len(data),
                "source": "haveibeenpwned",
            },
            confidence=0.95,
        )
        entities.append(email_node)

        # 2. Nodos de brechas y aristas EXPOSED_IN
        for item in data:
            if not isinstance(item, dict):
                continue
            breach_name = str(item.get("Name", "Unknown")).strip()
            title = str(item.get("Title", breach_name)).strip()
            domain = item.get("Domain")
            breach_date = item.get("BreachDate")
            pwn_count = item.get("PwnCount")
            data_classes = item.get("DataClasses", [])
            is_verified = item.get("IsVerified", True)

            breach_node = EntityNode.create(
                EntityType.BREACH,
                breach_name,
                f"Breach: {title}",
                attributes={
                    "title": title,
                    "domain": domain,
                    "breach_date": breach_date,
                    "pwn_count": pwn_count,
                    "data_classes": data_classes,
                    "is_verified": is_verified,
                    "source": "haveibeenpwned",
                },
                confidence=0.9,
            )
            entities.append(breach_node)

            relations.append(
                RelationEdge(
                    source_id=email_node.id,
                    target_id=breach_node.id,
                    relation_type=RelationType.EXPOSED_IN,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=email,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False)[:6000],
            metadata={
                "ok": True,
                "pwned": True,
                "breaches": len(data),
                "admiralty": rate_source(self.name),
                "admiralty_grade": assess_evidence(
                    self.name, confidence=0.95, entity_type="EMAIL"
                ).grade,
            },
        )

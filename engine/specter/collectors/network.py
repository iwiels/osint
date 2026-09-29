"""
WraithOSINT - Network & Infrastructure Collectors
Colectores de DNS, Certificate Transparency (crt.sh), inspección TLS/SSL y enriquecimiento IP/RDAP.
"""

import asyncio
import json
import socket
import ssl
from typing import Any

import dns.resolver
import dns.reversename
import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)


class DNSCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="dns_collector")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        raw_data: dict[str, Any] = {"domain": domain, "records": {}}

        # Nodo raíz del dominio
        domain_node = EntityNode.create(
            type=EntityType.DOMAIN,
            value=domain,
            label=f"Domain: {domain}",
            attributes={"target": True},
        )
        entities.append(domain_node)

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        for rtype in record_types:
            try:
                answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
                records_list = [r.to_text().strip('"') for r in answers]
                raw_data["records"][rtype] = records_list

                for record_str in records_list:
                    rec_node = EntityNode.create(
                        type=EntityType.DNS_RECORD,
                        value=f"{rtype}:{record_str}",
                        label=f"{rtype}: {record_str[:30]}",
                        attributes={"type": rtype, "record": record_str, "domain": domain},
                    )
                    entities.append(rec_node)
                    relations.append(
                        RelationEdge(
                            source_id=domain_node.id,
                            target_id=rec_node.id,
                            relation_type=RelationType.ASSOCIATED_WITH,
                        )
                    )

                    # Si es registro A/AAAA, vincular como IP_ADDRESS
                    if rtype in ("A", "AAAA"):
                        ip_node = EntityNode.create(
                            type=EntityType.IP_ADDRESS,
                            value=record_str,
                            label=f"IP: {record_str}",
                            attributes={"version": 4 if rtype == "A" else 6},
                        )
                        entities.append(ip_node)
                        relations.append(
                            RelationEdge(
                                source_id=domain_node.id,
                                target_id=ip_node.id,
                                relation_type=RelationType.RESOLVES_TO,
                            )
                        )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout):
                continue
            except Exception as e:
                raw_data["records"][f"{rtype}_error"] = str(e)

        # Chequeo específico de política DMARC
        try:
            dmarc_target = f"_dmarc.{domain}"
            answers = await asyncio.to_thread(resolver.resolve, dmarc_target, "TXT")
            dmarc_records = [r.to_text().strip('"') for r in answers]
            raw_data["records"]["DMARC"] = dmarc_records
            for d in dmarc_records:
                dmarc_node = EntityNode.create(
                    type=EntityType.DNS_RECORD,
                    value=f"DMARC:{d}",
                    label=f"DMARC: {d[:30]}",
                    attributes={"type": "DMARC", "policy": d},
                )
                entities.append(dmarc_node)
                relations.append(
                    RelationEdge(
                        source_id=domain_node.id,
                        target_id=dmarc_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
        except Exception:
            pass

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(raw_data, indent=2),
            metadata={"total_entities_found": len(entities)},
        )


class CrtShCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="crt_sh_collector")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        discovered_subs: set[str] = set()

        domain_node = EntityNode.create(
            type=EntityType.DOMAIN,
            value=domain,
            label=f"Domain: {domain}",
        )
        entities.append(domain_node)

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        raw_payload = ""

        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT-Investigator/1.0"
                }
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    raw_payload = resp.text
                    try:
                        data = resp.json()
                        for entry in data:
                            name_val = entry.get("name_value", "")
                            for sub in name_val.split("\n"):
                                clean_sub = sub.strip().lower()
                                if clean_sub.startswith("*."):
                                    clean_sub = clean_sub[2:]
                                if (
                                    clean_sub
                                    and clean_sub.endswith(f".{domain}")
                                    and clean_sub != domain
                                ):
                                    discovered_subs.add(clean_sub)
                    except Exception:
                        pass
        except Exception as e:
            raw_payload = json.dumps({"error": str(e), "target": domain})

        for sub in sorted(discovered_subs):
            sub_node = EntityNode.create(
                type=EntityType.SUBDOMAIN,
                value=sub,
                label=f"Subdomain: {sub}",
                attributes={"parent_domain": domain, "source": "crt.sh"},
            )
            entities.append(sub_node)
            relations.append(
                RelationEdge(
                    source_id=sub_node.id,
                    target_id=domain_node.id,
                    relation_type=RelationType.SUBDOMAIN_OF,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=raw_payload or json.dumps({"subdomains": list(discovered_subs)}),
            metadata={"subdomains_count": len(discovered_subs)},
        )


class TLSCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="tls_collector")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        host = target.strip().lower()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        cert_info: dict[str, Any] = {"host": host}

        domain_node = EntityNode.create(
            type=EntityType.DOMAIN,
            value=host,
            label=f"Host: {host}",
        )
        entities.append(domain_node)

        def _fetch_cert() -> dict[str, Any]:
            # Forense por diseño: se captura el certificado PRESENTADO aunque la
            # cadena no verifique (expirado, autofirmado, MITM: eso también es
            # evidencia). `tls_verified` lo deja explícito; nunca se afirma
            # validez de cadena a partir de este colector.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection((host, 443), timeout=4.0) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as ssock,
            ):
                return ssock.getpeercert() or {}

        try:
            cert_dict = await asyncio.to_thread(_fetch_cert)
            cert_info["cert"] = cert_dict
            # La cadena NO se verifica (ver _fetch_cert): este flag evita que
            # la UI o un dossier presenten el cert como "válido".
            cert_info["tls_verified"] = False

            subject = dict(x[0] for x in cert_dict.get("subject", ()))
            issuer = dict(x[0] for x in cert_dict.get("issuer", ()))
            sans = [val for key, val in cert_dict.get("subjectAltName", ()) if key == "DNS"]

            common_name = subject.get("commonName", host)
            cert_node = EntityNode.create(
                type=EntityType.SSL_CERTIFICATE,
                value=f"tls:{common_name}",
                label=f"Cert: {common_name}",
                attributes={
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": cert_dict.get("notBefore"),
                    "valid_until": cert_dict.get("notAfter"),
                    "sans": sans,
                },
            )
            entities.append(cert_node)
            relations.append(
                RelationEdge(
                    source_id=domain_node.id,
                    target_id=cert_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

            # Si el emisor es una organización conocida
            issuer_org = issuer.get("organizationName")
            if issuer_org:
                org_node = EntityNode.create(
                    type=EntityType.ORGANIZATION,
                    value=issuer_org,
                    label=f"Org: {issuer_org}",
                    attributes={"role": "Certificate Authority"},
                )
                entities.append(org_node)
                relations.append(
                    RelationEdge(
                        source_id=cert_node.id,
                        target_id=org_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )

        except Exception as e:
            cert_info["error"] = str(e)

        return CollectorResult(
            collector_name=self.name,
            source_target=host,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(cert_info, default=str, indent=2),
            metadata={"has_cert": len(entities) > 1},
        )


class IPEnricher(BaseCollector):
    def __init__(self):
        super().__init__(name="ip_enricher")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        ip = target.strip()
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        enrichment_data: dict[str, Any] = {"ip": ip}

        ip_node = EntityNode.create(
            type=EntityType.IP_ADDRESS,
            value=ip,
            label=f"IP: {ip}",
        )
        entities.append(ip_node)

        # 1. PTR Reverse DNS
        try:
            rev_name = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            answers = await asyncio.to_thread(resolver.resolve, rev_name, "PTR")
            ptr_list = [r.to_text().rstrip(".") for r in answers]
            enrichment_data["ptr"] = ptr_list

            for ptr in ptr_list:
                ptr_node = EntityNode.create(
                    type=EntityType.DOMAIN,
                    value=ptr,
                    label=f"PTR: {ptr}",
                )
                entities.append(ptr_node)
                relations.append(
                    RelationEdge(
                        source_id=ip_node.id,
                        target_id=ptr_node.id,
                        relation_type=RelationType.RESOLVES_TO,
                    )
                )
        except Exception:
            enrichment_data["ptr"] = []

        # 2. RDAP Lookup pasivo
        rdap_url = f"https://rdap.arin.net/registry/ip/{ip}"
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                headers = {"Accept": "application/rdap+json"}
                resp = await client.get(rdap_url, headers=headers)
                if resp.status_code == 200:
                    rdap_json = resp.json()
                    enrichment_data["rdap"] = rdap_json

                    net_name = rdap_json.get("name")
                    country = rdap_json.get("country")

                    if net_name:
                        org_node = EntityNode.create(
                            type=EntityType.ORGANIZATION,
                            value=net_name,
                            label=f"NetName: {net_name}",
                            attributes={"country": country},
                        )
                        entities.append(org_node)
                        relations.append(
                            RelationEdge(
                                source_id=ip_node.id,
                                target_id=org_node.id,
                                relation_type=RelationType.HOSTED_ON,
                            )
                        )
        except Exception as e:
            enrichment_data["rdap_error"] = str(e)

        # 3. ASN vía Team Cymru (DNS, sin key): origin.asn.cymru.com
        #    Responde "ASN | prefijo | país | registro | fecha". Solo IPv4
        #    (IPv6 usa ip6.arpa por nibbles: fuera de este paso).
        try:
            octets = ip.split(".")
            if len(octets) != 4 or not all(p.isdigit() for p in octets):
                raise ValueError("no IPv4")
            rev_ip = ".".join(reversed(octets))
            cymru_name = f"{rev_ip}.origin.asn.cymru.com"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            answers = await asyncio.to_thread(resolver.resolve, cymru_name, "TXT")
            parts = answers[0].to_text().strip('"').split("|")
            asn_num = parts[0].strip()
            enrichment_data["asn"] = {
                "asn": asn_num,
                "prefix": parts[1].strip() if len(parts) > 1 else "",
                "country": parts[2].strip() if len(parts) > 2 else "",
            }
            asn_node = EntityNode.create(
                type=EntityType.ASN,
                value=f"AS{asn_num}",
                label=f"ASN: AS{asn_num}",
                attributes={"source": "cymru"},
            )
            entities.append(asn_node)
            relations.append(
                RelationEdge(
                    source_id=ip_node.id,
                    target_id=asn_node.id,
                    relation_type=RelationType.HOSTED_ON,
                )
            )
        except Exception as e:
            enrichment_data["asn_error"] = str(e)

        # 4. GeoLite gratuita (ip-api.com, 45 req/min, sin key)
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}"
                    "?fields=status,country,city,lat,lon,isp,org,proxy,hosting,query"
                )
                if resp.status_code == 200:
                    geo = resp.json()
                    if geo.get("status") == "success":
                        enrichment_data["geo"] = geo
                        ip_node.attributes.update(
                            {
                                "geo_country": geo.get("country"),
                                "geo_city": geo.get("city"),
                                "geo_isp": geo.get("isp"),
                                "geo_proxy": geo.get("proxy"),
                                "geo_hosting": geo.get("hosting"),
                            }
                        )
                        if geo.get("lat") is not None and geo.get("lon") is not None:
                            geo_node = EntityNode.create(
                                type=EntityType.GEO_LOCATION,
                                value=f"{geo['lat']},{geo['lon']}",
                                label=f"GeoIP: {geo.get('city')}, {geo.get('country')}",
                                attributes={"source": "ip-api"},
                                confidence=0.7,
                            )
                            entities.append(geo_node)
                            relations.append(
                                RelationEdge(
                                    source_id=ip_node.id,
                                    target_id=geo_node.id,
                                    relation_type=RelationType.LOCATED_AT,
                                )
                            )
        except Exception as e:
            enrichment_data["geo_error"] = str(e)

        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(enrichment_data, indent=2, default=str),
            metadata={"ptr_records": len(enrichment_data.get("ptr", []))},
        )

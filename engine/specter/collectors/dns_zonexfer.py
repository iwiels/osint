"""
WraithOSINT - DNS Zone Transfer Collector
Intenta transferencia de zona DNS (AXFR) contra los nameservers del dominio.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import dns.query
import dns.resolver
import dns.zone
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.dns_zonexfer")


class DNSZoneTransferCollector(BaseCollector):
    """Intenta transferencia de zona DNS (AXFR) contra los NS del dominio.

    Si el servidor permite AXFR, extrae todos los registros del dominio
    incluyendo subdominios, IPs, MX, TXT, etc.
    """

    def __init__(self) -> None:
        super().__init__(name="dns_zonexfer")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower().rstrip(".")

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        zone_records: list[dict[str, Any]] = []
        ns_servers: list[str] = []
        transfer_success = False
        errors: list[str] = []

        # Nodo raíz del dominio
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"Dominio: {domain}",
            attributes={"source": "dns_zonexfer"},
        )
        entities.append(root)

        # Obtener nameservers del dominio
        try:
            ns_answer = dns.resolver.resolve(domain, "NS")
            ns_servers = [str(ns.target).rstrip(".") for ns in ns_answer]
        except Exception as exc:
            errors.append(f"No se pudieron obtener NS: {exc}")

        # Intentar AXFR contra cada NS
        for ns_host in ns_servers:
            try:
                # Resolver IP del NS
                try:
                    ns_ip_answer = dns.resolver.resolve(ns_host, "A")
                    ns_ip = str(ns_ip_answer[0])
                except Exception:
                    ns_ip = ns_host

                # Intentar transferencia de zona
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
                transfer_success = True

                # Extraer registros de la zona
                for name, node in zone.nodes.items():
                    fqdn = f"{name}.{domain}" if str(name) != "@" else domain
                    fqdn = fqdn.rstrip(".")

                    for rdataset in node.rdatasets:
                        rtype = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            rdata_str = str(rdata)

                            record_info = {
                                "name": fqdn,
                                "type": rtype,
                                "ttl": rdataset.ttl,
                                "data": rdata_str,
                                "ns": ns_host,
                            }
                            zone_records.append(record_info)

                            # Crear entidades según tipo de registro
                            if rtype == "A":
                                ip_node = EntityNode.create(
                                    EntityType.IP_ADDRESS,
                                    rdata_str,
                                    f"IP: {rdata_str}",
                                    attributes={
                                        "source": "dns_zonexfer",
                                        "record_type": rtype,
                                        "ttl": rdataset.ttl,
                                        "ns": ns_host,
                                    },
                                    confidence=0.9,
                                )
                                entities.append(ip_node)
                                relations.append(
                                    RelationEdge(
                                        source_id=root.id,
                                        target_id=ip_node.id,
                                        relation_type=RelationType.RESOLVES_TO,
                                    )
                                )
                            elif rtype == "CNAME":
                                cname_node = EntityNode.create(
                                    EntityType.DOMAIN,
                                    rdata_str.rstrip("."),
                                    f"CNAME: {rdata_str}",
                                    attributes={
                                        "source": "dns_zonexfer",
                                        "record_type": rtype,
                                        "ttl": rdataset.ttl,
                                    },
                                    confidence=0.8,
                                )
                                entities.append(cname_node)
                                relations.append(
                                    RelationEdge(
                                        source_id=root.id,
                                        target_id=cname_node.id,
                                        relation_type=RelationType.RESOLVES_TO,
                                    )
                                )
                            elif rtype == "MX":
                                mx_node = EntityNode.create(
                                    EntityType.DOMAIN,
                                    rdata_str.rstrip("."),
                                    f"MX: {rdata_str}",
                                    attributes={
                                        "source": "dns_zonexfer",
                                        "record_type": rtype,
                                        "ttl": rdataset.ttl,
                                    },
                                    confidence=0.8,
                                )
                                entities.append(mx_node)
                                relations.append(
                                    RelationEdge(
                                        source_id=root.id,
                                        target_id=mx_node.id,
                                        relation_type=RelationType.ASSOCIATED_WITH,
                                    )
                                )
                            elif rtype == "TXT":
                                txt_node = EntityNode.create(
                                    EntityType.ALIAS,
                                    rdata_str[:200],
                                    f"TXT: {rdata_str[:80]}",
                                    attributes={
                                        "source": "dns_zonexfer",
                                        "record_type": rtype,
                                        "ttl": rdataset.ttl,
                                    },
                                    confidence=0.6,
                                )
                                entities.append(txt_node)
                                relations.append(
                                    RelationEdge(
                                        source_id=root.id,
                                        target_id=txt_node.id,
                                        relation_type=RelationType.ASSOCIATED_WITH,
                                    )
                                )
                            elif rtype == "NS":
                                ns_node = EntityNode.create(
                                    EntityType.DOMAIN,
                                    rdata_str.rstrip("."),
                                    f"NS: {rdata_str}",
                                    attributes={
                                        "source": "dns_zonexfer",
                                        "record_type": rtype,
                                        "ttl": rdataset.ttl,
                                    },
                                    confidence=0.8,
                                )
                                entities.append(ns_node)
                                relations.append(
                                    RelationEdge(
                                        source_id=root.id,
                                        target_id=ns_node.id,
                                        relation_type=RelationType.ADMINISTERS,
                                    )
                                )
                            elif rtype == "SOA":
                                soa_node = EntityNode.create(
                                    EntityType.DNS_RECORD,
                                    f"{domain} SOA",
                                    f"SOA: {rdata_str[:80]}",
                                    attributes={
                                        "source": "dns_zonexfer",
                                        "record_type": rtype,
                                        "ttl": rdataset.ttl,
                                        "data": rdata_str,
                                    },
                                    confidence=0.9,
                                )
                                entities.append(soa_node)
                                relations.append(
                                    RelationEdge(
                                        source_id=root.id,
                                        target_id=soa_node.id,
                                        relation_type=RelationType.ASSOCIATED_WITH,
                                    )
                                )

                # Si tuvimos éxito, no necesitamos probar más NS
                break

            except Exception as exc:
                errors.append(f"AXFR falló contra {ns_host}: {exc}")
                continue

        # Si no se pudo AXFR, registrar los NS encontrados como entidades
        if not transfer_success:
            for ns_host in ns_servers:
                ns_node = EntityNode.create(
                    EntityType.DOMAIN,
                    ns_host,
                    f"NS: {ns_host}",
                    attributes={"source": "dns_zonexfer", "record_type": "NS"},
                    confidence=0.7,
                )
                entities.append(ns_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=ns_node.id,
                        relation_type=RelationType.ADMINISTERS,
                    )
                )

        metadata: dict[str, Any] = {
            "ok": transfer_success,
            "domain": domain,
            "ns_servers": ns_servers,
            "records_extracted": len(zone_records),
            "transfer_success": transfer_success,
            "errors": errors,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "ns_servers": ns_servers,
                    "transfer_success": transfer_success,
                    "records": zone_records[:500],
                    "errors": errors,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )

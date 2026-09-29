"""
SpecterOSINT - Passive DNS Collectors
Fuentes de resolución DNS histórica para pivoteo forense.

- DNSGrep (Rapid7 Sonar Project): dominio -> IPs históricas (sin key)
- Mnemonic PassiveDNS: registros DNS históricos con TTL (sin key)
- CIRCL.LU Passive DNS: registros pasivos de Luxemburgo (sin key)
- Farsight DNSDB: historial completo de resoluciones (requiere key)

Todas las fuentes gratuitas no requieren autenticación. DNSDB es Fase B:
sin key retorna requires_key y el agente ni lo intenta.
"""

from __future__ import annotations

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

logger = logging.getLogger("specter.collectors.passive_dns")

_TIMEOUT = 15.0
# ASCII estricto: httpx codifica los headers en ASCII.
_UA = {"User-Agent": "SpecterOSINT/0.2 (+forense, key en boveda local)"}


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


class DNSGrepCollector(BaseCollector):
    """DNSGrep (Rapid7 Sonar Project): resoluciones históricas de dominios.

    API: https://api.dnsgrep.com/v1/search/{domain}
    Retorna registros A/AAAA/CNAME/MX/NS/TXT con fechas de primera/última vez.
    """

    def __init__(self) -> None:
        super().__init__(name="dnsgrep")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://api.dnsgrep.com/v1/search/{quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=domain,
                        raw_payload=json.dumps({"domain": domain, "present": False}),
                        metadata={"ok": True, "present": False},
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

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN, domain, f"Dominio: {domain}", attributes={"source": "dnsgrep"}
        )
        entities.append(root)

        # DNSGrep retorna una lista de registros con campos: name, type, ttl, rdata, first_seen, last_seen
        records = data if isinstance(data, list) else data.get("data", data.get("records", []))
        if not isinstance(records, list):
            records = []

        seen_ips: set[str] = set()
        for rec in records[:100]:
            if not isinstance(rec, dict):
                continue
            rdata = str(rec.get("rdata", rec.get("answer", ""))).strip()
            rtype = str(rec.get("type", rec.get("rrtype", "A"))).upper()
            if not rdata:
                continue

            # Determinar tipo de entidad según rdata
            if rtype in ("A", "AAAA") and rdata not in seen_ips:
                seen_ips.add(rdata)
                ip_node = EntityNode.create(
                    EntityType.IP_ADDRESS,
                    rdata,
                    f"IP: {rdata}",
                    attributes={
                        "record_type": rtype,
                        "first_seen": rec.get("first_seen"),
                        "last_seen": rec.get("last_seen"),
                        "source": "dnsgrep",
                    },
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
            elif rtype == "CNAME":
                cname_node = EntityNode.create(
                    EntityType.DOMAIN,
                    rdata.rstrip("."),
                    f"CNAME: {rdata}",
                    attributes={
                        "record_type": rtype,
                        "first_seen": rec.get("first_seen"),
                        "last_seen": rec.get("last_seen"),
                        "source": "dnsgrep",
                    },
                    confidence=0.7,
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
                    rdata.rstrip("."),
                    f"MX: {rdata}",
                    attributes={
                        "record_type": rtype,
                        "first_seen": rec.get("first_seen"),
                        "last_seen": rec.get("last_seen"),
                        "source": "dnsgrep",
                    },
                    confidence=0.7,
                )
                entities.append(mx_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=mx_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            elif rtype == "NS":
                ns_node = EntityNode.create(
                    EntityType.DOMAIN,
                    rdata.rstrip("."),
                    f"NS: {rdata}",
                    attributes={
                        "record_type": rtype,
                        "first_seen": rec.get("first_seen"),
                        "last_seen": rec.get("last_seen"),
                        "source": "dnsgrep",
                    },
                    confidence=0.7,
                )
                entities.append(ns_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=ns_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            elif rtype == "TXT":
                txt_node = EntityNode.create(
                    EntityType.ALIAS,
                    rdata[:200],
                    f"TXT: {rdata[:80]}",
                    attributes={
                        "record_type": rtype,
                        "first_seen": rec.get("first_seen"),
                        "last_seen": rec.get("last_seen"),
                        "source": "dnsgrep",
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

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False),
            metadata={"ok": True, "records": len(records)},
        )


class MnemonicPassiveDNSCollector(BaseCollector):
    """Mnemonic PassiveDNS: registros DNS históricos con TTL.

    API: https://api.mnemonic.no/pdns/v3/{domain}
    Retorna registros A/AAAA/CNAME/MX/NS/PTR/TTL con timestamps.
    """

    def __init__(self) -> None:
        super().__init__(name="mnemonic_pdns")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://api.mnemonic.no/pdns/v3/{quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=domain,
                        raw_payload=json.dumps({"domain": domain, "present": False}),
                        metadata={"ok": True, "present": False},
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

        # Mnemonic retorna { responseCode, size, count, data: [...] }
        if data.get("responseCode") != 200:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps(
                    {"domain": domain, "responseCode": data.get("responseCode")}
                ),
                metadata={"ok": False, "error": f"responseCode {data.get('responseCode')}"},
            )

        records = data.get("data", [])
        if not isinstance(records, list):
            records = []

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"Dominio: {domain}",
            attributes={"source": "mnemonic_pdns"},
        )
        entities.append(root)

        seen_ips: set[str] = set()
        for rec in records[:100]:
            if not isinstance(rec, dict):
                continue
            query = str(rec.get("query", rec.get("rrname", ""))).rstrip(".")
            answer = str(rec.get("answer", rec.get("rdata", ""))).rstrip(".")
            rtype = str(rec.get("rrtype", rec.get("type", "A"))).upper()
            ttl = rec.get("ttl")
            last_seen = rec.get("lastSeenTimestamp", rec.get("time_last"))

            if not answer:
                continue

            # Ignorar registros con wildcards
            if "*" in query or "%" in query:
                continue

            if rtype in ("A", "AAAA") and answer not in seen_ips:
                seen_ips.add(answer)
                ip_node = EntityNode.create(
                    EntityType.IP_ADDRESS,
                    answer,
                    f"IP: {answer}",
                    attributes={
                        "record_type": rtype,
                        "ttl": ttl,
                        "last_seen": last_seen,
                        "source": "mnemonic_pdns",
                    },
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
            elif rtype == "CNAME" and answer != domain:
                cname_node = EntityNode.create(
                    EntityType.DOMAIN,
                    answer,
                    f"CNAME: {answer}",
                    attributes={
                        "record_type": rtype,
                        "ttl": ttl,
                        "last_seen": last_seen,
                        "source": "mnemonic_pdns",
                    },
                    confidence=0.7,
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
                    answer,
                    f"MX: {answer}",
                    attributes={
                        "record_type": rtype,
                        "ttl": ttl,
                        "last_seen": last_seen,
                        "source": "mnemonic_pdns",
                    },
                    confidence=0.7,
                )
                entities.append(mx_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=mx_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            elif rtype == "NS":
                ns_node = EntityNode.create(
                    EntityType.DOMAIN,
                    answer,
                    f"NS: {answer}",
                    attributes={
                        "record_type": rtype,
                        "ttl": ttl,
                        "last_seen": last_seen,
                        "source": "mnemonic_pdns",
                    },
                    confidence=0.7,
                )
                entities.append(ns_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=ns_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            elif rtype == "PTR":
                ptr_node = EntityNode.create(
                    EntityType.DOMAIN,
                    answer,
                    f"PTR: {answer}",
                    attributes={
                        "record_type": rtype,
                        "ttl": ttl,
                        "last_seen": last_seen,
                        "source": "mnemonic_pdns",
                    },
                    confidence=0.7,
                )
                entities.append(ptr_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=ptr_node.id,
                        relation_type=RelationType.RESOLVES_TO,
                    )
                )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(data, ensure_ascii=False),
            metadata={"ok": True, "records": len(records)},
        )


class CIRCLPassiveDNSCollector(BaseCollector):
    """CIRCL.LU Passive DNS: registros DNS pasivos de Luxemburgo.

    API: https://www.circl.lu/pdns/query/{domain}
    Retorna registros A/AAAA/CNAME/MX/NS/TXT con timestamps (JSON por línea).
    """

    def __init__(self) -> None:
        super().__init__(name="circl_pdns")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://www.circl.lu/pdns/query/{quote(domain)}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=domain,
                        raw_payload=json.dumps({"domain": domain, "present": False}),
                        metadata={"ok": True, "present": False},
                    )
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        # CIRCL retorna un JSON por línea (NDJSON)
        records: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    records.append(rec)
            except json.JSONDecodeError:
                continue

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        root = EntityNode.create(
            EntityType.DOMAIN,
            domain,
            f"Dominio: {domain}",
            attributes={"source": "circl_pdns"},
        )
        entities.append(root)

        seen_ips: set[str] = set()
        for rec in records[:100]:
            rrname = str(rec.get("rrname", rec.get("query", ""))).rstrip(".")
            rdata = str(rec.get("rdata", rec.get("answer", ""))).rstrip(".")
            rtype = str(rec.get("rrtype", rec.get("type", "A"))).upper()
            time_first = rec.get("time_first", rec.get("first_seen"))
            time_last = rec.get("time_last", rec.get("last_seen"))

            if not rdata:
                continue

            if rtype in ("A", "AAAA") and rdata not in seen_ips:
                seen_ips.add(rdata)
                ip_node = EntityNode.create(
                    EntityType.IP_ADDRESS,
                    rdata,
                    f"IP: {rdata}",
                    attributes={
                        "record_type": rtype,
                        "time_first": time_first,
                        "time_last": time_last,
                        "source": "circl_pdns",
                    },
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
            elif rtype == "CNAME" and rrname != domain:
                cname_node = EntityNode.create(
                    EntityType.DOMAIN,
                    rrname,
                    f"CNAME: {rrname}",
                    attributes={
                        "record_type": rtype,
                        "time_first": time_first,
                        "time_last": time_last,
                        "source": "circl_pdns",
                    },
                    confidence=0.7,
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
                    rdata,
                    f"MX: {rdata}",
                    attributes={
                        "record_type": rtype,
                        "time_first": time_first,
                        "time_last": time_last,
                        "source": "circl_pdns",
                    },
                    confidence=0.7,
                )
                entities.append(mx_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=mx_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            elif rtype == "NS":
                ns_node = EntityNode.create(
                    EntityType.DOMAIN,
                    rdata,
                    f"NS: {rdata}",
                    attributes={
                        "record_type": rtype,
                        "time_first": time_first,
                        "time_last": time_last,
                        "source": "circl_pdns",
                    },
                    confidence=0.7,
                )
                entities.append(ns_node)
                relations.append(
                    RelationEdge(
                        source_id=root.id,
                        target_id=ns_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )
            elif rtype == "TXT":
                txt_node = EntityNode.create(
                    EntityType.ALIAS,
                    rdata[:200],
                    f"TXT: {rdata[:80]}",
                    attributes={
                        "record_type": rtype,
                        "time_first": time_first,
                        "time_last": time_last,
                        "source": "circl_pdns",
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

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "records": records}, ensure_ascii=False),
            metadata={"ok": True, "records": len(records)},
        )


class DNSDBChecker(BaseCollector):
    """Farsight DNSDB: historial completo de resoluciones DNS (requiere key).

    API: https://api.dnsdb.info/lookup/rdata/ip/{ip}
    Retorna registros NDJSON con rrname, rrtype, rdata, time_first, time_last.
    """

    def __init__(self) -> None:
        super().__init__(name="dnsdb")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("dnsdb_api_key")
        ip = target.strip()
        if key is None:
            return _missing_key_result(self.name, ip, "dnsdb_api_key")

        url = f"https://api.dnsdb.info/lookup/rdata/ip/{quote(ip)}"
        headers = {**_UA, "Accept": "application/x-ndjson", "X-API-Key": key}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=ip,
                        raw_payload=json.dumps({"ip": ip, "present": False}),
                        metadata={"ok": True, "present": False},
                    )
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=ip,
                raw_payload=json.dumps({"ip": ip, "error": str(exc)}),
                metadata={"ok": False},
            )

        # DNSDB retorna NDJSON: primera línea es summary, resto son registros
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        records: list[dict[str, Any]] = []
        for line in lines[1:] if len(lines) > 1 else []:
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    records.append(rec)
            except json.JSONDecodeError:
                continue

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        ip_node = EntityNode.create(
            EntityType.IP_ADDRESS, ip, f"IP: {ip}", attributes={"source": "dnsdb"}
        )
        entities.append(ip_node)

        seen_domains: set[str] = set()
        for rec in records[:100]:
            rrname = str(rec.get("rrname", "")).rstrip(".")
            rrtype = str(rec.get("rrtype", "")).upper()
            rdata = rec.get("rdata", "")
            time_first = rec.get("time_first")
            time_last = rec.get("time_last")

            if not rrname or rrname in seen_domains:
                continue
            seen_domains.add(rrname)

            domain_node = EntityNode.create(
                EntityType.DOMAIN,
                rrname,
                f"Dominio: {rrname}",
                attributes={
                    "record_type": rrtype,
                    "rdata": rdata,
                    "time_first": time_first,
                    "time_last": time_last,
                    "source": "dnsdb",
                },
                confidence=0.8,
            )
            entities.append(domain_node)
            relations.append(
                RelationEdge(
                    source_id=domain_node.id,
                    target_id=ip_node.id,
                    relation_type=RelationType.RESOLVES_TO,
                )
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=ip,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"ip": ip, "records": records}, ensure_ascii=False),
            metadata={"ok": True, "records": len(records)},
        )

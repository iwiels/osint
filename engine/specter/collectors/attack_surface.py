"""
WraithOSINT - Attack Surface & Multi-Source Subdomain Reconnaissance Collector
Agregación pasiva multi-fuente de subdominios, resolución DNS concurrente y validación de superficie de ataque.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import shutil
from typing import Any

import dns.asyncresolver
import dns.resolver
import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.attack_surface")

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_CLI_TIMEOUT = 15.0
_DEFAULT_DNS_CONCURRENCY = 15
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT-Investigator/1.0"}


def is_valid_subdomain(sub: str, domain: str) -> bool:
    """Valida si un string representa un subdominio sintácticamente válido para el dominio raíz."""
    if not sub or not isinstance(sub, str):
        return False

    sub = sub.strip().lower()
    if sub.startswith("*."):
        sub = sub[2:]
    sub = sub.lstrip(".")

    domain = domain.strip().lower()
    if not sub or sub == domain or not sub.endswith(f".{domain}"):
        return False

    if len(sub) > 253:
        return False

    labels = sub.split(".")
    label_pattern = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not label_pattern.match(label):
            return False

    return True


class AttackSurfaceCollector(BaseCollector):
    """
    Colector de superficie de ataque y enumeración de subdominios.
    Agrega fuentes pasivas gratuitas (crt.sh, HackerTarget, AlienVault OTX, RapidDNS, Anubis),
    ejecuta herramientas CLI locales si existen (amass, subfinder) y valida registros activos (A/AAAA)
    mediante resolución DNS asíncrona concurrente.
    """

    def __init__(
        self,
        resolver: Any = None,
        timeout: float = _DEFAULT_TIMEOUT,
        max_dns_concurrency: int = _DEFAULT_DNS_CONCURRENCY,
        cli_timeout: float = _DEFAULT_CLI_TIMEOUT,
    ):
        super().__init__(name="attack_surface")
        self.resolver = resolver
        self.timeout = timeout
        self.max_dns_concurrency = max_dns_concurrency
        self.cli_timeout = cli_timeout

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = self._normalize_domain(target)
        if not domain:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=json.dumps({"error": "Objetivo inválido", "target": target}),
                metadata={"total_subdomains_found": 0, "resolved_subdomains": 0},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        raw_data: dict[str, Any] = {
            "domain": domain,
            "sources": {},
            "errors": {},
            "cli_tools": {},
            "dns_resolutions": {},
        }

        # 1. Nodo raíz del dominio objetivo
        domain_node = EntityNode.create(
            type=EntityType.DOMAIN,
            value=domain,
            label=f"Domain: {domain}",
            attributes={"target": True},
            confidence=1.0,
        )
        entities.append(domain_node)

        # 2. Concurrencia pasiva de fuentes HTTP
        subdomains_by_source: dict[str, set[str]] = {}
        http_tasks = [
            self._fetch_crtsh(domain),
            self._fetch_hackertarget(domain),
            self._fetch_alienvault(domain),
            self._fetch_rapiddns(domain),
            self._fetch_anubis(domain),
        ]

        # 3. Integración CLI (subfinder y amass si están instalados)
        cli_tools_found: list[str] = []
        cli_tasks = []

        subfinder_bin = shutil.which("subfinder")
        if subfinder_bin:
            cli_tools_found.append("subfinder")
            cli_tasks.append(
                self._run_cli_tool(
                    "subfinder",
                    [subfinder_bin, "-d", domain, "-silent"],
                    domain,
                )
            )

        amass_bin = shutil.which("amass")
        if amass_bin:
            cli_tools_found.append("amass")
            cli_tasks.append(
                self._run_cli_tool(
                    "amass",
                    [amass_bin, "enum", "-passive", "-d", domain, "-silent"],
                    domain,
                )
            )

        all_results = await asyncio.gather(*http_tasks, *cli_tasks, return_exceptions=True)

        for item in all_results:
            if isinstance(item, Exception):
                logger.debug("Error en recolección pasiva: %s", item)
                continue
            if isinstance(item, tuple) and len(item) == 3:
                src_name, found_subs, err = item
                if err:
                    raw_data["errors"][src_name] = err
                subdomains_by_source[src_name] = found_subs
                raw_data["sources"][src_name] = sorted(found_subs)

        # 4. Sanitización, deduplicación y mapeo inverso subdominio -> fuentes
        sources_map: dict[str, set[str]] = {}
        for src_name, sub_set in subdomains_by_source.items():
            for sub in sub_set:
                if is_valid_subdomain(sub, domain):
                    clean_sub = sub.strip().lower()
                    if clean_sub.startswith("*."):
                        clean_sub = clean_sub[2:]
                    clean_sub = clean_sub.lstrip(".")
                    if clean_sub and clean_sub != domain:
                        sources_map.setdefault(clean_sub, set()).add(src_name)

        all_unique_subs = sorted(sources_map.keys())

        # 5. Validación DNS concurrente (A / AAAA)
        dns_resolver = self._get_resolver()
        semaphore = asyncio.Semaphore(self.max_dns_concurrency)

        async def _resolve_worker(sub: str) -> tuple[str, list[str]]:
            async with semaphore:
                ips = await self._resolve_ips(sub, dns_resolver)
                return sub, ips

        resolve_tasks = [_resolve_worker(sub) for sub in all_unique_subs]
        resolve_results = await asyncio.gather(*resolve_tasks, return_exceptions=True)

        resolved_map: dict[str, list[str]] = {}
        for res in resolve_results:
            if isinstance(res, tuple) and len(res) == 2:
                s, ips = res
                if ips:
                    resolved_map[s] = ips
                    raw_data["dns_resolutions"][s] = ips

        # 6. Creación de nodos SUBDOMAIN e IP_ADDRESS y aristas
        ip_nodes_cache: dict[str, EntityNode] = {}

        for sub in all_unique_subs:
            src_list = sources_map[sub]
            ips = resolved_map.get(sub, [])

            # Cálculo de confianza
            if ips:
                sub_confidence = 0.95
            elif len(src_list) >= 2 or any(src in ("subfinder", "amass") for src in src_list):
                sub_confidence = 0.85
            else:
                sub_confidence = 0.70

            sub_node = EntityNode.create(
                type=EntityType.SUBDOMAIN,
                value=sub,
                label=f"Subdomain: {sub}",
                attributes={
                    "parent_domain": domain,
                    "sources": sorted(src_list),
                    "resolved": bool(ips),
                    "ip_count": len(ips),
                },
                confidence=sub_confidence,
            )
            entities.append(sub_node)

            # Arista SUBDOMAIN_OF hacia el dominio objetivo
            relations.append(
                RelationEdge(
                    source_id=sub_node.id,
                    target_id=domain_node.id,
                    relation_type=RelationType.SUBDOMAIN_OF,
                    confidence=sub_confidence,
                )
            )

            # Para cada IP resuelta: crear nodo IP y arista RESOLVES_TO
            for ip in ips:
                if ip not in ip_nodes_cache:
                    ip_node = EntityNode.create(
                        type=EntityType.IP_ADDRESS,
                        value=ip,
                        label=f"IP: {ip}",
                        attributes={
                            "version": 6 if ":" in ip else 4,
                            "subdomains": [sub],
                        },
                        confidence=1.0,
                    )
                    ip_nodes_cache[ip] = ip_node
                    entities.append(ip_node)
                else:
                    cached_ip = ip_nodes_cache[ip]
                    sub_list = cached_ip.attributes.get("subdomains", [])
                    if sub not in sub_list:
                        sub_list.append(sub)

                relations.append(
                    RelationEdge(
                        source_id=sub_node.id,
                        target_id=ip_nodes_cache[ip].id,
                        relation_type=RelationType.RESOLVES_TO,
                        confidence=1.0,
                    )
                )

        metadata = {
            "total_subdomains_found": len(all_unique_subs),
            "resolved_subdomains": len(resolved_map),
            "total_ips_found": len(ip_nodes_cache),
            "sources_queried": list(subdomains_by_source.keys()),
            "cli_tools_available": cli_tools_found,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(raw_data, indent=2, default=str),
            metadata=metadata,
        )

    def _normalize_domain(self, target: str) -> str:
        domain = target.strip().lower()
        if "://" in domain:
            domain = domain.split("://", 1)[1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]
        if ":" in domain:
            domain = domain.split(":", 1)[0]
        return domain.strip(".")

    def _get_resolver(self) -> Any:
        if self.resolver is not None:
            return self.resolver
        res = dns.asyncresolver.Resolver()
        res.timeout = 2.0
        res.lifetime = 4.0
        return res

    async def _resolve_ips(self, host: str, resolver: Any) -> list[str]:
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                if inspect.iscoroutinefunction(getattr(resolver, "resolve", None)):
                    answers = await resolver.resolve(host, rtype)
                elif hasattr(resolver, "resolve"):
                    answers = await asyncio.to_thread(resolver.resolve, host, rtype)
                else:
                    continue

                for r in answers:
                    ip_str = r.to_text().strip('"')
                    if ip_str and ip_str not in ips:
                        ips.append(ip_str)
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.LifetimeTimeout,
                dns.resolver.NoNameservers,
                Exception,
            ):
                continue
        return ips

    async def _fetch_crtsh(self, domain: str) -> tuple[str, set[str], str | None]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        found: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=_HEADERS)
                if resp.status_code != 200:
                    return "crt.sh", found, f"HTTP {resp.status_code}"

                data = resp.json()
                if isinstance(data, list):
                    for entry in data:
                        if not isinstance(entry, dict):
                            continue
                        name_val = entry.get("name_value", "")
                        for line in name_val.split("\n"):
                            clean = line.strip().lower()
                            if is_valid_subdomain(clean, domain):
                                found.add(clean)
                        cname = entry.get("common_name", "")
                        if is_valid_subdomain(cname, domain):
                            found.add(cname.strip().lower())
                return "crt.sh", found, None
        except Exception as exc:
            return "crt.sh", found, str(exc)

    async def _fetch_hackertarget(self, domain: str) -> tuple[str, set[str], str | None]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        found: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=_HEADERS)
                if resp.status_code != 200:
                    return "hackertarget", found, f"HTTP {resp.status_code}"

                text = resp.text
                if text.startswith("error") or text.startswith("API count"):
                    return "hackertarget", found, text.splitlines()[0]

                for line in text.splitlines():
                    line = line.strip()
                    if not line or "," not in line:
                        continue
                    host = line.split(",")[0].strip().lower()
                    if is_valid_subdomain(host, domain):
                        found.add(host)
                return "hackertarget", found, None
        except Exception as exc:
            return "hackertarget", found, str(exc)

    async def _fetch_alienvault(self, domain: str) -> tuple[str, set[str], str | None]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        found: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=_HEADERS)
                if resp.status_code != 200:
                    return "alienvault", found, f"HTTP {resp.status_code}"

                data = resp.json()
                records = data.get("passive_dns", [])
                if isinstance(records, list):
                    for record in records:
                        if isinstance(record, dict):
                            host = record.get("hostname") or record.get("indicator")
                            if host and is_valid_subdomain(str(host), domain):
                                found.add(str(host).strip().lower())
                return "alienvault", found, None
        except Exception as exc:
            return "alienvault", found, str(exc)

    async def _fetch_rapiddns(self, domain: str) -> tuple[str, set[str], str | None]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        found: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=_HEADERS)
                if resp.status_code != 200:
                    return "rapiddns", found, f"HTTP {resp.status_code}"

                text = resp.text
                pattern = re.compile(
                    rf"(?i)(?:<td>|\b)([a-z0-9_](?:[a-z0-9_-]{{0,61}}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{{0,61}}[a-z0-9_])?)*\.{re.escape(domain)})(?:</td>|\b)"
                )
                for match in pattern.findall(text):
                    clean = match.strip().lower()
                    if is_valid_subdomain(clean, domain):
                        found.add(clean)
                return "rapiddns", found, None
        except Exception as exc:
            return "rapiddns", found, str(exc)

    async def _fetch_anubis(self, domain: str) -> tuple[str, set[str], str | None]:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        found: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers=_HEADERS)
                if resp.status_code != 200:
                    return "anubis", found, f"HTTP {resp.status_code}"

                data = resp.json()
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str) and is_valid_subdomain(item, domain):
                            found.add(item.strip().lower())
                return "anubis", found, None
        except Exception as exc:
            return "anubis", found, str(exc)

    async def _run_cli_tool(
        self, name: str, cmd: list[str], domain: str
    ) -> tuple[str, set[str], str | None]:
        found: set[str] = set()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.cli_timeout)
            except TimeoutError:
                try:
                    if inspect.iscoroutinefunction(proc.kill):
                        await proc.kill()
                    else:
                        proc.kill()
                    await proc.communicate()
                except Exception:
                    pass
                return name, found, f"Timeout tras {self.cli_timeout}s"

            lines = stdout.decode("utf-8", errors="replace").splitlines()
            for line in lines:
                sub = line.strip().lower()
                if is_valid_subdomain(sub, domain):
                    found.add(sub)
            return name, found, None
        except Exception as exc:
            return name, found, str(exc)

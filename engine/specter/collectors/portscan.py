"""
WraithOSINT - Port Scan Collector
Escaneo de puertos TCP comunes con banner grabbing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import Any

from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.portscan")

_TIMEOUT = 5.0
_CONCURRENCY = 10

# Puertos comunes con sus servicios típicos
_COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    119: "nntp",
    123: "ntp",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2638: "sybase",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5631: "pcanywhere",
    5900: "vnc",
    5901: "vnc-1",
    5902: "vnc-2",
    5903: "vnc-3",
    631: "ipp",
    636: "ldaps",
    8080: "http-proxy",
    8888: "http-alt",
    9000: "cslistener",
    990: "ftps",
    992: "telnets",
    993: "imaps",
    995: "pop3s",
}


async def _grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
    """Intenta obtener el banner del servicio."""
    try:
        # Enviar un probe genérico para servicios que no envían banner inmediato
        writer.write(b"\r\n")
        await asyncio.wait_for(writer.drain(), timeout=2.0)
        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        return data.decode("utf-8", errors="ignore").strip()[:200]
    except Exception:
        return ""


async def _scan_port(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
) -> tuple[int, bool, str]:
    """Escanea un puerto individual. Retorna (port, abierto, banner)."""
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=_TIMEOUT,
            )
            banner = await _grab_banner(reader, writer)
            writer.close()
            await writer.wait_closed()
            return port, True, banner
        except (TimeoutError, OSError, ConnectionRefusedError):
            return port, False, ""


class PortScanCollector(BaseCollector):
    """Escaneo de puertos TCP comunes con banner grabbing.

    Escanea una lista de puertos comunes contra un host, identificando
    servicios abiertos y obteniendo banners cuando es posible.
    """

    def __init__(self) -> None:
        super().__init__(name="portscan")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        host = target.strip()
        # Si es un dominio, resolver a IP
        try:
            loop = asyncio.get_event_loop()
            addr_info = await loop.getaddrinfo(host, None, socket.AF_INET)
            ip = addr_info[0][4][0] if addr_info else host
        except Exception:
            ip = host

        ports_to_scan = list(_COMMON_PORTS.keys())
        semaphore = asyncio.Semaphore(_CONCURRENCY)

        # Ejecutar escaneo concurrente
        tasks = [_scan_port(ip, port, semaphore) for port in ports_to_scan]
        results = await asyncio.gather(*tasks)

        # Procesar resultados
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        open_ports: list[dict[str, Any]] = []

        # Nodo del host
        host_node = EntityNode.create(
            EntityType.IP_ADDRESS,
            ip,
            f"Host: {ip}",
            attributes={
                "source": "portscan",
                "target": host,
                "ports_scanned": len(ports_to_scan),
            },
        )
        entities.append(host_node)

        for port, is_open, banner in results:
            if is_open:
                service = _COMMON_PORTS.get(port, "unknown")
                port_node = EntityNode.create(
                    EntityType.PORT,
                    f"{ip}:{port}",
                    f"Puerto {port}/{service}",
                    attributes={
                        "source": "portscan",
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "protocol": "tcp",
                    },
                    confidence=0.9 if banner else 0.7,
                )
                entities.append(port_node)
                relations.append(
                    RelationEdge(
                        source_id=host_node.id,
                        target_id=port_node.id,
                        relation_type=RelationType.RUNS_PORT,
                    )
                )
                open_ports.append(
                    {
                        "port": port,
                        "service": service,
                        "banner": banner,
                    }
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "host": host,
            "ip": ip,
            "ports_scanned": len(ports_to_scan),
            "open_ports": len(open_ports),
            "timeout": _TIMEOUT,
            "concurrency": _CONCURRENCY,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "host": host,
                    "ip": ip,
                    "open_ports": open_ports,
                },
                ensure_ascii=False,
            ),
            metadata=metadata,
        )

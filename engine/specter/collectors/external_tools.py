"""
WraithOSINT - External Tools Collectors
Colectores que integran herramientas externas de seguridad vía subprocess.

Cada colector ejecuta la herramienta como subprocess si está instalada.
Si la herramienta no está disponible, retorna requires_tool en metadata.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import Any

from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

logger = logging.getLogger("specter.collectors.external_tools")

_TIMEOUT = 120  # Timeout por defecto para subprocess


async def _run_subprocess(
    cmd: list[str],
    timeout: int = _TIMEOUT,
) -> tuple[int, str, str]:
    """Ejecuta un subprocess de forma async. Retorna (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            proc.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except TimeoutError:
        return -1, "", "Timeout"
    except Exception as exc:
        return -1, "", str(exc)


def _check_tool_installed(tool_name: str) -> str | None:
    """Verifica si una herramienta está instalada. Retorna la ruta o None."""
    return shutil.which(tool_name)


class NmapScannerCollector(BaseCollector):
    """Integración con Nmap para escaneo de puertos y OS fingerprinting.

    Ejecuta nmap como subprocess si está instalado.
    Retorna entidades TCP_PORT_OPEN con banner y servicio.
    Si nmap no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="nmap_scanner")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        nmap_path = _check_tool_installed("nmap")

        if not nmap_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "nmap",
                    "error": "nmap no está instalado en el sistema",
                },
            )

        # Ejecutar nmap con escaneo de puertos y OS detection
        cmd = [nmap_path, "-O", "--osscan-limit", "-sV", "--open", target]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=180)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "nmap",
                    "error": f"nmap falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear salida de nmap
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        open_ports: list[dict[str, Any]] = []
        os_info: str | None = None

        # Nodo del host
        host_node = EntityNode.create(
            EntityType.IP_ADDRESS,
            target,
            f"Host: {target}",
            attributes={"source": "nmap", "tool": "nmap"},
        )
        entities.append(host_node)

        for line in stdout.split("\n"):
            line = line.strip()
            # Detectar puertos abiertos: "22/tcp open ssh OpenSSH 8.2"
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    port = int(port_proto.split("/")[0])
                    service = parts[2]
                    banner = " ".join(parts[3:]) if len(parts) > 3 else ""

                    port_node = EntityNode.create(
                        EntityType.PORT,
                        f"{target}:{port}",
                        f"Puerto {port}/{service}",
                        attributes={
                            "source": "nmap",
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

            # Detectar OS: "OS details: Linux 5.x"
            if "OS details:" in line:
                os_info = line.split("OS details:")[1].strip()
                os_node = EntityNode.create(
                    EntityType.ALIAS,
                    os_info,
                    f"OS: {os_info}",
                    attributes={"source": "nmap", "type": "os_fingerprint"},
                    confidence=0.8,
                )
                entities.append(os_node)
                relations.append(
                    RelationEdge(
                        source_id=host_node.id,
                        target_id=os_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "nmap",
            "target": target,
            "open_ports": len(open_ports),
            "os_detected": os_info,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class NucleiScannerCollector(BaseCollector):
    """Integración con Nuclei para escaneo de vulnerabilidades.

    Ejecuta nuclei como subprocess si está instalado.
    Retorna entidades VULNERABILITY con los hallazgos.
    Si nuclei no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="nuclei_scanner")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        nuclei_path = _check_tool_installed("nuclei")

        if not nuclei_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "nuclei",
                    "error": "nuclei no está instalado en el sistema",
                },
            )

        # Ejecutar nuclei con output JSON
        cmd = [
            nuclei_path,
            "-silent",
            "-json",
            "-concurrency",
            "50",
            "-retries",
            "1",
            "-target",
            target,
        ]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=300)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "nuclei",
                    "error": f"nuclei falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear output JSON de nuclei (JSON lines)
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        vulnerabilities: list[dict[str, Any]] = []

        target_node = EntityNode.create(
            EntityType.DOMAIN if not target[0].isdigit() else EntityType.IP_ADDRESS,
            target,
            f"Target: {target}",
            attributes={"source": "nuclei"},
        )
        entities.append(target_node)

        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = data.get("template-id", "unknown")
            info = data.get("info", {})
            severity = info.get("severity", "unknown")
            name = info.get("name", template_id)
            matched_at = data.get("matched-at", target)

            vuln_node = EntityNode.create(
                EntityType.CVE,
                f"{template_id}:{matched_at}",
                f"{name} ({severity})",
                attributes={
                    "source": "nuclei",
                    "template_id": template_id,
                    "severity": severity,
                    "matched_at": matched_at,
                    "references": info.get("reference", []),
                },
                confidence=0.9 if severity in ("critical", "high") else 0.7,
            )
            entities.append(vuln_node)
            relations.append(
                RelationEdge(
                    source_id=target_node.id,
                    target_id=vuln_node.id,
                    relation_type=RelationType.VULNERABLE_TO,
                )
            )
            vulnerabilities.append(
                {
                    "template_id": template_id,
                    "name": name,
                    "severity": severity,
                    "matched_at": matched_at,
                }
            )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "nuclei",
            "target": target,
            "vulnerabilities_found": len(vulnerabilities),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class WhatWebScannerCollector(BaseCollector):
    """Integración con WhatWeb para identificación de tecnologías web.

    Ejecuta whatweb como subprocess si está instalado.
    Retorna entidades ALIAS con las tecnologías identificadas.
    Si whatweb no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="whatweb_scanner")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        whatweb_path = _check_tool_installed("whatweb")

        if not whatweb_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "whatweb",
                    "error": "whatweb no está instalado en el sistema",
                },
            )

        # Ejecutar whatweb con output JSON
        cmd = [whatweb_path, "--quiet", "--log-json=/dev/stdout", target]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=120)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "whatweb",
                    "error": f"whatweb falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear output JSON de whatweb
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        technologies: list[str] = []

        target_node = EntityNode.create(
            EntityType.DOMAIN if not target[0].isdigit() else EntityType.IP_ADDRESS,
            target,
            f"Target: {target}",
            attributes={"source": "whatweb"},
        )
        entities.append(target_node)

        try:
            result_json = json.loads(stdout)
        except json.JSONDecodeError:
            result_json = []

        if isinstance(result_json, list):
            for result in result_json:
                plugins = result.get("plugins", {})
                for plugin_name, plugin_data in plugins.items():
                    if plugin_name in (
                        "Country",
                        "IP",
                        "Script",
                        "Title",
                        "HTTPServer",
                        "RedirectLocation",
                        "UncommonHeaders",
                        "Via-Proxy",
                        "Cookies",
                        "HttpOnly",
                        "Strict-Transport-Security",
                        "x-hacker",
                        "x-machine",
                        "x-pingback",
                        "X-Backend",
                        "X-Cache",
                        "X-UA-Compatible",
                        "X-Powered-By",
                        "X-Forwarded-For",
                        "X-Frame-Options",
                        "X-XSS-Protection",
                    ):
                        continue

                    strings = plugin_data.get("string", []) if isinstance(plugin_data, dict) else []
                    for tech in strings:
                        tech_str = str(tech)
                        if tech_str and tech_str not in technologies:
                            technologies.append(tech_str)
                            tech_node = EntityNode.create(
                                EntityType.ALIAS,
                                tech_str,
                                f"Tecnología: {tech_str}",
                                attributes={
                                    "source": "whatweb",
                                    "plugin": plugin_name,
                                    "target": target,
                                },
                                confidence=0.8,
                            )
                            entities.append(tech_node)
                            relations.append(
                                RelationEdge(
                                    source_id=target_node.id,
                                    target_id=tech_node.id,
                                    relation_type=RelationType.ASSOCIATED_WITH,
                                )
                            )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "whatweb",
            "target": target,
            "technologies_found": len(technologies),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class WAFW00FDetectorCollector(BaseCollector):
    """Integración con WAFW00F para detección de WAF.

    Ejecuta wafw00f como subprocess si está instalado.
    Retorna entidades ALIAS con el WAF detectado.
    Si wafw00f no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="wafw00f_detector")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        wafw00f_path = _check_tool_installed("wafw00f")

        if not wafw00f_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "wafw00f",
                    "error": "wafw00f no está instalado en el sistema",
                },
            )

        # Ejecutar wafw00f con output JSON
        cmd = [wafw00f_path, "-a", "-o-", "-f", "json", target]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=120)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "wafw00f",
                    "error": f"wafw00f falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear output JSON de wafw00f
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        waf_detected: str | None = None

        target_node = EntityNode.create(
            EntityType.DOMAIN if not target[0].isdigit() else EntityType.IP_ADDRESS,
            target,
            f"Target: {target}",
            attributes={"source": "wafw00f"},
        )
        entities.append(target_node)

        try:
            result_json = json.loads(stdout)
        except json.JSONDecodeError:
            result_json = []

        if isinstance(result_json, list):
            for waf in result_json:
                if not waf:
                    continue
                firewall = waf.get("firewall")
                manufacturer = waf.get("manufacturer")
                if not firewall or firewall == "Generic" or not manufacturer:
                    continue
                software = " ".join(filter(None, [manufacturer, firewall]))
                if software and software != waf_detected:
                    waf_detected = software
                    waf_node = EntityNode.create(
                        EntityType.ALIAS,
                        software,
                        f"WAF: {software}",
                        attributes={
                            "source": "wafw00f",
                            "firewall": firewall,
                            "manufacturer": manufacturer,
                            "target": target,
                        },
                        confidence=0.9,
                    )
                    entities.append(waf_node)
                    relations.append(
                        RelationEdge(
                            source_id=target_node.id,
                            target_id=waf_node.id,
                            relation_type=RelationType.ASSOCIATED_WITH,
                        )
                    )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "wafw00f",
            "target": target,
            "waf_detected": waf_detected,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class CMSeeKDetectorCollector(BaseCollector):
    """Integración con CMSeeK para detección de CMS.

    Ejecuta cmseek como subprocess si está instalado.
    Retorna entidades ALIAS con el CMS detectado.
    Si cmseek no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="cmseek_detector")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        cmseek_path = _check_tool_installed("cmseek")

        if not cmseek_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "cmseek",
                    "error": "cmseek no está instalado en el sistema",
                },
            )

        # Ejecutar cmseek con output JSON
        cmd = [cmseek_path, "--follow-redirect", "--batch", "-u", target]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=180)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "cmseek",
                    "error": f"cmseek falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear output de cmseek
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        cms_detected: str | None = None

        target_node = EntityNode.create(
            EntityType.DOMAIN if not target[0].isdigit() else EntityType.IP_ADDRESS,
            target,
            f"Target: {target}",
            attributes={"source": "cmseek"},
        )
        entities.append(target_node)

        # cmseek output: "CMS: WordPress (version 5.8)" or similar
        for line in stdout.split("\n"):
            line = line.strip()
            if "CMS:" in line or "cms_name" in line.lower():
                # Intentar extraer el CMS del output
                if "CMS:" in line:
                    cms_detected = line.split("CMS:")[1].strip()
                break

        # Si no se encontró en el output, verificar si hay un archivo de resultado
        if not cms_detected:
            # cmseek guarda resultados en Result/<target>/cms.json
            import os

            result_path = f"Result/{target}/cms.json"
            if os.path.isfile(result_path):
                try:
                    with open(result_path, encoding="utf-8") as f:
                        cms_data = json.load(f)
                    cms_name = cms_data.get("cms_name")
                    cms_version = cms_data.get("cms_version")
                    if cms_name:
                        cms_detected = " ".join(filter(None, [cms_name, cms_version]))
                except (json.JSONDecodeError, OSError):
                    pass

        if cms_detected:
            cms_node = EntityNode.create(
                EntityType.ALIAS,
                cms_detected,
                f"CMS: {cms_detected}",
                attributes={
                    "source": "cmseek",
                    "target": target,
                },
                confidence=0.9,
            )
            entities.append(cms_node)
            relations.append(
                RelationEdge(
                    source_id=target_node.id,
                    target_id=cms_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "cmseek",
            "target": target,
            "cms_detected": cms_detected,
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class TruffleHogScannerCollector(BaseCollector):
    """Integración con TruffleHog para búsqueda de secretos en repositorios.

    Ejecuta trufflehog como subprocess si está instalado.
    Retorna entidades ALIAS con los secretos encontrados.
    Si trufflehog no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="trufflehog_scanner")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        trufflehog_path = _check_tool_installed("trufflehog")

        if not trufflehog_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "trufflehog",
                    "error": "trufflehog no está instalado en el sistema",
                },
            )

        # Ejecutar trufflehog con output JSON
        cmd = [trufflehog_path, "--json", "--regex", target]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=300)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "trufflehog",
                    "error": f"trufflehog falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parser output JSON de trufflehog (JSON lines)
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        secrets_found: list[dict[str, Any]] = []

        target_node = EntityNode.create(
            EntityType.ALIAS,
            target,
            f"Repo: {target}",
            attributes={"source": "trufflehog"},
        )
        entities.append(target_node)

        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extraer información del secreto
            detector = row.get("DetectorName", "unknown")
            source = row.get("SourceMetadata", {})
            data = source.get("Data", "") if isinstance(source, dict) else ""
            raw = row.get("Raw", "")

            secret_desc = f"{detector}: {data[:100]}" if data else detector
            secret_node = EntityNode.create(
                EntityType.ALIAS,
                secret_desc,
                f"Secreto: {detector}",
                attributes={
                    "source": "trufflehog",
                    "detector": detector,
                    "data": data[:200] if data else "",
                    "raw": raw[:200] if raw else "",
                    "target": target,
                },
                confidence=0.8,
            )
            entities.append(secret_node)
            relations.append(
                RelationEdge(
                    source_id=target_node.id,
                    target_id=secret_node.id,
                    relation_type=RelationType.ASSOCIATED_WITH,
                )
            )
            secrets_found.append(
                {
                    "detector": detector,
                    "data": data[:100] if data else "",
                }
            )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "trufflehog",
            "target": target,
            "secrets_found": len(secrets_found),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class RetireJSScannerCollector(BaseCollector):
    """Integración con Retire.js para detección de vulnerabilidades JS.

    Ejecuta retire.js como subprocess si está instalado.
    Retorna entidades VULNERABILITY con las vulnerabilidades JS.
    Si retire.js no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="retirejs_scanner")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        retire_path = _check_tool_installed("retire")

        if not retire_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "retire",
                    "error": "retire.js no está instalado en el sistema",
                },
            )

        # Ejecutar retire.js con output JSON
        cmd = [retire_path, "--outputformat", "json", "--path", target]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=120)

        # retire.js retorna 0 o 13 (13 = vulnerabilidades encontradas)
        if returncode not in (0, 13):
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "retire",
                    "error": f"retire.js falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear output JSON de retire.js
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        vulnerabilities: list[dict[str, Any]] = []

        target_node = EntityNode.create(
            EntityType.DOMAIN if not target[0].isdigit() else EntityType.IP_ADDRESS,
            target,
            f"Target: {target}",
            attributes={"source": "retirejs"},
        )
        entities.append(target_node)

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            data = {}

        for item in data.get("data", []):
            for result in item.get("results", []):
                for vuln in result.get("vulnerabilities", []):
                    identifiers = vuln.get("identifiers", {})
                    severity = vuln.get("severity", "unknown")
                    summary = identifiers.get("summary", "Unknown vulnerability")
                    cve_list = identifiers.get("CVE", [])

                    vuln_id = cve_list[0] if cve_list else summary
                    vuln_node = EntityNode.create(
                        EntityType.CVE,
                        f"{vuln_id}:{target}",
                        f"JS Vuln: {summary} ({severity})",
                        attributes={
                            "source": "retirejs",
                            "severity": severity,
                            "summary": summary,
                            "cve": cve_list,
                            "target": target,
                        },
                        confidence=0.9 if severity in ("critical", "high") else 0.7,
                    )
                    entities.append(vuln_node)
                    relations.append(
                        RelationEdge(
                            source_id=target_node.id,
                            target_id=vuln_node.id,
                            relation_type=RelationType.VULNERABLE_TO,
                        )
                    )
                    vulnerabilities.append(
                        {
                            "summary": summary,
                            "severity": severity,
                            "cve": cve_list,
                        }
                    )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "retirejs",
            "target": target,
            "vulnerabilities_found": len(vulnerabilities),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class TestSSLScannerCollector(BaseCollector):
    """Integración con testssl.sh para análisis de TLS/SSL.

    Ejecuta testssl.sh como subprocess si está instalado.
    Retorna entidades VULNERABILITY con las vulnerabilidades TLS.
    Si testssl.sh no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="testssl_scanner")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        testssl_path = _check_tool_installed("testssl.sh")

        if not testssl_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "testssl.sh",
                    "error": "testssl.sh no está instalado en el sistema",
                },
            )

        # Ejecutar testssl.sh con output JSON
        cmd = [
            testssl_path,
            "-U",
            "--connect-timeout",
            "5",
            "--openssl-timeout",
            "5",
            "--severity",
            "LOW",
            "--jsonfile",
            "/dev/stdout",
            target,
        ]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=300)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "testssl.sh",
                    "error": f"testssl.sh falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear output JSON de testssl.sh
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        vulnerabilities: list[dict[str, Any]] = []

        target_node = EntityNode.create(
            EntityType.DOMAIN if not target[0].isdigit() else EntityType.IP_ADDRESS,
            target,
            f"Target: {target}",
            attributes={"source": "testssl"},
        )
        entities.append(target_node)

        try:
            result_json = json.loads(stdout)
        except json.JSONDecodeError:
            result_json = []

        if isinstance(result_json, list):
            for result in result_json:
                finding = result.get("finding", "")
                if finding == "not vulnerable":
                    continue

                severity = result.get("severity", "unknown")
                if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    continue

                vuln_id = result.get("id", finding)
                cve = result.get("cve", "")

                vuln_node = EntityNode.create(
                    EntityType.CVE,
                    f"{vuln_id}:{target}",
                    f"TLS Vuln: {finding} ({severity})",
                    attributes={
                        "source": "testssl",
                        "severity": severity,
                        "finding": finding,
                        "cve": cve,
                        "target": target,
                    },
                    confidence=0.9 if severity in ("critical", "high") else 0.7,
                )
                entities.append(vuln_node)
                relations.append(
                    RelationEdge(
                        source_id=target_node.id,
                        target_id=vuln_node.id,
                        relation_type=RelationType.VULNERABLE_TO,
                    )
                )
                vulnerabilities.append(
                    {
                        "id": vuln_id,
                        "finding": finding,
                        "severity": severity,
                        "cve": cve,
                    }
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "testssl",
            "target": target,
            "vulnerabilities_found": len(vulnerabilities),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )


class SnallygasterScannerCollector(BaseCollector):
    """Integración con snallygaster para búsqueda de archivos expuestos.

    Ejecuta snallygaster como subprocess si está instalado.
    Retorna entidades ALIAS con los archivos expuestos.
    Si snallygaster no está instalado, retorna requires_tool.
    """

    def __init__(self) -> None:
        super().__init__(name="snallygaster_scanner")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        target = target.strip()
        snallygaster_path = _check_tool_installed("snallygaster")

        if not snallygaster_path:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=None,
                metadata={
                    "ok": False,
                    "requires_tool": "snallygaster",
                    "error": "snallygaster no está instalado en el sistema",
                },
            )

        # Ejecutar snallygaster con output JSON
        cmd = [snallygaster_path, "--nowww", "-j", target]
        returncode, stdout, stderr = await _run_subprocess(cmd, timeout=300)

        if returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                source_target=target,
                entities=[],
                relations=[],
                raw_payload=stdout,
                metadata={
                    "ok": False,
                    "requires_tool": "snallygaster",
                    "error": f"snallygaster falló (rc={returncode}): {stderr[:200]}",
                },
            )

        # Parsear output JSON de snallygaster
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        exposed_files: list[dict[str, Any]] = []

        target_node = EntityNode.create(
            EntityType.DOMAIN if not target[0].isdigit() else EntityType.IP_ADDRESS,
            target,
            f"Target: {target}",
            attributes={"source": "snallygaster"},
        )
        entities.append(target_node)

        try:
            result_json = json.loads(stdout)
        except json.JSONDecodeError:
            result_json = []

        if isinstance(result_json, list):
            for res in result_json:
                if "cause" not in res:
                    continue

                cause = res.get("cause", "unknown")
                url = res.get("url", "")
                misc = res.get("misc", "")

                file_node = EntityNode.create(
                    EntityType.ALIAS,
                    url or cause,
                    f"Archivo expuesto: {cause}",
                    attributes={
                        "source": "snallygaster",
                        "cause": cause,
                        "url": url,
                        "misc": misc,
                        "target": target,
                    },
                    confidence=0.8,
                )
                entities.append(file_node)
                relations.append(
                    RelationEdge(
                        source_id=target_node.id,
                        target_id=file_node.id,
                        relation_type=RelationType.EXPOSED_IN,
                    )
                )
                exposed_files.append(
                    {
                        "cause": cause,
                        "url": url,
                    }
                )

        metadata: dict[str, Any] = {
            "ok": True,
            "tool": "snallygaster",
            "target": target,
            "exposed_files": len(exposed_files),
        }

        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=entities,
            relations=relations,
            raw_payload=stdout,
            metadata=metadata,
        )

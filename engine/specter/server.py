"""
SpecterOSINT - FastMCP Server
Servidor MCP profesional para OpenCode AI con capacidades forenses, grafos y cadena de custodia.
"""

import asyncio
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from specter import browser_osint
from specter import config as specter_config
from specter import triage as artifact_triage
from specter.collectors.artifacts import FileForensics
from specter.collectors.dorker import DocumentHunter
from specter.collectors.github_forensics import GitHubForensics
from specter.collectors.identity import EmailInvestigator, UsernameInvestigator
from specter.collectors.network import CrtShCollector, DNSCollector, IPEnricher, TLSCollector
from specter.collectors.person import PersonInvestigator
from specter.collectors.registry import CollectorRegistry
from specter.collectors.threatintel import (
    AbuseIPDBCollector,
    GreyNoiseCollector,
    HackertargetCollector,
    HunterCollector,
    InternetDBCollector,
    ShodanCollector,
    ThreatFoxCollector,
    UrlscanCollector,
    VirusTotalCollector,
    WaybackCollector,
)
from specter.collectors.web import WebFetchCollector, WebSearchCollector
from specter.osint_core.correlation import CorrelationEngine
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.ledger import ForensicLedger
from specter.osint_core.models import (
    CaseMetadata,
    EntityType,
    RawEvidence,
    RelationEdge,
    RelationType,
)
from specter.osint_core.timeline import CaseTimeline
from specter.visualizer.exporter import DossierExporter

# Inicialización del servidor MCP y servicios core
# Las rutas se resuelven vía specter.config (env vars → repo root), de modo
# que la app empaquetada y los tests puedan redirigir el almacenamiento.
mcp_server = MCPServer(name="specter-osint")
db = Database(specter_config.database_path())
ledger = ForensicLedger(db)
graph = OSINTGraph(db)
exporter = DossierExporter(db)
correlation = CorrelationEngine(db)
timeline_engine = CaseTimeline(db)


def reset_services(db_path: str | Path | None = None) -> Database:
    """Reconstruye los servicios core contra una ruta de BD.

    Seam de testabilidad: los handlers de tools leen estos globals en cada
    llamada, así que reasignarlos aquí redirige todo el kernel. En producción
    no se usa (una sola inicialización al importar).
    """
    global db, ledger, graph, exporter, correlation, timeline_engine
    db = Database(Path(db_path) if db_path else specter_config.database_path())
    ledger = ForensicLedger(db)
    graph = OSINTGraph(db)
    exporter = DossierExporter(db)
    correlation = CorrelationEngine(db)
    timeline_engine = CaseTimeline(db)
    return db


# Colectores
# Los built-ins se registran en un catálogo único: las tools curadas siguen
# usándolos directamente, y `run_collector` permite invocar *cualquiera* del
# catálogo (incluidos los plugins externos descubiertos por entry-points).
dns_collector = DNSCollector()
crt_sh_collector = CrtShCollector()
tls_collector = TLSCollector()
ip_enricher = IPEnricher()
username_collector = UsernameInvestigator()
email_collector = EmailInvestigator()
file_forensics = FileForensics()
document_hunter = DocumentHunter()
github_forensics = GitHubForensics()
person_collector = PersonInvestigator()
web_search_collector = WebSearchCollector()
web_fetch_collector = WebFetchCollector()
# Fase A Maltego-gap (fuentes gratuitas sin key): reputación y exposición.
internetdb_collector = InternetDBCollector()
threatfox_collector = ThreatFoxCollector()
urlscan_collector = UrlscanCollector()
hackertarget_collector = HackertargetCollector()
wayback_collector = WaybackCollector()
# Fase B (con key de la bóveda; sin key se omiten en silencio).
virustotal_collector = VirusTotalCollector()
shodan_collector = ShodanCollector()
greynoise_collector = GreyNoiseCollector()
abuseipdb_collector = AbuseIPDBCollector()
hunter_collector = HunterCollector()

collectors = CollectorRegistry()
for _collector in (
    dns_collector,
    crt_sh_collector,
    tls_collector,
    ip_enricher,
    username_collector,
    email_collector,
    file_forensics,
    document_hunter,
    github_forensics,
    person_collector,
    web_search_collector,
    web_fetch_collector,
    internetdb_collector,
    threatfox_collector,
    urlscan_collector,
    hackertarget_collector,
    wayback_collector,
    virustotal_collector,
    shodan_collector,
    greynoise_collector,
    abuseipdb_collector,
    hunter_collector,
):
    collectors.register(_collector)


async def _ingest_evidence(
    case_id: str, collector: Any, target: str, action: str, source_url: str
) -> tuple[Any, RawEvidence]:
    """Atajo Fase A: collect + ingesta al grafo + sello en el ledger."""
    res = await collector.collect(target)
    graph.ingest_collector_result(case_id, res)
    raw_ev = RawEvidence(
        id=f"ev-{collector.name}-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=collector.name,
        source_url=source_url,
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=dict(res.metadata or {}),
    )
    ledger.record_evidence_action(case_id, collector.name, f"{action}: {target}", raw_ev)
    return res, raw_ev


# --- Herramientas de Gestión de Casos ---


@mcp_server.tool()
def create_case(name: str, description: str, investigator: str = "Analista_Specter") -> str:
    """
    Crea un caso formal de investigación OSINT e inicializa el bloque Génesis de la cadena de custodia.
    """
    case_uuid = f"case-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    case = CaseMetadata(
        case_id=case_uuid,
        name=name,
        description=description,
        investigator=investigator,
    )
    db.create_case(case)
    genesis_block = ledger.initialize_case_genesis(case)

    return json.dumps(
        {
            "status": "CASE_CREATED",
            "case_id": case.case_id,
            "name": case.name,
            "investigator": case.investigator,
            "genesis_hash": genesis_block.block_hash,
            "message": f"Caso inicializado formalmente con hash génesis {genesis_block.block_hash[:16]}...",
        },
        indent=2,
    )


@mcp_server.tool()
def list_cases() -> str:
    """
    Lista todos los casos de investigación forense activos y archivados.
    """
    cases = db.list_cases()
    return json.dumps([c.model_dump() for c in cases], indent=2)


# --- Herramientas de Investigación de Red ---


@mcp_server.tool()
async def investigate_domain(case_id: str, domain: str) -> str:
    """
    Ejecuta resolución DNS forense profunda (A, AAAA, MX, NS, TXT, DMARC) e inspección TLS/SSL,
    insertando las entidades y relaciones en el grafo y asegurando la evidencia en el ledger inmutable.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    # 1. DNS
    dns_res = await dns_collector.collect(domain)
    graph.ingest_collector_result(case_id, dns_res)
    raw_ev_dns = RawEvidence(
        id=f"ev-dns-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=dns_collector.name,
        source_url=f"dns://{domain}",
        raw_payload=dns_res.raw_payload or "{}",
        payload_hash="auto",
        metadata={"entities": len(dns_res.entities)},
    )
    ledger.record_evidence_action(
        case_id, dns_collector.name, f"DNS_ENUMERATION: {domain}", raw_ev_dns
    )

    # 2. TLS/SSL
    tls_res = await tls_collector.collect(domain)
    graph.ingest_collector_result(case_id, tls_res)
    raw_ev_tls = RawEvidence(
        id=f"ev-tls-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=tls_collector.name,
        source_url=f"tls://{domain}:443",
        raw_payload=tls_res.raw_payload or "{}",
        payload_hash="auto",
        metadata={"entities": len(tls_res.entities)},
    )
    ledger.record_evidence_action(
        case_id, tls_collector.name, f"TLS_INSPECTION: {domain}", raw_ev_tls
    )

    # Fase A (fuentes gratuitas sin key): reputación ThreatFox, URLs observadas
    # (urlscan) e historial Wayback. Cada una sella su propia evidencia.
    extra: dict[str, Any] = {}
    for collector, action, source in (
        (threatfox_collector, "IOC_REPUTATION", f"threatfox://{domain}"),
        (urlscan_collector, "URL_OBSERVED", f"urlscan://{domain}"),
        (wayback_collector, "URL_HISTORY", f"wayback://{domain}"),
        (virustotal_collector, "VT_REPUTATION", f"virustotal://{domain}"),
    ):
        try:
            res, ev = await _ingest_evidence(case_id, collector, domain, action, source)
            extra[collector.name] = {
                "entities": len(res.entities),
                "evidence_hash": ev.payload_hash,
                "meta": res.metadata,
            }
        except Exception as exc:
            extra[collector.name] = {"error": str(exc)[:200]}

    return json.dumps(
        {
            "status": "COMPLETED",
            "domain": domain,
            "dns_entities_found": len(dns_res.entities),
            "tls_entities_found": len(tls_res.entities),
            "evidence_hashes": {
                "dns": raw_ev_dns.payload_hash,
                "tls": raw_ev_tls.payload_hash,
            },
            "threat_intel": extra,
        },
        indent=2,
    )


@mcp_server.tool()
async def enumerate_subdomains(case_id: str, domain: str) -> str:
    """
    Descubre subdominios pasivamente a través de Certificate Transparency (crt.sh),
    vinculándolos como relaciones SUBDOMAIN_OF en el grafo forense.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    res = await crt_sh_collector.collect(domain)
    graph.ingest_collector_result(case_id, res)

    raw_ev = RawEvidence(
        id=f"ev-crtsh-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=crt_sh_collector.name,
        source_url=f"https://crt.sh/?q=%.{domain}&output=json",
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=res.metadata,
    )
    ledger.record_evidence_action(
        case_id, crt_sh_collector.name, f"SUBDOMAIN_ENUM: {domain}", raw_ev
    )

    subdomains = [e.value for e in res.entities if e.type == EntityType.SUBDOMAIN]
    return json.dumps(
        {
            "status": "COMPLETED",
            "domain": domain,
            "subdomains_found": len(subdomains),
            "subdomains": subdomains[:30],
            "evidence_hash": raw_ev.payload_hash,
        },
        indent=2,
    )


@mcp_server.tool()
async def investigate_ip(case_id: str, ip: str) -> str:
    """
    Investiga una dirección IP: realiza resolución inversa PTR y consulta pasiva RDAP para extraer
    organización, proveedor y país, vinculándolo en el grafo.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    res = await ip_enricher.collect(ip)
    graph.ingest_collector_result(case_id, res)

    raw_ev = RawEvidence(
        id=f"ev-ip-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=ip_enricher.name,
        source_url=f"rdap://{ip}",
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=res.metadata,
    )
    ledger.record_evidence_action(case_id, ip_enricher.name, f"IP_ENRICHMENT: {ip}", raw_ev)

    # Fase A (fuentes gratuitas sin key): exposición Shodan, reputación
    # ThreatFox y co-hospedaje. Cada una sella su propia evidencia.
    extra: dict[str, Any] = {}
    for collector, action, source in (
        (internetdb_collector, "IP_EXPOSURE", f"internetdb://{ip}"),
        (threatfox_collector, "IOC_REPUTATION", f"threatfox://{ip}"),
        (hackertarget_collector, "REVERSE_IP", f"hackertarget://{ip}"),
        (virustotal_collector, "VT_REPUTATION", f"virustotal://{ip}"),
        (shodan_collector, "SHODAN_HOST", f"shodan://{ip}"),
        (greynoise_collector, "GREYNOISE_RIOT", f"greynoise://{ip}"),
        (abuseipdb_collector, "ABUSE_SCORE", f"abuseipdb://{ip}"),
    ):
        try:
            res, ev = await _ingest_evidence(case_id, collector, ip, action, source)
            extra[collector.name] = {
                "entities": len(res.entities),
                "evidence_hash": ev.payload_hash,
                "meta": res.metadata,
            }
        except Exception as exc:
            extra[collector.name] = {"error": str(exc)[:200]}

    return json.dumps(
        {
            "status": "COMPLETED",
            "ip": ip,
            "entities_identified": [e.value for e in res.entities],
            "evidence_hash": raw_ev.payload_hash,
            "threat_intel": extra,
        },
        indent=2,
    )


# --- Herramientas de Identidad & Huella Digital ---


@mcp_server.tool()
async def investigate_identity(case_id: str, username: str) -> str:
    """
    Investigación exhaustiva de identidad digital:
    - Sondea más de 700 plataformas públicas (WhatsMyName + Sherlock) con normalización Unicode (fraktur/homoglifos).
    - Si detecta un perfil en GitHub, realiza automáticamente minería forense de repositorios, commits y Discord.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    # 1. Escaneo de Plataformas y Alias
    res = await username_collector.collect(username)
    graph.ingest_collector_result(case_id, res)

    raw_ev = RawEvidence(
        id=f"ev-ident-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=username_collector.name,
        source_url=f"profiles://{username}",
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=res.metadata,
    )
    ledger.record_evidence_action(
        case_id, username_collector.name, f"ALIAS_ENUM: {username}", raw_ev
    )

    confirmed_profiles = [
        e.attributes.get("url") for e in res.entities if e.type == EntityType.SOCIAL_PROFILE
    ]

    # 2. Si se detectó perfil en GitHub, ejecutar automáticamente análisis forense profundo
    github_profile = next((url for url in confirmed_profiles if "github.com" in url.lower()), None)
    github_forensics_data = None
    if github_profile:
        gh_user = username.strip().lstrip("@")
        gh_res = await github_forensics.collect(gh_user)
        graph.ingest_collector_result(case_id, gh_res)

        gh_ev = RawEvidence(
            id=f"ev-gh-{uuid.uuid4().hex[:8]}",
            case_id=case_id,
            collector=github_forensics.name,
            source_url=github_profile,
            raw_payload=gh_res.raw_payload or "{}",
            payload_hash="auto",
            metadata=gh_res.metadata,
        )
        ledger.record_evidence_action(
            case_id, github_forensics.name, f"GITHUB_DEEP_FORENSICS: {gh_user}", gh_ev
        )
        github_forensics_data = gh_res.metadata

    return json.dumps(
        {
            "status": "COMPLETED",
            "username": username,
            "platforms_checked": res.metadata.get("platforms_checked"),
            "profiles_found": len(confirmed_profiles),
            "profiles": confirmed_profiles,
            "github_forensics": github_forensics_data,
            "evidence_hash": raw_ev.payload_hash,
        },
        indent=2,
    )


@mcp_server.tool()
async def investigate_person(
    case_id: str,
    full_name: str,
    pivot_usernames: bool = False,
    execute_search: bool = True,
) -> str:
    """
    Huella digital de un nombre completo:
    - Registra a la persona en el grafo y deriva candidatos de username
      (ana.delacruz, adelacruz, ...) como entidades ALIAS conectadas.
    - Genera dorks de documentos de identidad (DNI/NIE/pasaporte/CUIT + nombre
      en filtraciones indexadas) y dorks de presencia pública.
    - Si `execute_search=True` (por defecto), realiza búsqueda activa vía el motor
      de navegación Chromium sigiloso enriqueciendo el grafo con instituciones y documentos.
    - Si `pivot_usernames=True`, sondea los 3 primeros candidatos con el investigator
      de usernames (~700 plataformas) y enlaza perfiles confirmados a la persona.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    res = await person_collector.collect(full_name, execute_search=execute_search)
    graph.ingest_collector_result(case_id, res)

    raw_ev = RawEvidence(
        id=f"ev-person-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=person_collector.name,
        source_url=f"person://{full_name}",
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=res.metadata,
    )
    ledger.record_evidence_action(
        case_id, person_collector.name, f"PERSON_FOOTPRINT: {full_name}", raw_ev
    )

    alias_values = [e.value for e in res.entities if e.type == EntityType.ALIAS]
    pivots: list[dict[str, Any]] = []
    if pivot_usernames:
        for candidate in alias_values[:3]:
            pivot_res = await username_collector.collect(candidate)
            graph.ingest_collector_result(case_id, pivot_res)
            profiles = [
                e.attributes.get("url")
                for e in pivot_res.entities
                if e.type == EntityType.SOCIAL_PROFILE
            ]
            pivots.append(
                {
                    "username": candidate,
                    "profiles_found": len(profiles),
                    "profiles": profiles,
                }
            )
        if pivots:
            pivot_ev = RawEvidence(
                id=f"ev-person-pivot-{uuid.uuid4().hex[:8]}",
                case_id=case_id,
                collector=username_collector.name,
                source_url=f"person-pivots://{full_name}",
                raw_payload=json.dumps(pivots, ensure_ascii=False),
                payload_hash="auto",
                metadata={"pivots": len(pivots)},
            )
            ledger.record_evidence_action(
                case_id,
                username_collector.name,
                f"PERSON_PIVOT_ENUM: {full_name}",
                pivot_ev,
            )

    return json.dumps(
        {
            "status": "COMPLETED",
            "full_name": full_name,
            "derived_usernames": alias_values,
            "dorks": res.metadata.get("dorks", {}),
            "name_structure": res.metadata.get("name_structure", {}),
            "username_pivots": pivots,
            "evidence_hash": raw_ev.payload_hash,
        },
        indent=2,
    )


@mcp_server.tool()
def triage_entity(artifact: str) -> str:
    """
    Clasificación automática de un artefacto crudo (entrada libre del analista):
    email, IPv4/IPv6, dominio, subdominio, DNI/NIE/CUIT/RUT, teléfono, hash de
    archivo, nombre de persona o username. Devuelve el tipo de entidad y la
    tool de investigación recomendada con sus argumentos listos para invocar.
    """
    verdict = artifact_triage.triage_artifact(artifact)
    return json.dumps(
        {
            "artifact": verdict.artifact,
            "entity_type": verdict.entity_type.value,
            "recommended_tool": verdict.tool,
            "arguments": verdict.args,
            "notes": verdict.notes,
        },
        indent=2,
    )


@mcp_server.tool()
async def hunt_documents_and_leaks(case_id: str, target: str) -> str:
    """
    Caza pasiva de documentos (PDF, DOCX) y menciones de filtraciones (Pastebin, Rentry, leaks):
    Busca documentos asociados al objetivo, los descarga e inspecciona automáticamente con FileForensics
    extrayendo hashes (MD5/SHA1/SHA256) y metadatos de autor, software y fechas en el grafo.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    res = await document_hunter.collect(target)
    graph.ingest_collector_result(case_id, res)

    raw_ev = RawEvidence(
        id=f"ev-hunt-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=document_hunter.name,
        source_url=f"dork://{target}",
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=res.metadata,
    )
    ledger.record_evidence_action(
        case_id, document_hunter.name, f"DOCUMENT_AND_LEAK_HUNT: {target}", raw_ev
    )

    pdfs = [
        e.attributes.get("filename") or e.value
        for e in res.entities
        if e.type == EntityType.FILE_ARTIFACT
    ]
    mentions = [
        e.attributes.get("url")
        for e in res.entities
        if e.type in (EntityType.SOCIAL_PROFILE, EntityType.DOMAIN)
        and e.attributes.get("source") == "DuckDuckGo Intelligence"
    ]

    return json.dumps(
        {
            "status": "COMPLETED",
            "target": target,
            "pdfs_analyzed": len(pdfs),
            "pdf_artifacts": pdfs,
            "web_mentions_found": len(mentions),
            "web_mentions": mentions[:10],
            "evidence_hash": raw_ev.payload_hash,
        },
        indent=2,
    )


@mcp_server.tool()
async def deep_investigate_github(case_id: str, username: str) -> str:
    """
    Extracción forense especializada en GitHub:
    - Minería de repositorios públicos y commits para descubrir direcciones de email privadas o de trabajo.
    - Extracción de enlaces externos a Discord, servidores o portales en READMEs/descripciones.
    - Extracción de claves públicas SSH.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    gh_user = username.strip().lstrip("@")
    gh_res = await github_forensics.collect(gh_user)
    graph.ingest_collector_result(case_id, gh_res)

    gh_ev = RawEvidence(
        id=f"ev-gh-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=github_forensics.name,
        source_url=f"https://github.com/{gh_user}",
        raw_payload=gh_res.raw_payload or "{}",
        payload_hash="auto",
        metadata=gh_res.metadata,
    )
    ledger.record_evidence_action(
        case_id, github_forensics.name, f"GITHUB_DEEP_FORENSICS: {gh_user}", gh_ev
    )

    return json.dumps(
        {
            "status": "COMPLETED",
            "username": gh_user,
            "metadata": gh_res.metadata,
            "entities_created": len(gh_res.entities),
            "evidence_hash": gh_ev.payload_hash,
        },
        indent=2,
    )


@mcp_server.tool()
async def investigate_email(case_id: str, email: str) -> str:
    """
    Analiza una dirección de correo: valida sintaxis, comprueba dominios desechables,
    resuelve servidores MX y genera huellas de filtración/Gravatar.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    res = await email_collector.collect(email)
    graph.ingest_collector_result(case_id, res)

    raw_ev = RawEvidence(
        id=f"ev-email-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=email_collector.name,
        source_url=f"email://{email}",
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=res.metadata,
    )
    ledger.record_evidence_action(case_id, email_collector.name, f"EMAIL_ANALYSIS: {email}", raw_ev)

    # Fase B (con key): verificación Hunter.io. Sin key se omite en silencio.
    extra: dict[str, Any] = {}
    try:
        res_h, ev_h = await _ingest_evidence(
            case_id, hunter_collector, email, "EMAIL_VERIFY", f"hunter://{email}"
        )
        extra[hunter_collector.name] = {
            "entities": len(res_h.entities),
            "evidence_hash": ev_h.payload_hash,
            "meta": res_h.metadata,
        }
    except Exception as exc:
        extra[hunter_collector.name] = {"error": str(exc)[:200]}

    return json.dumps(
        {
            "status": "COMPLETED",
            "email": email,
            "entities_created": len(res.entities),
            "evidence_hash": raw_ev.payload_hash,
            "threat_intel": extra,
        },
        indent=2,
    )


# --- Herramientas Forenses de Archivos ---


@mcp_server.tool()
async def analyze_file_metadata(case_id: str, target: str) -> str:
    """
    Extrae hashes forenses (MD5, SHA1, SHA256) y metadatos EXIF/GPS de imágenes o metadatos de autor de PDFs
    a partir de una ruta de archivo local o URL.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    res = await file_forensics.collect(target)
    graph.ingest_collector_result(case_id, res)

    raw_ev = RawEvidence(
        id=f"ev-file-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=file_forensics.name,
        source_url=target,
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata=res.metadata,
    )
    ledger.record_evidence_action(
        case_id, file_forensics.name, f"FILE_METADATA_ANALYSIS: {Path(target).name}", raw_ev
    )

    file_node = next((e for e in res.entities if e.type == EntityType.FILE_ARTIFACT), None)
    sha256 = file_node.attributes.get("hashes", {}).get("sha256") if file_node else None

    # Fase B (con key): reputación del hash en VirusTotal. Sin key se omite.
    vt_status: dict[str, Any] = {}
    if sha256:
        try:
            res_vt, ev_vt = await _ingest_evidence(
                case_id, virustotal_collector, sha256, "VT_FILE", f"virustotal://{sha256}"
            )
            vt_status = {
                "entities": len(res_vt.entities),
                "evidence_hash": ev_vt.payload_hash,
                "meta": res_vt.metadata,
            }
        except Exception as exc:
            vt_status = {"error": str(exc)[:200]}

    return json.dumps(
        {
            "status": "COMPLETED",
            "target": target,
            "sha256": sha256,
            "gps": next(
                (
                    e.attributes.get("google_maps")
                    for e in res.entities
                    if e.type == EntityType.GEO_LOCATION
                ),
                None,
            ),
            "author": next((e.value for e in res.entities if e.type == EntityType.PERSON), None),
            "evidence_hash": raw_ev.payload_hash,
            "virustotal": vt_status,
        },
        indent=2,
    )


# --- Herramientas de Correlación y Grafo ---


@mcp_server.tool()
def link_entities(
    case_id: str,
    source_id: str,
    target_id: str,
    relation_type: str,
    confidence: float = 1.0,
    rationale: str = "Correlación manual del analista",
) -> str:
    """
    Vincula manualmente dos entidades existentes en el grafo con una relación tipada y justificación forense.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    try:
        rel_type_enum = RelationType(relation_type.upper())
    except ValueError:
        return json.dumps(
            {
                "error": f"Tipo de relación inválido: {relation_type}",
                "valid_types": [r.value for r in RelationType],
            }
        )

    rel = RelationEdge(
        source_id=source_id,
        target_id=target_id,
        relation_type=rel_type_enum,
        confidence=confidence,
        attributes={"rationale": rationale},
    )
    db.upsert_relations(case_id, [rel])
    ledger.record_evidence_action(
        case_id,
        "analyst",
        f"MANUAL_LINK: {source_id} -> {rel_type_enum.value} -> {target_id} ({rationale})",
    )

    return json.dumps(
        {
            "status": "LINK_CREATED",
            "edge_id": rel.edge_id,
            "confidence": confidence,
        },
        indent=2,
    )


@mcp_server.tool()
def query_graph(
    case_id: str,
    search_term: str | None = None,
    entity_type: str | None = None,
    center_id: str | None = None,
    max_depth: int = 2,
) -> str:
    """
    Consulta el grafo del caso: busca subgrafos, filtra por tipo de entidad o expande los vecinos de un nodo central.
    """
    subgraph = graph.query_subgraph(
        case_id=case_id,
        search_term=search_term,
        entity_type=entity_type,
        center_id=center_id,
        max_depth=max_depth,
    )
    return json.dumps(subgraph, indent=2)


@mcp_server.tool()
def analyze_network_metrics(case_id: str) -> str:
    """
    Calcula métricas de red avanzadas sobre el grafo: nodos con mayor influencia (PageRank),
    puntos de articulación/puente (Betweenness) y densidad general de la infraestructura.
    """
    metrics = graph.analyze_metrics(case_id)
    return json.dumps(metrics, indent=2)


@mcp_server.tool()
def find_entity_path(case_id: str, source_id: str, target_id: str) -> str:
    """
    Camino más corto entre dos entidades del caso (pivote Maltego): devuelve la
    cadena de nodos que las conecta, o vacío si no hay ruta.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})
    path = graph.find_shortest_path(case_id, source_id, target_id)
    return json.dumps(
        {
            "status": "COMPLETED",
            "case_id": case_id,
            "source_id": source_id,
            "target_id": target_id,
            "hops": (len(path) - 1) if path else None,
            "path": path or [],
        },
        indent=2,
    )


@mcp_server.tool()
def suggest_identity_links(case_id: str, min_score: float = 0.7, limit: int = 20) -> str:
    """
    Candidatos de resolución de identidad (solo lectura): pares de entidades
    que probablemente son la misma persona/alias, con score y motivo. El
    agente los confirma con link_entities; nada se escribe solo.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})
    report = correlation.identity_candidates(
        case_id, min_score=max(0.0, min(1.0, min_score)), limit=max(1, min(limit, 100))
    )
    return json.dumps({"status": "COMPLETED", **report}, indent=2)


@mcp_server.tool()
def compare_cases(case_a: str, case_b: str) -> str:
    """
    Similitud entre dos casos (Jaccard + veredicto NONE/MODERATE/HIGH): revela
    si dos investigaciones tocan la misma infraestructura o identidad.
    """
    for cid in (case_a, case_b):
        if not db.get_case(cid):
            return json.dumps({"error": f"Caso {cid} no existe"})
    report = correlation.case_similarity(case_a, case_b)
    return json.dumps({"status": "COMPLETED", **report}, indent=2)


# --- Herramientas de Integridad y Reportes ---


# --- Herramientas de Colectores (built-ins + plugins) ---


@mcp_server.tool()
def list_collectors() -> str:
    """
    Lista el catálogo de colectores disponibles: los del kernel y los plugins de terceros
    descubiertos por entry-points (`specter.collectors`).
    """
    return json.dumps(
        {
            "total": len(collectors),
            "collectors": collectors.describe(),
            "errors": collectors.errors,
        },
        indent=2,
    )


@mcp_server.tool()
async def run_collector(case_id: str, collector: str, target: str) -> str:
    """
    Ejecuta cualquier colector del catálogo (incluido un plugin externo) contra un objetivo:
    ingesta las entidades en el grafo del caso y sella la evidencia en la cadena de custodia.
    Usa list_collectors para ver los nombres disponibles.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    try:
        registered = collectors.spec(collector)
    except KeyError:
        return json.dumps(
            {
                "error": f"Colector '{collector}' no registrado",
                "available": collectors.names(),
            }
        )

    try:
        res = await registered.instance.collect(target)
    except Exception as exc:
        return json.dumps({"error": f"Colector '{collector}' falló: {exc}", "target": target})

    graph.ingest_collector_result(case_id, res)
    raw_ev = RawEvidence(
        id=f"ev-{res.collector_name}-{uuid.uuid4().hex[:8]}",
        case_id=case_id,
        collector=res.collector_name,
        source_url=f"collector://{res.collector_name}/{target}",
        raw_payload=res.raw_payload or "{}",
        payload_hash="auto",
        metadata={**res.metadata, "collector_origin": registered.origin},
    )
    ledger.record_evidence_action(
        case_id, res.collector_name, f"COLLECTOR_RUN: {collector} -> {target}", raw_ev
    )

    return json.dumps(
        {
            "status": "COMPLETED",
            "collector": res.collector_name,
            "target": target,
            "entities_found": len(res.entities),
            "relations_found": len(res.relations),
            "evidence_hash": raw_ev.payload_hash,
        },
        indent=2,
    )


# --- Herramientas Web (sin API key, estilo opencode websearch/webfetch) ---


@mcp_server.tool()
async def web_search(query: str, top_k: int = 8) -> str:
    """
    Búsqueda web pasiva (DuckDuckGo, sin API key): devuelve títulos, URLs y
    snippets. Para barrer variantes usa parallel_search (un fan-out concurrente)
    en vez de N llamadas secuenciales.
    """
    res = await web_search_collector.collect(query, top_k=top_k)
    return res.raw_payload or "{}"


# --- Navegador sigiloso OSINT (Playwright, con custodia y anti-bot) ---


@mcp_server.tool()
async def browser_snapshot(url: str, case_id: str | None = None, timeout: int = 30) -> str:
    """
    Navega con Chromium sigiloso (anti-bot integrado) y extrae título + texto
    visible + enlaces de la página renderizada. Si se pasa `case_id`, la
    extracción se sella en la cadena de custodia (bloque HMAC verificable).
    Si el sitio activó protección anti-bot, la respuesta trae `blocked` con la
    razón (captcha_redirect/blocked_page/blocked_content): considera
    browser_rotate_identity y reintenta, o cambia de fuente.
    """
    return await browser_osint.osint_snapshot(url, case_id=case_id, timeout=timeout)


@mcp_server.tool()
async def browser_screenshot(
    url: str,
    case_id: str | None = None,
    full_page: bool = False,
    timeout: int = 30,
) -> str:
    """
    Captura PNG del estado real de una página (evidencia visual). Con `case_id`
    se sella en el ledger: el hash SHA-256 del payload queda en la custodia y un
    tercero puede verificar que la captura no fue alterada. Devuelve base64 +
    metadatos + hash del bloque.
    """
    return await browser_osint.osint_screenshot(
        url, case_id=case_id, full_page=full_page, timeout=timeout
    )


@mcp_server.tool()
async def browser_interact(
    url: str,
    actions: list[dict[str, Any]],
    case_id: str | None = None,
    timeout: int = 30,
) -> str:
    """
    Ejecuta una secuencia de interacción humana sobre una página (ritmo humano
    integrado: escritura con delay por tecla, pausas no deterministas) y extrae
    el estado final. Acciones permitidas: click, fill, press, wait, scroll.
    Ejemplo de búsqueda interna en un sitio:
      actions=[
        {"action": "fill", "selector": "input[name=q]", "text": "consulta"},
        {"action": "press", "key": "Enter"},
        {"action": "wait", "ms": 2000}
      ]
    Con `case_id`, el resultado final se sella en la cadena de custodia.
    """
    return await browser_osint.osint_interact(url, actions, case_id=case_id, timeout=timeout)


@mcp_server.tool()
async def browser_rotate_identity() -> str:
    """
    Rota la identidad del navegador sigiloso: nueva huella (UA/locale/zona
    horaria/viewport) y contexto limpio (cookies+storage). Úsalo tras un bloqueo
    anti-bot (`blocked` en snapshot/screenshot) o entre sujetos que no deben
    correlacionarse por cookies. Se aplica en la próxima navegación.
    """
    return await browser_osint.osint_rotate_identity()


@mcp_server.tool()
async def browser_status() -> str:
    """
    Estado del navegador sigiloso: huella activa, reinicios recientes y
    disponibilidad. Diagnóstico rápido antes de una sesión intensiva.
    """
    return await browser_osint.osint_browser_status()


@mcp_server.tool()
async def web_fetch(url: str, max_chars: int = 12000, timeout: int = 30) -> str:
    """
    Descarga una URL http(s) y extrae título + texto visible (máx 5MB,
    timeout 30s por defecto y 120s como máximo). El texto largo vuelve
    truncado con aviso y conteo total de caracteres.
    """
    res = await web_fetch_collector.collect(url, max_chars=max_chars, timeout=timeout)
    return res.raw_payload or "{}"


@mcp_server.tool()
async def parallel_search(queries: list[str], top_k: int = 5) -> str:
    """
    Barrido concurrente de varias consultas web en una sola llamada (fan-out
    estilo opencode: semáforo de 5, timeout 25s por consulta). Una consulta
    fallida no tumba al resto: vuelve como {"error": ...} en su entrada.
    """
    clean = [q.strip() for q in (queries or []) if isinstance(q, str) and q.strip()][:10]
    if not clean:
        return json.dumps({"error": "queries vacío: pasa 1-10 consultas no vacías"})

    sem = asyncio.Semaphore(5)

    async def _one(query: str) -> tuple[str, dict[str, Any]]:
        async with sem:
            try:
                res = await asyncio.wait_for(
                    web_search_collector.collect(query, top_k=top_k), timeout=25.0
                )
                return query, json.loads(res.raw_payload or "{}")
            except Exception as exc:
                return query, {"query": query, "error": f"{type(exc).__name__}: {exc}"}

    done = await asyncio.gather(*(_one(q) for q in clean))
    return json.dumps(
        {"status": "COMPLETED", "results": {q: payload for q, payload in done}},
        indent=2,
        ensure_ascii=False,
    )


def _skills_dir() -> Path:
    """Carpeta de playbooks (skills/*.md): repo en dev, bundle en empaquetado."""
    return specter_config.bundle_dir() / "skills"


@mcp_server.tool()
def load_skill(name: str) -> str:
    """
    Carga un playbook de investigación (skills/*.md) con el procedimiento
    paso a paso para un tipo de objetivo. Disponible: 'dni-ar' (DNI argentino
    suelto: CUIT derivados, fuentes oficiales, prueba de control y cierre).
    """
    slug = name.strip().lower().removesuffix(".md")
    if not re.fullmatch(r"[a-z0-9_-]{1,40}", slug):
        return json.dumps({"error": f"Skill inválido: {name!r}"})
    base = _skills_dir()
    path = base / f"{slug}.md"
    if not path.is_file():
        available = sorted(p.stem for p in base.glob("*.md")) if base.is_dir() else []
        return json.dumps({"error": f"Skill '{slug}' no existe", "available": available})
    return json.dumps(
        {"status": "LOADED", "skill": slug, "playbook": path.read_text(encoding="utf-8")},
        ensure_ascii=False,
    )


# Efímero por diseño: la lista de tareas vive en memoria y se pierde al
# reiniciar el engine (no es evidencia: no toca ledger ni SQLite).
_TODOS: dict[str, list[dict[str, str]]] = {}


@mcp_server.tool()
def todowrite(case_id: str, todos: list[dict[str, str]]) -> str:
    """
    Reemplaza la lista de tareas del caso (plan de fases visible, estilo
    opencode todowrite): cada item lleva content, status
    (pending|in_progress|completed|cancelled) y priority (high|medium|low).
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})

    items: list[dict[str, str]] = []
    for position, raw in enumerate(todos or []):
        if not isinstance(raw, dict):
            continue
        content = str(raw.get("content", "")).strip()
        if not content:
            continue
        status = str(raw.get("status", "pending")).strip().lower()
        if status not in ("pending", "in_progress", "completed", "cancelled"):
            status = "pending"
        priority = str(raw.get("priority", "medium")).strip().lower()
        if priority not in ("high", "medium", "low"):
            priority = "medium"
        items.append(
            {"content": content, "status": status, "priority": priority, "position": str(position)}
        )
    _TODOS[case_id] = items
    pending = sum(1 for t in items if t["status"] not in ("completed", "cancelled"))
    return json.dumps(
        {"status": "UPDATED", "case_id": case_id, "pending": pending, "todos": items},
        indent=2,
        ensure_ascii=False,
    )


# --- Herramientas de Correlación Temporal y Sellado ---


@mcp_server.tool()
def correlate_cases(case_id: str | None = None, entity_types: list[str] | None = None) -> str:
    """
    Correlaciona artefactos entre casos: dominios, emails, alias o IPs presentes en más de una
    investigación. Sin case_id barre todo el repositorio; con case_id ancla el análisis a ese caso.
    """
    report = correlation.cross_case_matches(case_id=case_id, entity_types=entity_types)
    return json.dumps(report, indent=2)


@mcp_server.tool()
def case_timeline(case_id: str, bucket: str = "day") -> str:
    """
    Reconstruye la línea temporal del caso: cuándo entró cada artefacto al grafo, cuándo se
    recolectó cada evidencia y qué acciones se firmaron, detectando ráfagas de actividad.
    Usa bucket='day' (por defecto) o 'hour'.
    """
    try:
        report = timeline_engine.build(case_id, bucket=bucket)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    # El detalle evento a evento es para la UI/HTTP; al agente le bastan los agregados.
    report.pop("events", None)
    return json.dumps(report, indent=2)


@mcp_server.tool()
def attest_case_ledger(case_id: str) -> str:
    """
    Sella el estado de la cadena de custodia y emite una atestación HMAC-SHA256 verificable
    por terceros sin acceso a la base forense (payload canónico + firma detached).
    """
    return json.dumps(ledger.attest_case(case_id), indent=2)


@mcp_server.tool()
def verify_case_integrity(case_id: str) -> str:
    """
    Audita la cadena de custodia criptográfica bloque por bloque, verificando hashes SHA-256 e integridad de payloads.
    """
    audit = ledger.verify_case_integrity(case_id)
    return json.dumps(audit, indent=2)


@mcp_server.tool()
def export_case_dossier(case_id: str, format: str = "html") -> str:
    """
    Genera un informe forense formal:
    - format='html': Visualizador interactivo en HTML autónomo con red visual navegable y panel forense.
    - format='md' o 'markdown': Dossier estructurado en Markdown con inventario de entidades y cadena de custodia.
    """
    format_lower = format.lower().strip()
    if format_lower == "html":
        file_path = exporter.export_html(case_id)
    elif format_lower in ("md", "markdown"):
        file_path = exporter.export_markdown(case_id)
    else:
        return json.dumps({"error": f"Formato no soportado: {format}. Use 'html' o 'md'"})

    return json.dumps(
        {
            "status": "DOSSIER_EXPORTED",
            "case_id": case_id,
            "format": format_lower,
            "file_path": file_path,
            "message": f"Dossier generado exitosamente en {file_path}",
        },
        indent=2,
    )


@mcp_server.tool()
def export_case_stix(case_id: str) -> str:
    """
    Exporta el caso como bundle STIX 2.1 (identity + observables + relationships
    con confianza): interoperable con MISP, OpenCTI y SIEM vía TAXII.
    """
    case = db.get_case(case_id)
    if not case:
        return json.dumps({"error": f"Caso {case_id} no existe"})
    try:
        file_path = exporter.export_stix(case_id)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps(
        {
            "status": "STIX_EXPORTED",
            "case_id": case_id,
            "format": "stix2.1",
            "file_path": file_path,
        },
        indent=2,
    )


def main():
    # El servidor stdio también sella su cadena: garantiza que exista clave local.
    specter_config.ensure_ledger_key()
    collectors.load_entry_points()
    mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()

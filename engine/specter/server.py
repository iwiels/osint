"""
SpecterOSINT - FastMCP Server
Servidor MCP profesional para OpenCode AI con capacidades forenses, grafos y cadena de custodia.
"""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from specter import config as specter_config
from specter.collectors.artifacts import FileForensics
from specter.collectors.dorker import DocumentHunter
from specter.collectors.github_forensics import GitHubForensics
from specter.collectors.identity import EmailInvestigator, UsernameInvestigator
from specter.collectors.network import CrtShCollector, DNSCollector, IPEnricher, TLSCollector
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
from specter.visualizer.exporter import DossierExporter

# Inicialización del servidor MCP y servicios core
# Las rutas se resuelven vía specter.config (env vars → repo root), de modo
# que la app empaquetada y los tests puedan redirigir el almacenamiento.
mcp_server = MCPServer(name="specter-osint")
db = Database(specter_config.database_path())
ledger = ForensicLedger(db)
graph = OSINTGraph(db)
exporter = DossierExporter(db)


def reset_services(db_path: str | Path | None = None) -> Database:
    """Reconstruye los servicios core contra una ruta de BD.

    Seam de testabilidad: los handlers de tools leen estos globals en cada
    llamada, así que reasignarlos aquí redirige todo el kernel. En producción
    no se usa (una sola inicialización al importar).
    """
    global db, ledger, graph, exporter
    db = Database(Path(db_path) if db_path else specter_config.database_path())
    ledger = ForensicLedger(db)
    graph = OSINTGraph(db)
    exporter = DossierExporter(db)
    return db


# Colectores
dns_collector = DNSCollector()
crt_sh_collector = CrtShCollector()
tls_collector = TLSCollector()
ip_enricher = IPEnricher()
username_collector = UsernameInvestigator()
email_collector = EmailInvestigator()
file_forensics = FileForensics()
document_hunter = DocumentHunter()
github_forensics = GitHubForensics()


# --- Herramientas de Gestión de Casos ---


@mcp_server.tool()
def create_case(name: str, description: str, investigator: str = "Analista_OpenCode") -> str:
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

    return json.dumps(
        {
            "status": "COMPLETED",
            "ip": ip,
            "entities_identified": [e.value for e in res.entities],
            "evidence_hash": raw_ev.payload_hash,
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

    return json.dumps(
        {
            "status": "COMPLETED",
            "email": email,
            "entities_created": len(res.entities),
            "evidence_hash": raw_ev.payload_hash,
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
    return json.dumps(
        {
            "status": "COMPLETED",
            "target": target,
            "sha256": file_node.attributes.get("hashes", {}).get("sha256") if file_node else None,
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


# --- Herramientas de Integridad y Reportes ---


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


def main():
    mcp_server.run(transport="stdio")


if __name__ == "__main__":
    main()

"""
WraithOSINT - CLI & Demo Runner
Herramienta de línea de comandos para demostraciones, auditorías forenses y ejecución directa.
"""

import asyncio
import json
import sys

from specter.server import (
    analyze_network_metrics,
    create_case,
    enumerate_subdomains,
    export_case_dossier,
    investigate_domain,
    investigate_identity,
    mcp_server,
    verify_case_integrity,
)


async def run_demo():
    print("=" * 70)
    print("🛡️  INICIANDO DEMOSTRACIÓN FORENSE WraithOSINT")
    print("=" * 70)

    target_domain = "example.com"
    print("\n[+] 1. Creando caso formal de investigación...")
    case_raw = create_case(
        name="Investigación Forense Demo",
        description=f"Auditoría pasiva de infraestructura para {target_domain}",
        investigator="Comandante_OSINT",
    )
    case_info = json.loads(case_raw)
    case_id = case_info["case_id"]
    print(f"    -> Caso Creado: {case_id}")
    print(f"    -> Hash Génesis: {case_info['genesis_hash']}")

    print(f"\n[+] 2. Ejecutando recolección de red profunda (DNS + TLS) sobre {target_domain}...")
    inv_domain = json.loads(await investigate_domain(case_id, target_domain))
    print(f"    -> Entidades DNS: {inv_domain.get('dns_entities_found')}")
    print(f"    -> Entidades TLS: {inv_domain.get('tls_entities_found')}")
    print(f"    -> Hash Evidencia DNS: {inv_domain.get('evidence_hashes', {}).get('dns')[:24]}...")

    print("\n[+] 3. Descubriendo subdominios pasivos vía Certificate Transparency (crt.sh)...")
    inv_subs = json.loads(await enumerate_subdomains(case_id, target_domain))
    print(f"    -> Subdominios descubiertos: {inv_subs.get('subdomains_found')}")

    print("\n[+] 4. Sondeando presencia de identidad para alias 'octocat' (patrón Sherlock)...")
    inv_id = json.loads(await investigate_identity(case_id, "octocat"))
    print(f"    -> Perfiles confirmados: {inv_id.get('profiles_found')}")
    for p in inv_id.get("profiles", [])[:3]:
        print(f"       * {p}")

    print("\n[+] 5. Analizando métricas de centralidad en el grafo (NetworkX)...")
    metrics = json.loads(analyze_network_metrics(case_id))
    print(f"    -> Total Nodos: {metrics.get('total_nodes')}")
    print(f"    -> Total Aristas: {metrics.get('total_edges')}")
    print(f"    -> Densidad de Red: {metrics.get('density')}")

    print("\n[+] 6. Auditando Cadena de Custodia Criptográfica (Forensic Ledger)...")
    audit = json.loads(verify_case_integrity(case_id))
    print(
        f"    -> Integridad: {'✓ VÁLIDA (INMUTABLE)' if audit.get('valid') else '✗ COMPROMETIDA'}"
    )
    print(f"    -> Bloques auditados: {audit.get('total_blocks')}")
    print(f"    -> Head Hash: {audit.get('head_block_hash')}")

    print("\n[+] 7. Exportando Visualizador Interactivo Autónomo (HTML)...")
    dossier_html = json.loads(export_case_dossier(case_id, format="html"))
    html_path = dossier_html.get("file_path")
    print(f"    -> Reporte HTML generado: {html_path}")

    dossier_md = json.loads(export_case_dossier(case_id, format="md"))
    print(f"    -> Dossier Markdown generado: {dossier_md.get('file_path')}")

    print("\n" + "=" * 70)
    print("✓ DEMOSTRACIÓN COMPLETADA CON ÉXITO")
    print(f"Abre el reporte interactivo en tu navegador: file:///{html_path.replace(chr(92), '/')}")
    print("=" * 70)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        asyncio.run(run_demo())
    elif len(sys.argv) > 1 and sys.argv[1] == "serve":
        mcp_server.run(transport="stdio")
    else:
        print("Uso:")
        print(
            "  uv run python -m specter.cli demo   # Ejecuta caso de prueba y genera visualizador"
        )
        print("  uv run python -m specter.cli serve  # Inicia servidor MCP en modo stdio")


if __name__ == "__main__":
    main()

"""
Batch Investigation Runner for Requested Usernames with Deep Forensics & Document Hunting
"""

import asyncio
import json
from pathlib import Path
from specter.server import (
    create_case,
    investigate_identity,
    hunt_documents_and_leaks,
    analyze_network_metrics,
    verify_case_integrity,
    export_case_dossier,
    query_graph,
)

TARGET_USERNAMES = [
    "[objetivo-1]",
    "[objetivo-2]",
    "𝖌𝖍",
    "[objetivo-3]",
    "[objetivo-6]",
    "@[objetivo-4]",
    "[objetivo-5]",
]


async def main():
    print("=" * 80)
    print("🕵️‍♂️  INICIANDO INVESTIGACIÓN OSINT AVANZADA CON GRAFOS Y DOCUMENT HUNTING")
    print("=" * 80)

    # 1. Crear Caso
    case_raw = create_case(
        name="Investigación Forense Profunda Multiusuario",
        description="Auditoría forense sobre 7 objetivos: 700+ plataformas, minería GitHub, caza de PDFs y cadena de custodia SHA-256",
        investigator="Analista_Forense",
    )
    case_data = json.loads(case_raw)
    case_id = case_data["case_id"]
    print(f"\n[+] Caso Registrado: {case_id}")
    print(f"[+] Bloque Génesis: {case_data['genesis_hash']}\n")

    for username in TARGET_USERNAMES:
        print(f"\n" + "-" * 70)
        print(f"[*] Analizando Identidad & Huella Digital: {username} ...")
        res_raw = await investigate_identity(case_id, username)
        res = json.loads(res_raw)
        profiles = res.get("profiles", [])
        gh_meta = res.get("github_forensics")

        print(f"    -> Plataformas consultadas: {res.get('platforms_checked')}")
        print(f"    -> Perfiles confirmados: {len(profiles)}")
        for p in profiles[:8]:
            print(f"       ✓ {p}")
        if len(profiles) > 8:
            print(f"       ... y {len(profiles) - 8} más en el grafo.")

        if gh_meta:
            print(f"    [+] Minería GitHub:")
            print(f"        - Repositorios analizados: {gh_meta.get('repos_analyzed')}")
            print(f"        - Enlaces externos / Discord: {gh_meta.get('external_links_found')}")

        # 2. Caza de Documentos PDF y menciones web
        print(f"[*] Caza de Documentos (PDFs) y filtraciones para: {username} ...")
        hunt_raw = await hunt_documents_and_leaks(case_id, username)
        hunt = json.loads(hunt_raw)
        pdfs = hunt.get("pdf_artifacts", [])
        mentions = hunt.get("web_mentions", [])

        if pdfs:
            print(f"    ✓ Documentos PDF descubiertos y analizados: {len(pdfs)}")
            for pdf in pdfs:
                print(f"       [PDF] {pdf}")
        else:
            print(f"    - Sin documentos PDF indexados públicamente con esta identidad")

        if mentions:
            print(f"    ✓ Menciones web descubiertas: {len(mentions)}")
            for m in mentions[:3]:
                print(f"       [WEB] {m}")

    # 3. Métricas del Grafo de Inteligencia
    print("\n" + "=" * 80)
    print("[+] Análisis de Métricas en el Grafo de Inteligencia (NetworkX)...")
    metrics = json.loads(analyze_network_metrics(case_id))
    print(f"    -> Nodos Totales: {metrics.get('total_nodes')}")
    print(f"    -> Relaciones Totales: {metrics.get('total_edges')}")
    print(f"    -> Densidad de Red: {metrics.get('density')}")
    print(f"    -> Clusters Identificados: {metrics.get('clusters_count')}")

    # 4. Auditoría de Cadena de Custodia Criptográfica
    print("\n[+] Auditando Cadena de Custodia Criptográfica (Forensic Ledger)...")
    audit = json.loads(verify_case_integrity(case_id))
    print(f"    -> Estado de Integridad: {'✓ VÁLIDA E INMUTABLE' if audit.get('valid') else '✗ ALTERADA'}")
    print(f"    -> Bloques Criptográficos Auditados: {audit.get('total_blocks')}")
    print(f"    -> Head Block Hash: {audit.get('head_block_hash')}")

    # 5. Exportar Dossiers
    print("\n[+] Exportando Dossiers Forenses...")
    html_res = json.loads(export_case_dossier(case_id, format="html"))
    md_res = json.loads(export_case_dossier(case_id, format="md"))

    print(f"    -> Visualizador HTML Interactivo: {html_res.get('file_path')}")
    print(f"    -> Dossier Markdown Formal: {md_res.get('file_path')}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())

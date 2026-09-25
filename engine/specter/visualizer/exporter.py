"""
SpecterOSINT - Dossier Exporter & Visualizer Generator
Generación de reportes forenses autónomos en HTML (Vis.js) y dossiers en formato Markdown.
"""

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from specter import config as specter_config
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.ledger import ForensicLedger


def _reports_dir() -> Path:
    """Delega en specter.config (única fuente de verdad de rutas)."""
    return specter_config.reports_dir()


class DossierExporter:
    def __init__(self, db: Database):
        self.db = db
        self.graph = OSINTGraph(db)
        self.ledger = ForensicLedger(db)
        self.template_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(loader=FileSystemLoader(str(self.template_dir)))

    def export_html(self, case_id: str, output_path: str | Path | None = None) -> str:
        case = self.db.get_case(case_id)
        if not case:
            raise ValueError(f"Caso {case_id} no encontrado")

        graph_data = self.graph.query_subgraph(case_id)
        audit_data = self.ledger.verify_case_integrity(case_id)

        template = self.jinja_env.get_template("graph_template.html")
        rendered_html = template.render(
            case=case,
            graph_json=json.dumps(graph_data),
            audit_json=json.dumps(audit_data),
            ledger_audit=audit_data,
        )

        if output_path is None:
            output_path = _reports_dir() / f"dossier_{case_id}.html"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(rendered_html, encoding="utf-8")
        return str(output_path.resolve())

    def export_markdown(self, case_id: str, output_path: str | Path | None = None) -> str:
        case = self.db.get_case(case_id)
        if not case:
            raise ValueError(f"Caso {case_id} no encontrado")

        entities = self.db.get_case_entities(case_id)
        relations = self.db.get_case_relations(case_id)
        metrics = self.graph.analyze_metrics(case_id)
        audit = self.ledger.verify_case_integrity(case_id)

        md_lines = [
            f"# Dossier Forense OSINT: {case.name}",
            f"**Identificador de Caso:** `{case.case_id}`  ",
            f"**Investigador a Cargo:** {case.investigator}  ",
            f"**Fecha de Creación (UTC):** {case.created_at}  ",
            f"**Estado de Integridad:** `{'VERIFICADO' if audit.get('valid') else 'RIESGO_DE_ALTERACIÓN'}` ({audit.get('total_blocks', 0)} bloques encadenados)  ",
            "",
            "## 1. Resumen Ejecutivo y Métricas de Inteligencia",
            f"- **Entidades Descubiertas:** {len(entities)}",
            f"- **Relaciones Mapeadas:** {len(relations)}",
            f"- **Densidad de Red:** {metrics.get('density', 0.0)}",
            f"- **Clusters Conexos:** {metrics.get('clusters_count', 0)}",
            "",
        ]

        if metrics.get("top_central_nodes"):
            md_lines.append("\n### Activos con Mayor Conectividad (Degree)")
            for c in metrics.get("top_central_nodes", [])[:5]:
                md_lines.append(f"- **{c['label']}** (`{c['type']}`) - Grado: `{c['score']}`")

        if metrics.get("top_bridges"):
            md_lines.append("\n### Nodos Puente Estratégicos (Betweenness)")
            for b in metrics.get("top_bridges", [])[:5]:
                md_lines.append(f"- **{b['label']}** (`{b['type']}`) - Centralidad: `{b['score']}`")

        if metrics.get("top_pagerank"):
            md_lines.append("\n### Nodos de Mayor Influencia (PageRank)")
            for p in metrics.get("top_pagerank", [])[:5]:
                md_lines.append(f"- **{p['label']}** (`{p['type']}`) - Score: `{p['score']}`")

        md_lines.extend(
            [
                "",
                "## 2. Inventario de Entidades Identificadas",
                "| Tipo | Identificador Canónico | Confianza | Primera Detección |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )

        for e in entities:
            md_lines.append(
                f"| `{e.type.value}` | `{e.id}` | {int(e.confidence * 100)}% | {e.first_seen} |"
            )

        md_lines.extend(
            [
                "",
                "## 3. Cadena de Custodia Criptográfica (Forensic Audit)",
                f"- **Head Block Hash:** `{audit.get('head_block_hash', 'N/A')}`",
                f"- **Fecha de Verificación:** `{audit.get('verified_at', 'N/A')}`",
                "",
                "---",
                "*Reporte emitido automáticamente por SpecterOSINT Forensics Engine.*",
            ]
        )

        md_content = "\n".join(md_lines)

        if output_path is None:
            output_path = _reports_dir() / f"dossier_{case_id}.md"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(md_content, encoding="utf-8")
        return str(output_path.resolve())

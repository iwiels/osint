"""
SpecterOSINT - Dossier Exporter & Visualizer Generator
Generación de reportes forenses autónomos en HTML (Vis.js) y dossiers en formato Markdown.
"""

import json
from pathlib import Path
from typing import Any

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

        # Fase C: confianza por arista (el grafo la persiste con merge MAX).
        md_lines.extend(
            [
                "",
                "## 2b. Relaciones con Confianza",
                "| Origen | Relación | Destino | Confianza |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for r in relations:
            md_lines.append(
                f"| `{r.source_id}` | `{r.relation_type.value}` | `{r.target_id}` "
                f"| {int(r.confidence * 100)}% |"
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

    # ------------------------------------------------------------------
    # STIX 2.1 (Fase C): bundle interoperable para TAXII/SIEM/MISP.
    # Sin dependencias nuevas: dicts + mapeo de tipos propio.
    # ------------------------------------------------------------------

    _STIX_REL = {
        "RESOLVES_TO": "resolves-to",
        "SUBDOMAIN_OF": "contains",
        "HOSTED_ON": "located-at",
        "REGISTERED_BY": "related-to",
        "ADMINISTERS": "related-to",
        "USES_ALIAS": "related-to",
        "REGISTERED_WITH": "related-to",
        "CONTAINS_METADATA": "contains",
        "LOCATED_AT": "located-at",
        "ASSOCIATED_WITH": "related-to",
        "CORRELATED_WITH": "related-to",
        "NAMED_ON_DOCUMENT": "related-to",
        "HAS_DOCUMENT": "contains",
    }

    @staticmethod
    def _stix_id(prefix: str) -> str:
        import uuid

        return f"{prefix}--{uuid.uuid4()}"

    def export_stix(self, case_id: str, output_path: str | Path | None = None) -> str:
        """Exporta el caso como bundle STIX 2.1 (identity + observables + relationships)."""
        case = self.db.get_case(case_id)
        if not case:
            raise ValueError(f"Caso {case_id} no encontrado")
        entities = self.db.get_case_entities(case_id)
        relations = self.db.get_case_relations(case_id)
        now = case.created_at

        objects: list[dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": self._stix_id("identity"),
                "created": now,
                "modified": now,
                "name": f"SpecterOSINT:{case.investigator}",
                "identity_class": "system",
            }
        ]
        id_map: dict[str, str] = {}
        for e in entities:
            sco = self._entity_to_stix(e, now)
            if sco is None:
                continue
            id_map[e.id] = sco["id"]
            objects.append(sco)
        for r in relations:
            if r.source_id not in id_map or r.target_id not in id_map:
                continue
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": self._stix_id("relationship"),
                    "created": r.first_seen,
                    "modified": r.first_seen,
                    "relationship_type": self._STIX_REL.get(r.relation_type.value, "related-to"),
                    "confidence": int(r.confidence * 100),
                    "source_ref": id_map[r.source_id],
                    "target_ref": id_map[r.target_id],
                }
            )

        bundle = {
            "type": "bundle",
            "id": self._stix_id("bundle"),
            "spec_version": "2.1",
            "objects": objects,
        }
        if output_path is None:
            output_path = _reports_dir() / f"stix_{case_id}.json"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(output_path.resolve())

    @classmethod
    def _entity_to_stix(cls, e: Any, now: str) -> dict[str, Any] | None:
        """Mapeo entidad Specter -> SCO STIX 2.1. None = tipo sin correlato."""
        from specter.osint_core.models import EntityType

        base = {
            "spec_version": "2.1",
            "created": e.first_seen or now,
            "modified": e.last_seen or now,
            "confidence": int(e.confidence * 100),
            "labels": [f"specter:{e.type.value.lower()}"],
        }
        value = e.value
        if e.type == EntityType.DOMAIN or e.type == EntityType.SUBDOMAIN:
            return {
                **base,
                "type": "domain-name",
                "id": cls._stix_id("domain-name"),
                "value": value,
            }
        if e.type == EntityType.IP_ADDRESS:
            kind = "ipv6-addr" if ":" in value else "ipv4-addr"
            return {**base, "type": kind, "id": cls._stix_id(kind), "value": value}
        if e.type == EntityType.EMAIL:
            return {**base, "type": "email-addr", "id": cls._stix_id("email-addr"), "value": value}
        if e.type == EntityType.ALIAS:
            return {
                **base,
                "type": "user-account",
                "id": cls._stix_id("user-account"),
                "user_id": value,
            }
        if e.type == EntityType.FILE_ARTIFACT:
            hashes = (
                (e.attributes or {}).get("hashes", {}) if isinstance(e.attributes, dict) else {}
            )
            return {
                **base,
                "type": "file",
                "id": cls._stix_id("file"),
                "hashes": {k.upper(): v for k, v in hashes.items() if v},
                "name": (e.attributes or {}).get("filename", value),
            }
        if e.type == EntityType.SOCIAL_PROFILE or (
            e.type == EntityType.UNKNOWN and value.startswith(("http://", "https://"))
        ):
            return {**base, "type": "url", "id": cls._stix_id("url"), "value": value}
        if e.type == EntityType.ASN:
            return {
                **base,
                "type": "autonomous-system",
                "id": cls._stix_id("autonomous-system"),
                "number": int("".join(c for c in value if c.isdigit()) or 0),
                "name": e.label or value,
            }
        return None

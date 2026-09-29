"""
WraithOSINT - Dossier Exporter & Visualizer Generator
Generación de reportes forenses autónomos en HTML (Vis.js) y dossiers en formato Markdown.
"""

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from specter import config as specter_config
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.ledger import ForensicLedger


def _reports_dir() -> Path:
    """Delega en specter.config (única fuente de verdad de rutas)."""
    return specter_config.reports_dir()


def _json_for_script(value: Any) -> str:
    """Serializa JSON sin permitir que datos cierren el elemento <script>."""
    return (
        json.dumps(value, ensure_ascii=True)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def export_case_dossier_html(
    case_id: str,
    db: Database,
    graph_engine: OSINTGraph | str | Path | None = None,
    output_path: str | Path | None = None,
) -> str:
    """Genera un dossier de investigación autónomo en HTML, preparado para imprimir o guardar como PDF.

    Incluye:
      - Encabezado con Case ID, banner de clasificación CONFIDENCIAL / FORENSE, sello de investigador,
        marcas temporales y estado de sellado criptográfico HMAC-SHA256.
      - Resumen ejecutivo y calificaciones de fuente disponibles en el caso.
      - Métricas de red: Hubs (Degree), Puentes (Betweenness), PageRank y Células cohesivas (Louvain).
      - Reconstrucción de línea temporal de eventos y ráfagas (bursts) de actividad.
      - Inventario exhaustivo de entidades agrupadas por categoría con barras visuales de confianza.
      - Estilos CSS integrados y reglas de impresión (@media print, @page { size: A4; margin: 15mm; }).
    """
    if isinstance(graph_engine, (str, Path)):
        output_path = graph_engine
        graph_engine = None

    case = db.get_case(case_id)
    if not case:
        raise ValueError(f"Caso {case_id} no encontrado")

    if graph_engine is None:
        graph_engine = OSINTGraph(db)

    metrics = graph_engine.analyze_metrics(case_id)
    ledger = ForensicLedger(db)
    audit = ledger.verify_case_integrity(case_id)
    ledger_blocks = db.get_case_ledger(case_id)
    if "head_block_hash" not in audit:
        audit["head_block_hash"] = ledger_blocks[-1].block_hash if ledger_blocks else "N/A"
    if "signature_status" not in audit:
        audit["signature_status"] = "UNSIGNED"
    if "key_id" not in audit:
        audit["key_id"] = None
    if "total_blocks" not in audit:
        audit["total_blocks"] = len(ledger_blocks)

    from specter.osint_core.timeline import CaseTimeline

    timeline_engine = CaseTimeline(db)
    timeline_data = timeline_engine.build(case_id)

    entities = db.get_case_entities(case_id)
    relations = db.get_case_relations(case_id)

    # Agrupar entidades por categoría y ordenar por confianza descendente
    entities_by_cat: dict[str, list[Any]] = {}
    for e in entities:
        cat = e.type.value if hasattr(e.type, "value") else str(e.type)
        entities_by_cat.setdefault(cat, []).append(e)

    for cat in entities_by_cat:
        entities_by_cat[cat].sort(key=lambda item: -item.confidence)
    entities_by_category = dict(sorted(entities_by_cat.items()))

    # Matriz del Almirantazgo por fuente observada
    from specter.osint_core.admiralty import (
        CREDIBILITY_DIGITS,
        rate_source,
    )

    reliability_descriptions = {
        "A": "Juicio pericial / Evidencia sellada propia",
        "B": "Fuente primaria o registro oficial",
        "C": "Feed curado o existencia verificada",
        "D": "Búsqueda web o HTML parseado",
        "E": "Fuente dudosa con historial de error",
        "F": "Fiabilidad indeterminable",
    }

    # Contar aportes por colector
    collector_counts: dict[str, int] = {}
    for b in ledger_blocks:
        if b.collector and b.collector != "core_engine":
            collector_counts[b.collector] = collector_counts.get(b.collector, 0) + 1
    for ev in db.get_case_evidences(case_id):
        if ev.collector:
            collector_counts[ev.collector] = collector_counts.get(ev.collector, 0) + 1

    admiralty_sources: list[dict[str, Any]] = []
    for col_name, count in sorted(collector_counts.items()):
        rel_code = rate_source(col_name)
        rel_desc = reliability_descriptions.get(rel_code, "Fuente no clasificada")
        if len(collector_counts) > 1 and rel_code in ("A", "B"):
            cred_code = 1
        elif rel_code in ("A", "B", "C"):
            cred_code = 2
        elif rel_code == "D":
            cred_code = 3
        else:
            cred_code = 6
        cred_desc = CREDIBILITY_DIGITS.get(cred_code, "Veracidad indeterminable")

        admiralty_sources.append(
            {
                "collector": col_name,
                "reliability_code": rel_code,
                "reliability_name": rel_desc,
                "credibility_code": cred_code,
                "credibility_name": cred_desc,
                "rating_label": f"{rel_code}{cred_code}",
                "events_count": count,
            }
        )

    from specter.osint_core.models import current_utc_iso

    generated_at = current_utc_iso()

    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(("html", "htm", "xml")),
    )
    template = env.get_template("dossier_executive.html")

    rendered_html = template.render(
        case=case,
        audit=audit,
        metrics=metrics,
        timeline=timeline_data,
        entities_by_category=entities_by_category,
        total_entities=len(entities),
        relations=relations,
        admiralty_sources=admiralty_sources,
        generated_at=generated_at,
        ledger_blocks=ledger_blocks,
    )

    if output_path is None:
        output_path = _reports_dir() / f"dossier_executive_{case_id}.html"
    else:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(rendered_html, encoding="utf-8")
    return str(output_path.resolve())


def export_case_dossier_markdown(
    case_id: str, db: Database, output_path: str | Path | None = None
) -> str:
    """Exporta el dossier forense en formato Markdown manteniendo total compatibilidad hacia atrás."""
    exporter = DossierExporter(db)
    return exporter.export_markdown(case_id, output_path=output_path)


class DossierExporter:
    def __init__(self, db: Database):
        self.db = db
        self.graph = OSINTGraph(db)
        self.ledger = ForensicLedger(db)
        self.template_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(("html", "htm", "xml")),
        )

    def export_html(self, case_id: str, output_path: str | Path | None = None) -> str:
        case = self.db.get_case(case_id)
        if not case:
            raise ValueError(f"Caso {case_id} no encontrado")

        graph_data = self.graph.query_subgraph(case_id)
        audit_data = self.ledger.verify_case_integrity(case_id)

        template = self.jinja_env.get_template("graph_template.html")
        rendered_html = template.render(
            case=case,
            graph_json=_json_for_script(graph_data),
            audit_json=_json_for_script(audit_data),
            ledger_audit=audit_data,
        )

        if output_path is None:
            output_path = _reports_dir() / f"dossier_{case_id}.html"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(rendered_html, encoding="utf-8")
        return str(output_path.resolve())

    def export_case_dossier_html(self, case_id: str, output_path: str | Path | None = None) -> str:
        return export_case_dossier_html(case_id, self.db, self.graph, output_path=output_path)

    def export_case_dossier_markdown(
        self, case_id: str, output_path: str | Path | None = None
    ) -> str:
        return self.export_markdown(case_id, output_path=output_path)

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

        if metrics.get("communities"):
            md_lines.append("\n### Células y Comunidades Cohesivas (Louvain)")
            for comm in metrics.get("communities", [])[:5]:
                members_str = ", ".join(comm["members"][:5])
                if comm.get("truncated"):
                    members_str += f" (+{comm['size'] - 5} más)"
                md_lines.append(
                    f"- **Comunidad #{comm['community_id'] + 1}** ({comm['size']} miembros): `{members_str}`"
                )

        from specter.osint_core.timeline import CaseTimeline

        timeline_report = CaseTimeline(self.db).build(case_id)
        if timeline_report.get("bursts"):
            md_lines.append("\n### Ráfagas de Actividad Detectadas")
            for b in timeline_report.get("bursts", []):
                md_lines.append(
                    f"- **Ventana {b['bucket']}**: {b['count']} eventos ({b['ratio_vs_average']}x sobre la media)"
                )

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

        # Fase C: fiabilidad Almirantazgo por fuente usada (transparencia pericial).
        from specter.osint_core.admiralty import rate_source

        used = sorted({b.collector for b in self.db.get_case_ledger(case_id) if b.collector})
        if used:
            md_lines.extend(
                [
                    "",
                    "## 2c. Fiabilidad de Fuentes (Almirantazgo OTAN)",
                    "| Colector/Fuente | Fiabilidad |",
                    "| :--- | :--- |",
                ]
            )
            for collector_name in used:
                md_lines.append(f"| `{collector_name}` | {rate_source(collector_name)} |")
            md_lines.append(
                "\n> Links con confianza ≥ 85% exigen corroboración independiente "
                "o revisión del analista (regla Berkeley)."
            )

        md_lines.extend(
            [
                "",
                "## 3. Cadena de Custodia Criptográfica (Forensic Audit)",
                f"- **Head Block Hash:** `{audit.get('head_block_hash', 'N/A')}`",
                f"- **Fecha de Verificación:** `{audit.get('verified_at', 'N/A')}`",
                f"- **Sello HMAC-SHA256:** `{audit.get('signature_status', 'N/A')}` (Key ID: `{audit.get('key_id', 'N/A')}`)",
                "",
                "---",
                "*Reporte emitido automáticamente por WraithOSINT Forensics Engine.*",
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

    def export_graphml(self, case_id: str, output_path: str | Path | None = None) -> str:
        """Exporta el grafo a GraphML (Gephi/Neo4j offline): aplanando atributos."""
        import networkx as nx

        case = self.db.get_case(case_id)
        if not case:
            raise ValueError(f"Caso {case_id} no encontrado")
        source = self.graph.build_graph(case_id)
        flat = nx.DiGraph()
        for node_id, data in source.nodes(data=True):
            clean = {
                k: v
                if isinstance(v, (str, int, float, bool))
                else json.dumps(v, ensure_ascii=False)
                for k, v in dict(data).items()
            }
            flat.add_node(str(node_id), **clean)
        for src, dst, data in source.edges(data=True):
            clean = {
                k: v
                if isinstance(v, (str, int, float, bool))
                else json.dumps(v, ensure_ascii=False)
                for k, v in dict(data).items()
            }
            flat.add_edge(str(src), str(dst), **clean)
        if output_path is None:
            output_path = _reports_dir() / f"graph_{case_id}.graphml"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
        nx.write_graphml(flat, output_path)
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
                "name": f"WraithOSINT:{case.investigator}",
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

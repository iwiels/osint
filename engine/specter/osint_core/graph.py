"""
SpecterOSINT - Graph Analytics Engine
Motor de grafos basado en NetworkX con cálculo de métricas de inteligencia y centralidad.
"""

from typing import Any

import networkx as nx
from specter.osint_core.database import Database
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    sanitize_edge_dict,
    sanitize_node_dict,
)


class OSINTGraph:
    def __init__(self, db: Database):
        self.db = db

    def build_graph(self, case_id: str) -> nx.DiGraph:
        g = nx.DiGraph()
        entities = self.db.get_case_entities(case_id)
        relations = self.db.get_case_relations(case_id)

        for e in entities:
            g.add_node(
                e.id,
                type=e.type.value,
                value=e.value,
                label=e.label or e.value,
                confidence=e.confidence,
                attributes=e.attributes,
                first_seen=e.first_seen,
                last_seen=e.last_seen,
            )

        for r in relations:
            for endpoint in (r.source_id, r.target_id):
                if endpoint not in g:
                    stub = EntityNode.from_node_id(endpoint, first_seen=r.first_seen)
                    g.add_node(
                        stub.id,
                        type=stub.type.value,
                        value=stub.value,
                        label=stub.label or stub.value,
                        confidence=stub.confidence,
                        attributes=stub.attributes,
                        first_seen=stub.first_seen,
                        last_seen=stub.last_seen,
                    )
            g.add_edge(
                r.source_id,
                r.target_id,
                relation_type=r.relation_type.value,
                confidence=r.confidence,
                attributes=r.attributes,
                first_seen=r.first_seen,
            )

        return g

    def ingest_collector_result(self, case_id: str, result: CollectorResult) -> None:
        if result.entities:
            self.db.upsert_entities(case_id, result.entities)
        if result.relations:
            self.db.upsert_relations(case_id, result.relations)

    def query_subgraph(
        self,
        case_id: str,
        entity_type: str | None = None,
        search_term: str | None = None,
        center_id: str | None = None,
        max_depth: int = 2,
    ) -> dict[str, Any]:
        g = self.build_graph(case_id)
        if g.number_of_nodes() == 0:
            return {"nodes": [], "edges": [], "total_nodes": 0, "total_edges": 0}

        has_filter = bool(center_id or entity_type or search_term)

        if has_filter:
            target_nodes: set[str] = set()

            if center_id:
                if center_id in g:
                    undirected = g.to_undirected()
                    lengths = nx.single_source_shortest_path_length(
                        undirected, center_id, cutoff=max_depth
                    )
                    target_nodes.update(lengths.keys())
            else:
                for node, data in g.nodes(data=True):
                    type_match = True
                    term_match = True
                    if entity_type and str(data.get("type", "")).upper() != entity_type.upper():
                        type_match = False
                    if search_term:
                        st = search_term.lower()
                        val_str = str(data.get("value", "")).lower()
                        lbl_str = str(data.get("label", "")).lower()
                        nid_str = str(node).lower()
                        if st not in val_str and st not in lbl_str and st not in nid_str:
                            term_match = False
                    if type_match and term_match:
                        target_nodes.add(node)

                # Si hay nodos coincidentes y se especificó término, expandir 1 salto
                if search_term and target_nodes:
                    expanded = set(target_nodes)
                    for tn in list(target_nodes):
                        expanded.update(g.neighbors(tn))
                        expanded.update(g.predecessors(tn))
                    target_nodes = expanded

            subg = g.subgraph(target_nodes)
        else:
            subg = g

        nodes_list = [
            sanitize_node_dict(dict(data), node_id=n) for n, data in subg.nodes(data=True)
        ]
        edges_list = [
            sanitize_edge_dict(dict(data), source=u, target=v)
            for u, v, data in subg.edges(data=True)
        ]

        return {
            "nodes": nodes_list,
            "edges": edges_list,
            "total_nodes": len(nodes_list),
            "total_edges": len(edges_list),
        }

    def analyze_metrics(self, case_id: str) -> dict[str, Any]:
        g = self.build_graph(case_id)
        total_nodes = g.number_of_nodes()
        total_edges = g.number_of_edges()

        if total_nodes == 0:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "density": 0.0,
                "top_central_nodes": [],
                "top_bridges": [],
                "top_pagerank": [],
                "clusters_count": 0,
            }

        density = nx.density(g)
        degree_dict = dict(g.degree())
        top_degree = sorted(degree_dict.items(), key=lambda x: x[1], reverse=True)[:5]

        # Centralidad de intermediación (nodos puente)
        betweenness = nx.betweenness_centrality(g)
        top_betweenness = sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:5]

        # PageRank (con fallback a versión no dirigida)
        try:
            pagerank = nx.pagerank(g, alpha=0.85, max_iter=500, tol=1e-04)
            top_pagerank = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)[:5]
        except Exception:
            try:
                pagerank = nx.pagerank(g.to_undirected(), alpha=0.85, max_iter=500, tol=1e-04)
                top_pagerank = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)[:5]
            except Exception:
                top_pagerank = []

        # Componentes conexas en versión no dirigida
        clusters_count = nx.number_connected_components(g.to_undirected())

        def format_rankings(rankings: list[tuple]) -> list[dict[str, Any]]:
            res = []
            for node_id, score in rankings:
                node_data = sanitize_node_dict(dict(g.nodes.get(node_id, {})), node_id=node_id)
                res.append(
                    {
                        "id": node_id,
                        "label": node_data.get("label", node_id),
                        "type": node_data.get("type", "UNKNOWN"),
                        "score": round(float(score), 4),
                    }
                )
            return res

        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "density": round(density, 4),
            "top_central_nodes": format_rankings(top_degree),
            "top_bridges": format_rankings(top_betweenness),
            "top_pagerank": format_rankings(top_pagerank),
            "clusters_count": clusters_count,
        }

    def find_shortest_path(
        self, case_id: str, source_id: str, target_id: str
    ) -> list[dict[str, Any]] | None:
        g = self.build_graph(case_id)
        if source_id not in g or target_id not in g:
            return None

        try:
            # Buscar en el grafo no dirigido para encontrar cualquier camino de relación
            path_nodes = nx.shortest_path(g.to_undirected(), source=source_id, target=target_id)
            return [
                sanitize_node_dict(dict(g.nodes.get(node_id, {})), node_id=node_id)
                for node_id in path_nodes
            ]
        except nx.NetworkXNoPath:
            return None

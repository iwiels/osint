"""
WraithOSINT - Projections (CQRS)
Vistas materializadas del estado: grafo, timeline y correlaciones.
Se reconstruyen desde eventos y se actualizan incrementalmente.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.models import (
    EntityNode,
    RelationEdge,
    current_utc_iso,
)


class Projection(BaseModel):
    """Clase base para todas las proyecciones."""

    name: str
    case_id: str
    last_updated: str = Field(default_factory=current_utc_iso)
    event_count: int = 0


class GraphProjection(Projection):
    """
    Vista materializada del grafo de un caso.

    Mantiene una caché en memoria del grafo para consultas rápidas.
    """

    nodes: dict[str, EntityNode] = Field(default_factory=dict)
    edges: list[RelationEdge] = Field(default_factory=list)
    adjacency: dict[str, list[str]] = Field(default_factory=dict)

    @classmethod
    async def rebuild(cls, db: Database, graph: OSINTGraph, case_id: str) -> GraphProjection:
        """Reconstruye la proyección desde la base de datos."""
        entities = db.get_case_entities(case_id)
        relations = db.get_case_relations(case_id)

        nodes: dict[str, EntityNode] = {}
        adjacency: dict[str, list[str]] = {}

        for entity in entities:
            nodes[entity.id] = entity
            if entity.id not in adjacency:
                adjacency[entity.id] = []

        for rel in relations:
            if rel.source_id not in adjacency:
                adjacency[rel.source_id] = []
            if rel.target_id not in adjacency:
                adjacency[rel.target_id] = []
            adjacency[rel.source_id].append(rel.target_id)
            adjacency[rel.target_id].append(rel.source_id)

        return cls(
            name="graph",
            case_id=case_id,
            nodes=nodes,
            edges=relations,
            adjacency=adjacency,
            event_count=len(entities) + len(relations),
        )

    async def update(self, event: dict[str, Any]) -> None:
        """Actualiza la proyección con un evento."""
        event_type = event.get("type")

        if event_type == "entity_added":
            entity = EntityNode(**event["data"])
            self.nodes[entity.id] = entity
            if entity.id not in self.adjacency:
                self.adjacency[entity.id] = []

        elif event_type == "relation_added":
            rel = RelationEdge(**event["data"])
            self.edges.append(rel)
            if rel.source_id not in self.adjacency:
                self.adjacency[rel.source_id] = []
            if rel.target_id not in self.adjacency:
                self.adjacency[rel.target_id] = []
            self.adjacency[rel.source_id].append(rel.target_id)
            self.adjacency[rel.target_id].append(rel.source_id)

        self.event_count += 1
        self.last_updated = current_utc_iso()

    def get_neighbors(self, node_id: str) -> list[EntityNode]:
        """Obtiene los vecinos de un nodo."""
        neighbor_ids = self.adjacency.get(node_id, [])
        return [self.nodes[nid] for nid in neighbor_ids if nid in self.nodes]

    def get_subgraph(self, center_id: str, max_depth: int = 2) -> dict[str, Any]:
        """Obtiene un subgrafo centrado en un nodo."""
        if center_id not in self.nodes:
            return {"nodes": [], "edges": []}

        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(center_id, 0)]
        nodes: list[EntityNode] = []
        edges: list[RelationEdge] = []

        while queue:
            current_id, depth = queue.pop(0)
            if current_id in visited or depth > max_depth:
                continue

            visited.add(current_id)
            if current_id in self.nodes:
                nodes.append(self.nodes[current_id])

            for neighbor_id in self.adjacency.get(current_id, []):
                if neighbor_id not in visited:
                    queue.append((neighbor_id, depth + 1))
                    # Buscar la arista correspondiente
                    for edge in self.edges:
                        if (edge.source_id == current_id and edge.target_id == neighbor_id) or (
                            edge.source_id == neighbor_id and edge.target_id == current_id
                        ):
                            edges.append(edge)
                            break

        return {
            "nodes": [n.model_dump() for n in nodes],
            "edges": [e.model_dump() for e in edges],
        }


class TimelineProjection(Projection):
    """
    Vista materializada del timeline de un caso.

    Mantiene eventos ordenados cronológicamente para consultas rápidas.
    """

    events: list[dict[str, Any]] = Field(default_factory=list)
    buckets: dict[str, int] = Field(default_factory=dict)

    @classmethod
    async def rebuild(cls, db: Database, case_id: str) -> TimelineProjection:
        """Reconstruye la proyección desde la base de datos."""
        from specter.osint_core.timeline import CaseTimeline

        timeline_engine = CaseTimeline(db)
        events = timeline_engine.events(case_id)

        buckets: dict[str, int] = {}
        for event in events:
            bucket_key = event["timestamp"][:10]  # YYYY-MM-DD
            buckets[bucket_key] = buckets.get(bucket_key, 0) + 1

        return cls(
            name="timeline",
            case_id=case_id,
            events=events,
            buckets=buckets,
            event_count=len(events),
        )

    async def update(self, event: dict[str, Any]) -> None:
        """Actualiza la proyección con un evento."""
        self.events.append(event)
        # Mantener orden cronológico
        self.events.sort(key=lambda e: e.get("timestamp", ""))

        bucket_key = event.get("timestamp", "")[:10]
        self.buckets[bucket_key] = self.buckets.get(bucket_key, 0) + 1

        self.event_count += 1
        self.last_updated = current_utc_iso()

    def get_events_range(
        self, start: str | None = None, end: str | None = None
    ) -> list[dict[str, Any]]:
        """Obtiene eventos en un rango temporal."""
        filtered = self.events
        if start:
            filtered = [e for e in filtered if e.get("timestamp", "") >= start]
        if end:
            filtered = [e for e in filtered if e.get("timestamp", "") <= end]
        return filtered


class CorrelationsProjection(Projection):
    """
    Vista materializada de correlaciones entre casos.

    Mapea entidades compartidas entre diferentes investigaciones.
    """

    shared_entities: dict[str, list[str]] = Field(default_factory=dict)
    case_connections: dict[str, list[str]] = Field(default_factory=dict)

    @classmethod
    async def rebuild(cls, db: Database, case_id: str | None = None) -> CorrelationsProjection:
        """Reconstruye la proyección desde la base de datos."""
        shared = db.find_shared_entities(case_id=case_id)

        shared_entities: dict[str, list[str]] = {}
        case_connections: dict[str, list[str]] = {}

        for item in shared:
            entity_id = item["id"]
            case_ids = item.get("case_ids", [])
            shared_entities[entity_id] = case_ids

            for cid in case_ids:
                if cid not in case_connections:
                    case_connections[cid] = []
                for other_cid in case_ids:
                    if other_cid != cid and other_cid not in case_connections[cid]:
                        case_connections[cid].append(other_cid)

        return cls(
            name="correlations",
            case_id=case_id or "global",
            shared_entities=shared_entities,
            case_connections=case_connections,
            event_count=len(shared),
        )

    async def update(self, event: dict[str, Any]) -> None:
        """Actualiza la proyección con un evento."""
        event_type = event.get("type")

        if event_type == "entity_shared":
            entity_id = event["entity_id"]
            case_ids = event.get("case_ids", [])
            self.shared_entities[entity_id] = case_ids

            for cid in case_ids:
                if cid not in self.case_connections:
                    self.case_connections[cid] = []
                for other_cid in case_ids:
                    if other_cid != cid and other_cid not in self.case_connections[cid]:
                        self.case_connections[cid].append(other_cid)

        self.event_count += 1
        self.last_updated = current_utc_iso()

    def get_related_cases(self, case_id: str) -> list[str]:
        """Obtiene casos relacionados por entidades compartidas."""
        return self.case_connections.get(case_id, [])

    def get_shared_entities(self, case_id: str) -> list[str]:
        """Obtiene entidades compartidas de un caso."""
        return [entity_id for entity_id, cases in self.shared_entities.items() if case_id in cases]


class ProjectionManager:
    """
    Gestor de proyecciones: mantiene y actualiza todas las vistas materializadas.
    """

    def __init__(self, db: Database, graph: OSINTGraph):
        self.db = db
        self.graph = graph
        self._projections: dict[str, Projection] = {}

    async def rebuild_all(self, case_id: str) -> None:
        """Reconstruye todas las proyecciones para un caso."""
        self._projections[f"graph:{case_id}"] = await GraphProjection.rebuild(
            self.db, self.graph, case_id
        )
        self._projections[f"timeline:{case_id}"] = await TimelineProjection.rebuild(
            self.db, case_id
        )
        self._projections[f"correlations:{case_id}"] = await CorrelationsProjection.rebuild(
            self.db, case_id
        )

    async def update(self, case_id: str, event: dict[str, Any]) -> None:
        """Actualiza todas las proyecciones con un evento."""
        for key, projection in self._projections.items():
            if key.endswith(f":{case_id}"):
                await projection.update(event)

    def get_projection(self, name: str, case_id: str) -> Projection | None:
        """Obtiene una proyección por nombre y caso."""
        return self._projections.get(f"{name}:{case_id}")

    def get_graph_projection(self, case_id: str) -> GraphProjection | None:
        """Obtiene la proyección de grafo de un caso."""
        proj = self._projections.get(f"graph:{case_id}")
        return proj if isinstance(proj, GraphProjection) else None

    def get_timeline_projection(self, case_id: str) -> TimelineProjection | None:
        """Obtiene la proyección de timeline de un caso."""
        proj = self._projections.get(f"timeline:{case_id}")
        return proj if isinstance(proj, TimelineProjection) else None

    def get_correlations_projection(self, case_id: str) -> CorrelationsProjection | None:
        """Obtiene la proyección de correlaciones de un caso."""
        proj = self._projections.get(f"correlations:{case_id}")
        return proj if isinstance(proj, CorrelationsProjection) else None

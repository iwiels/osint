"""
WraithOSINT - Event Types
Definición de los tipos de eventos del dominio para Event Sourcing.

Cada evento representa un hecho inmutable que ocurrió en el sistema. Los tipos
están organizados por prefijo de dominio (collector, entity, correlation, etc.)
para facilitar el filtrado y la auditoría.
"""

from enum import StrEnum


class EventType(StrEnum):
    """Tipos de eventos del dominio OSINT.

    Cada tipo representa un hecho atómico e inmutable. El EventStore persiste
    estos eventos en orden secuencial por aggregate (case_id), permitiendo
    reconstruir el estado completo de un caso mediante replay.
    """

    # Eventos de colectores
    COLLECTOR_RAN = "collector.ran"

    # Eventos de entidades
    ENTITY_RESOLVED = "entity.resolved"

    # Eventos de correlación
    CORRELATION_FOUND = "correlation.found"

    # Eventos de grafo
    GRAPH_UPDATED = "graph.updated"

    # Eventos de reportes
    REPORT_EXPORTED = "report.exported"

    # Eventos de casos
    CASE_CREATED = "case.created"
    CASE_CLOSED = "case.closed"

    # Eventos de permisos
    PERMISSION_GRANTED = "permission.granted"
    PERMISSION_DENIED = "permission.denied"


# Metadatos por tipo de evento: campos esperados en `data` para validación ligera.
EVENT_DATA_SCHEMA: dict[EventType, list[str]] = {
    EventType.COLLECTOR_RAN: ["collector", "target", "entities_found"],
    EventType.ENTITY_RESOLVED: ["entity_id", "entity_type", "value"],
    EventType.CORRELATION_FOUND: ["source_id", "target_id", "relation_type"],
    EventType.GRAPH_UPDATED: ["nodes_added", "edges_added"],
    EventType.REPORT_EXPORTED: ["format", "path"],
    EventType.CASE_CREATED: ["case_id", "name", "investigator"],
    EventType.CASE_CLOSED: ["case_id", "reason"],
    EventType.PERMISSION_GRANTED: ["request_id", "tool"],
    EventType.PERMISSION_DENIED: ["request_id", "tool", "reason"],
}

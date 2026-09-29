"""
SpecterOSINT - Queries (CQRS)
Consultas que leen estado: obtienen casos, entidades, grafos,
evidencias, timelines y correlaciones sin mutar nada.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.models import (
    EntityType,
    current_utc_iso,
)


class QueryResult(BaseModel):
    """Resultado de la ejecución de una query."""

    success: bool
    query_id: str = Field(default_factory=lambda: f"qry-{__import__('uuid').uuid4().hex[:8]}")
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=current_utc_iso)


class Query(ABC):
    """Clase base para todas las consultas del sistema."""

    @abstractmethod
    async def execute(self) -> QueryResult:
        """Ejecuta la query y retorna el resultado."""
        pass

    @abstractmethod
    def validate(self) -> list[str]:
        """Valida la query. Retorna lista de errores (vacía si es válida)."""
        pass


class GetCaseQuery(Query):
    """Query para obtener un caso por su ID."""

    def __init__(self, db: Database, case_id: str):
        self.db = db
        self.case_id = case_id

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        return errors

    async def execute(self) -> QueryResult:
        errors = self.validate()
        if errors:
            return QueryResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return QueryResult(success=False, message=f"Caso {self.case_id} no encontrado")

        return QueryResult(
            success=True,
            message="Caso encontrado",
            data={"case": case.model_dump()},
        )


class GetEntitiesQuery(Query):
    """Query para obtener entidades de un caso."""

    def __init__(
        self,
        db: Database,
        case_id: str,
        entity_type: EntityType | None = None,
        limit: int = 100,
        offset: int = 0,
    ):
        self.db = db
        self.case_id = case_id
        self.entity_type = entity_type
        self.limit = limit
        self.offset = offset

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if self.limit < 1 or self.limit > 1000:
            errors.append("limit debe estar entre 1 y 1000")
        if self.offset < 0:
            errors.append("offset debe ser >= 0")
        return errors

    async def execute(self) -> QueryResult:
        errors = self.validate()
        if errors:
            return QueryResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return QueryResult(success=False, message=f"Caso {self.case_id} no encontrado")

        entities = self.db.get_case_entities(
            self.case_id,
            entity_type=self.entity_type.value if self.entity_type else None,
        )

        # Aplicar paginación
        total = len(entities)
        paginated = entities[self.offset : self.offset + self.limit]

        return QueryResult(
            success=True,
            message=f"Entidades obtenidas: {len(paginated)} de {total}",
            data={
                "entities": [e.model_dump() for e in paginated],
                "total": total,
                "limit": self.limit,
                "offset": self.offset,
            },
        )


class GetGraphQuery(Query):
    """Query para obtener el grafo de un caso."""

    def __init__(
        self,
        db: Database,
        graph: OSINTGraph,
        case_id: str,
        search_term: str | None = None,
        entity_type: str | None = None,
        center_id: str | None = None,
        max_depth: int = 2,
    ):
        self.db = db
        self.graph = graph
        self.case_id = case_id
        self.search_term = search_term
        self.entity_type = entity_type
        self.center_id = center_id
        self.max_depth = max_depth

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if self.max_depth < 1 or self.max_depth > 10:
            errors.append("max_depth debe estar entre 1 y 10")
        return errors

    async def execute(self) -> QueryResult:
        errors = self.validate()
        if errors:
            return QueryResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return QueryResult(success=False, message=f"Caso {self.case_id} no encontrado")

        subgraph = self.graph.query_subgraph(
            case_id=self.case_id,
            search_term=self.search_term,
            entity_type=self.entity_type,
            center_id=self.center_id,
            max_depth=self.max_depth,
        )

        return QueryResult(
            success=True,
            message="Grafo obtenido",
            data={"graph": subgraph},
        )


class SearchEvidenceQuery(Query):
    """Query para buscar evidencias en un caso."""

    def __init__(
        self,
        db: Database,
        case_id: str,
        collector: str | None = None,
        search_term: str | None = None,
        limit: int = 50,
    ):
        self.db = db
        self.case_id = case_id
        self.collector = collector
        self.search_term = search_term
        self.limit = limit

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if self.limit < 1 or self.limit > 500:
            errors.append("limit debe estar entre 1 y 500")
        return errors

    async def execute(self) -> QueryResult:
        errors = self.validate()
        if errors:
            return QueryResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return QueryResult(success=False, message=f"Caso {self.case_id} no encontrado")

        evidences = self.db.get_case_evidences(self.case_id)

        # Filtrar por colector
        if self.collector:
            evidences = [e for e in evidences if e.collector == self.collector]

        # Filtrar por término de búsqueda
        if self.search_term:
            term = self.search_term.lower()
            evidences = [
                e
                for e in evidences
                if term in e.source_url.lower()
                or term in e.collector.lower()
                or term in e.raw_payload.lower()
            ]

        # Aplicar límite
        total = len(evidences)
        limited = evidences[: self.limit]

        return QueryResult(
            success=True,
            message=f"Evidencias encontradas: {len(limited)} de {total}",
            data={
                "evidences": [e.model_dump() for e in limited],
                "total": total,
                "limit": self.limit,
            },
        )


class GetTimelineQuery(Query):
    """Query para obtener el timeline de un caso."""

    def __init__(
        self,
        db: Database,
        case_id: str,
        bucket: str = "day",
        burst_threshold: float = 2.5,
    ):
        self.db = db
        self.case_id = case_id
        self.bucket = bucket
        self.burst_threshold = burst_threshold

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if self.bucket not in ("hour", "day"):
            errors.append("bucket debe ser 'hour' o 'day'")
        return errors

    async def execute(self) -> QueryResult:
        errors = self.validate()
        if errors:
            return QueryResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return QueryResult(success=False, message=f"Caso {self.case_id} no encontrado")

        from specter.osint_core.timeline import CaseTimeline

        timeline_engine = CaseTimeline(self.db)
        timeline = timeline_engine.build(
            self.case_id,
            bucket=self.bucket,
            burst_threshold=self.burst_threshold,
        )

        return QueryResult(
            success=True,
            message="Timeline obtenido",
            data={"timeline": timeline},
        )


class GetCorrelationsQuery(Query):
    """Query para obtener correlaciones entre casos."""

    def __init__(
        self,
        db: Database,
        case_id: str | None = None,
        entity_types: list[str] | None = None,
    ):
        self.db = db
        self.case_id = case_id
        self.entity_types = entity_types

    def validate(self) -> list[str]:
        return []

    async def execute(self) -> QueryResult:
        errors = self.validate()
        if errors:
            return QueryResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        # Obtener entidades compartidas entre casos
        shared = self.db.find_shared_entities(
            case_id=self.case_id,
            entity_types=self.entity_types,
        )

        return QueryResult(
            success=True,
            message=f"Correlaciones encontradas: {len(shared)}",
            data={
                "correlations": shared,
                "total": len(shared),
            },
        )

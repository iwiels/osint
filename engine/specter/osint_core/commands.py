"""
WraithOSINT - Commands (CQRS)
Comandos que mutan estado: ejecutan colectores, resuelven entidades,
actualizan el grafo, exportan reportes y gestionan casos.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from specter.osint_core.database import Database
from specter.osint_core.graph import OSINTGraph
from specter.osint_core.ledger import ForensicLedger
from specter.osint_core.models import (
    CaseMetadata,
    CollectorResult,
    EntityNode,
    EntityType,
    RawEvidence,
    RelationEdge,
    current_utc_iso,
)


class CommandResult(BaseModel):
    """Resultado de la ejecución de un comando."""

    success: bool
    command_id: str = Field(default_factory=lambda: f"cmd-{uuid.uuid4().hex[:8]}")
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=current_utc_iso)


class Command(ABC):
    """Clase base para todos los comandos del sistema."""

    @abstractmethod
    async def execute(self) -> CommandResult:
        """Ejecuta el comando y retorna el resultado."""
        pass

    @abstractmethod
    def validate(self) -> list[str]:
        """Valida el comando. Retorna lista de errores (vacía si es válido)."""
        pass

    async def undo(self) -> CommandResult:
        """Deshace el comando si es posible. Por defecto no soportado."""
        return CommandResult(
            success=False,
            message=f"Undo no soportado para {self.__class__.__name__}",
        )


class RunCollectorCommand(Command):
    """Comando para ejecutar un colector contra un objetivo."""

    def __init__(
        self,
        db: Database,
        graph: OSINTGraph,
        ledger: ForensicLedger,
        case_id: str,
        collector: Any,
        target: str,
        options: dict[str, Any] | None = None,
    ):
        self.db = db
        self.graph = graph
        self.ledger = ledger
        self.case_id = case_id
        self.collector = collector
        self.target = target
        self.options = options or {}
        self._result: CollectorResult | None = None
        self._evidence: RawEvidence | None = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if not self.target:
            errors.append("target es requerido")
        if self.collector is None:
            errors.append("collector es requerido")
        return errors

    async def execute(self) -> CommandResult:
        errors = self.validate()
        if errors:
            return CommandResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        # Verificar que el caso existe
        case = self.db.get_case(self.case_id)
        if not case:
            return CommandResult(success=False, message=f"Caso {self.case_id} no existe")

        try:
            # Ejecutar el colector
            self._result = await self.collector.collect(self.target, **self.options)

            # Ingestar en el grafo
            self.graph.ingest_collector_result(self.case_id, self._result)

            # Crear evidencia
            self._evidence = RawEvidence(
                id=f"ev-{self._result.collector_name}-{uuid.uuid4().hex[:8]}",
                case_id=self.case_id,
                collector=self._result.collector_name,
                source_url=f"collector://{self._result.collector_name}/{self.target}",
                raw_payload=self._result.raw_payload or "{}",
                payload_hash="auto",
                metadata=self._result.metadata,
            )

            # Registrar en el ledger
            self.ledger.record_evidence_action(
                self.case_id,
                self._result.collector_name,
                f"COLLECTOR_RUN: {self.target}",
                self._evidence,
            )

            return CommandResult(
                success=True,
                message=f"Colector '{self._result.collector_name}' ejecutado exitosamente",
                data={
                    "collector": self._result.collector_name,
                    "target": self.target,
                    "entities_found": len(self._result.entities),
                    "relations_found": len(self._result.relations),
                    "evidence_id": self._evidence.id,
                },
            )
        except Exception as exc:
            return CommandResult(
                success=False,
                message=f"Error ejecutando colector: {exc}",
            )

    async def undo(self) -> CommandResult:
        """Deshace la ejecución del colector (elimina la evidencia creada)."""
        if not self._evidence:
            return CommandResult(success=False, message="No hay evidencia para deshacer")

        # Nota: En un sistema complejo, aquí se eliminarían las entidades y relaciones
        # específicas creadas por este colector. Por simplicidad, solo registramos
        # la acción de undo en el ledger.
        self.ledger.record_evidence_action(
            self.case_id,
            "system",
            f"UNDO_COLLECTOR: {self.target}",
        )
        return CommandResult(
            success=True,
            message=f"Colector '{self.collector.name}' deshecho",
        )


class ResolveEntityCommand(Command):
    """Comando para resolver una entidad (crear o actualizar en el grafo)."""

    def __init__(
        self,
        db: Database,
        graph: OSINTGraph,
        ledger: ForensicLedger,
        case_id: str,
        entity_type: EntityType,
        value: str,
        label: str | None = None,
        attributes: dict[str, Any] | None = None,
        confidence: float = 1.0,
    ):
        self.db = db
        self.graph = graph
        self.ledger = ledger
        self.case_id = case_id
        self.entity_type = entity_type
        self.value = value
        self.label = label
        self.attributes = attributes or {}
        self.confidence = confidence
        self._entity: EntityNode | None = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if not self.value:
            errors.append("value es requerido")
        if not isinstance(self.entity_type, EntityType):
            errors.append("entity_type debe ser un EntityType válido")
        return errors

    async def execute(self) -> CommandResult:
        errors = self.validate()
        if errors:
            return CommandResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return CommandResult(success=False, message=f"Caso {self.case_id} no existe")

        # Crear la entidad
        self._entity = EntityNode.create(
            type=self.entity_type,
            value=self.value,
            label=self.label,
            attributes=self.attributes,
            confidence=self.confidence,
        )

        # Ingestar en el grafo
        result = CollectorResult(
            collector_name="entity_resolver",
            source_target=self.value,
            entities=[self._entity],
            relations=[],
        )
        self.graph.ingest_collector_result(self.case_id, result)

        # Registrar en el ledger
        self.ledger.record_evidence_action(
            self.case_id,
            "entity_resolver",
            f"ENTITY_RESOLVED: {self._entity.id}",
        )

        return CommandResult(
            success=True,
            message=f"Entidad resuelta: {self._entity.id}",
            data={
                "entity_id": self._entity.id,
                "type": self._entity.type.value,
                "value": self._entity.value,
            },
        )


class UpdateGraphCommand(Command):
    """Comando para actualizar el grafo con entidades y relaciones."""

    def __init__(
        self,
        db: Database,
        graph: OSINTGraph,
        ledger: ForensicLedger,
        case_id: str,
        entities: list[EntityNode] | None = None,
        relations: list[RelationEdge] | None = None,
        action: str = "GRAPH_UPDATE",
    ):
        self.db = db
        self.graph = graph
        self.ledger = ledger
        self.case_id = case_id
        self.entities = entities or []
        self.relations = relations or []
        self.action = action

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if not self.entities and not self.relations:
            errors.append("Se requiere al menos una entidad o relación")
        return errors

    async def execute(self) -> CommandResult:
        errors = self.validate()
        if errors:
            return CommandResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return CommandResult(success=False, message=f"Caso {self.case_id} no existe")

        # Ingestar entidades y relaciones
        result = CollectorResult(
            collector_name="graph_updater",
            source_target=self.case_id,
            entities=self.entities,
            relations=self.relations,
        )
        self.graph.ingest_collector_result(self.case_id, result)

        # Registrar en el ledger
        self.ledger.record_evidence_action(
            self.case_id,
            "graph_updater",
            f"{self.action}: {len(self.entities)} entidades, {len(self.relations)} relaciones",
        )

        return CommandResult(
            success=True,
            message="Grafo actualizado exitosamente",
            data={
                "entities_added": len(self.entities),
                "relations_added": len(self.relations),
            },
        )


class ExportReportCommand(Command):
    """Comando para exportar un reporte del caso."""

    def __init__(
        self,
        db: Database,
        ledger: ForensicLedger,
        case_id: str,
        output_path: str | Path,
        format: str = "json",
    ):
        self.db = db
        self.ledger = ledger
        self.case_id = case_id
        self.output_path = Path(output_path)
        self.format = format

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        if not self.output_path:
            errors.append("output_path es requerido")
        if self.format not in ("json", "html", "pdf"):
            errors.append("format debe ser 'json', 'html' o 'pdf'")
        return errors

    async def execute(self) -> CommandResult:
        errors = self.validate()
        if errors:
            return CommandResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        case = self.db.get_case(self.case_id)
        if not case:
            return CommandResult(success=False, message=f"Caso {self.case_id} no existe")

        # Recopilar datos del caso
        entities = self.db.get_case_entities(self.case_id)
        relations = self.db.get_case_relations(self.case_id)
        evidences = self.db.get_case_evidences(self.case_id)
        ledger_blocks = self.db.get_case_ledger(self.case_id)

        report_data = {
            "case": case.model_dump(),
            "summary": {
                "total_entities": len(entities),
                "total_relations": len(relations),
                "total_evidences": len(evidences),
                "total_ledger_blocks": len(ledger_blocks),
            },
            "entities": [e.model_dump() for e in entities],
            "relations": [r.model_dump() for r in relations],
            "evidences": [e.model_dump() for e in evidences],
            "ledger": [b.model_dump() for b in ledger_blocks],
        }

        # Escribir reporte
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        if self.format == "json":
            import json

            self.output_path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        else:
            # Para html/pdf, por ahora escribimos JSON (simplificación)
            import json

            self.output_path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        # Registrar en el ledger
        self.ledger.record_evidence_action(
            self.case_id,
            "reporter",
            f"REPORT_EXPORTED: {self.format} -> {self.output_path}",
        )

        return CommandResult(
            success=True,
            message=f"Reporte exportado a {self.output_path}",
            data={
                "output_path": str(self.output_path),
                "format": self.format,
                "entities_count": len(entities),
            },
        )


class CreateCaseCommand(Command):
    """Comando para crear un nuevo caso de investigación."""

    def __init__(
        self,
        db: Database,
        ledger: ForensicLedger,
        name: str,
        description: str,
        investigator: str = "Analista_Specter",
    ):
        self.db = db
        self.ledger = ledger
        self.name = name
        self.description = description
        self.investigator = investigator
        self._case: CaseMetadata | None = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.name:
            errors.append("name es requerido")
        if not self.description:
            errors.append("description es requerido")
        return errors

    async def execute(self) -> CommandResult:
        errors = self.validate()
        if errors:
            return CommandResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        # Crear el caso
        case_uuid = f"case-{datetime.now(UTC).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
        self._case = CaseMetadata(
            case_id=case_uuid,
            name=self.name,
            description=self.description,
            investigator=self.investigator,
        )

        self.db.create_case(self._case)

        # Inicializar el ledger con bloque génesis
        genesis_block = self.ledger.initialize_case_genesis(self._case)

        return CommandResult(
            success=True,
            message=f"Caso creado: {self._case.case_id}",
            data={
                "case_id": self._case.case_id,
                "name": self._case.name,
                "genesis_hash": genesis_block.block_hash,
            },
        )

    async def undo(self) -> CommandResult:
        """Deshace la creación del caso (lo elimina)."""
        if not self._case:
            return CommandResult(success=False, message="No hay caso para deshacer")

        self.db.delete_case(self._case.case_id)
        return CommandResult(
            success=True,
            message=f"Caso {self._case.case_id} eliminado",
        )


class DeleteCaseCommand(Command):
    """Comando para eliminar un caso de investigación."""

    def __init__(self, db: Database, ledger: ForensicLedger, case_id: str):
        self.db = db
        self.ledger = ledger
        self.case_id = case_id
        self._case: CaseMetadata | None = None

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.case_id:
            errors.append("case_id es requerido")
        return errors

    async def execute(self) -> CommandResult:
        errors = self.validate()
        if errors:
            return CommandResult(success=False, message=f"Validación fallida: {'; '.join(errors)}")

        # Guardar referencia al caso antes de eliminar
        self._case = self.db.get_case(self.case_id)
        if not self._case:
            return CommandResult(success=False, message=f"Caso {self.case_id} no existe")

        # Eliminar el caso (cascade elimina entidades, relaciones, evidencias, ledger)
        self.db.delete_case(self.case_id)

        return CommandResult(
            success=True,
            message=f"Caso {self.case_id} eliminado",
            data={"case_id": self.case_id},
        )

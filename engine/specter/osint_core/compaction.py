"""
SpecterOSINT - Compaction Service
Compactación de resultados de colectores para reducir el tamaño del contexto.

Inspirado en la compactación de OpenCode: cuando un resultado es demasiado
grande para el contexto del agente, se compacta preservando los hallazgos
clave y guardando la evidencia completa en disco con una referencia URI.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from pydantic import BaseModel, Field
from specter import config as specter_config
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    RelationEdge,
    current_utc_iso,
)


class CompactEntity(BaseModel):
    """Entidad compactada: solo campos esenciales para el contexto."""

    id: str
    type: str
    value: str
    confidence: float = 1.0
    label: str | None = None
    attributes_ref: str | None = None  # URI a los atributos completos


class CompactRelation(BaseModel):
    """Relación compactada: solo campos esenciales."""

    source_id: str
    target_id: str
    relation_type: str
    confidence: float = 1.0
    attributes_ref: str | None = None


class CompactResult(BaseModel):
    """Resultado compactado listo para el contexto del agente."""

    collector_name: str
    source_target: str
    entities: list[CompactEntity] = Field(default_factory=list)
    relations: list[CompactRelation] = Field(default_factory=list)
    raw_payload_ref: str | None = None  # URI a la evidencia completa
    summary: str = ""
    compacted_at: str = Field(default_factory=current_utc_iso)
    original_size_bytes: int = 0
    compacted_size_bytes: int = 0


class CompactionService:
    """Servicio de compactación de resultados de colectores.

    La compactación:
    - Preserva hallazgos clave (entidades y relaciones esenciales)
    - Guarda evidencia completa en disco (raw_payload, attributes)
    - Crea referencias URI para recuperar la evidencia
    - Reduce el tamaño del contexto del agente
    """

    def __init__(self, storage_dir: Path | None = None) -> None:
        self.storage_dir = storage_dir or (specter_config.data_dir() / "compactions")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def compact_collector_result(self, result: CollectorResult) -> CompactResult:
        """Compacta un CollectorResult completo.

        - Entidades: preserva id, type, value, confidence; attributes van a disco
        - Relaciones: preserva source, target, type, confidence; attributes van a disco
        - raw_payload: se guarda en disco y se referencia por URI
        """
        original_size = len(result.model_dump_json().encode("utf-8"))

        # Compactar entidades
        compact_entities = self.compact_entities(result.entities)

        # Compactar relaciones
        compact_relations = self.compact_relations(result.relations)

        # Guardar raw_payload en disco
        raw_ref = None
        if result.raw_payload:
            raw_ref = self._save_evidence(
                f"{result.collector_name}_{result.source_target}",
                "raw_payload",
                result.raw_payload,
            )

        # Crear resumen ejecutivo
        summary = self.create_summary(result)

        compact_json = (
            CompactResult(
                collector_name=result.collector_name,
                source_target=result.source_target,
                entities=compact_entities,
                relations=compact_relations,
                raw_payload_ref=raw_ref,
                summary=summary,
                original_size_bytes=original_size,
            )
            .model_dump_json()
            .encode("utf-8")
        )

        return CompactResult(
            collector_name=result.collector_name,
            source_target=result.source_target,
            entities=compact_entities,
            relations=compact_relations,
            raw_payload_ref=raw_ref,
            summary=summary,
            original_size_bytes=original_size,
            compacted_size_bytes=len(compact_json),
        )

    def compact_entities(self, entities: list[EntityNode]) -> list[CompactEntity]:
        """Compacta una lista de entidades.

        Preserva id, type, value, confidence. Los attributes completos se
        guardan en disco y se referencian por URI.
        """
        compact: list[CompactEntity] = []
        for entity in entities:
            attrs_ref = None
            if entity.attributes:
                attrs_ref = self._save_evidence(
                    entity.id,
                    "entity_attributes",
                    json.dumps(entity.attributes, ensure_ascii=False),
                )
            compact.append(
                CompactEntity(
                    id=entity.id,
                    type=entity.type.value,
                    value=entity.value,
                    confidence=entity.confidence,
                    label=entity.label,
                    attributes_ref=attrs_ref,
                )
            )
        return compact

    def compact_relations(self, relations: list[RelationEdge]) -> list[CompactRelation]:
        """Compacta una lista de relaciones.

        Preserva source, target, type, confidence. Los attributes completos
        se guardan en disco y se referencian por URI.
        """
        compact: list[CompactRelation] = []
        for rel in relations:
            attrs_ref = None
            if rel.attributes:
                attrs_ref = self._save_evidence(
                    rel.edge_id,
                    "relation_attributes",
                    json.dumps(rel.attributes, ensure_ascii=False),
                )
            compact.append(
                CompactRelation(
                    source_id=rel.source_id,
                    target_id=rel.target_id,
                    relation_type=rel.relation_type.value,
                    confidence=rel.confidence,
                    attributes_ref=attrs_ref,
                )
            )
        return compact

    def create_summary(self, result: CollectorResult) -> str:
        """Crea un resumen ejecutivo del resultado.

        El resumen incluye:
        - Tipo de colector y objetivo
        - Conteo de entidades por tipo
        - Conteo de relaciones por tipo
        - Hallazgos clave (entidades de alta confianza)
        """
        lines: list[str] = []
        lines.append(f"## Resumen: {result.collector_name} → {result.source_target}")
        lines.append("")

        # Entidades por tipo
        if result.entities:
            type_counts: dict[str, int] = {}
            for e in result.entities:
                type_counts[e.type.value] = type_counts.get(e.type.value, 0) + 1
            lines.append("### Entidades")
            for etype, count in sorted(type_counts.items()):
                lines.append(f"- {etype}: {count}")
            lines.append("")

        # Relaciones por tipo
        if result.relations:
            rel_counts: dict[str, int] = {}
            for r in result.relations:
                rel_counts[r.relation_type.value] = rel_counts.get(r.relation_type.value, 0) + 1
            lines.append("### Relaciones")
            for rtype, count in sorted(rel_counts.items()):
                lines.append(f"- {rtype}: {count}")
            lines.append("")

        # Hallazgos clave (confianza >= 0.8)
        key_findings = [e for e in result.entities if e.confidence >= 0.8]
        if key_findings:
            lines.append("### Hallazgos clave (confianza ≥ 0.8)")
            for e in key_findings[:10]:  # máx 10 para no inflar el contexto
                lines.append(f"- [{e.type.value}] {e.value} ({e.confidence:.0%})")
            if len(key_findings) > 10:
                lines.append(f"- ... y {len(key_findings) - 10} más")
            lines.append("")

        # Metadata relevante
        if result.metadata:
            lines.append("### Metadata")
            for key, value in result.metadata.items():
                if isinstance(value, (str, int, float, bool)):
                    lines.append(f"- {key}: {value}")
            lines.append("")

        return "\n".join(lines)

    def _save_evidence(self, identifier: str, kind: str, content: str) -> str:
        """Guarda evidencia en disco y retorna la URI de referencia.

        Esquema de archivo: {storage_dir}/{kind}/{safe_id}.json
        URI: compaction://{kind}/{safe_id}
        """
        # Sanitizar caracteres inválidos en filenames (Windows y Unix)
        safe_id = (
            identifier.replace("/", "_")
            .replace(":", "_")
            .replace(" ", "_")
            .replace("->", "_to_")
            .replace("<", "_")
            .replace(">", "_")
            .replace('"', "_")
            .replace("|", "_")
            .replace("?", "_")
            .replace("*", "_")
        )
        kind_dir = self.storage_dir / kind
        kind_dir.mkdir(parents=True, exist_ok=True)

        file_path = kind_dir / f"{safe_id}.json"
        file_path.write_text(content, encoding="utf-8")

        return f"compaction://{kind}/{safe_id}"

    def load_evidence(self, uri: str) -> str | None:
        """Carga evidencia desde una URI de compactación.

        Retorna el contenido original o None si no existe.
        """
        if not uri.startswith("compaction://"):
            return None
        parts = uri.removeprefix("compaction://").split("/", 1)
        if len(parts) != 2:
            return None
        kind, safe_id = parts
        file_path = self.storage_dir / kind / f"{safe_id}.json"
        if not file_path.exists():
            return None
        return file_path.read_text(encoding="utf-8")

    def should_compact(self, result: CollectorResult, threshold_bytes: int = 10000) -> bool:
        """Determina si un resultado debe compactarse.

        Umbral por defecto: 10KB. Los resultados más grandes se compactan
        automáticamente para no inflar el contexto del agente.
        """
        size = len(result.model_dump_json().encode("utf-8"))
        return size > threshold_bytes


# Servicio global del motor
compaction_service = CompactionService()


def generate_compaction_id() -> str:
    """Genera un identificador único para una compactación."""
    return f"compact-{uuid.uuid4().hex[:12]}"

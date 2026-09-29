"""
WraithOSINT - Correlation Rules Engine
Motor de correlaciones declarativas inspirado en SpiderFoot.

Las reglas se definen en YAML y se ejecutan contra la base de datos.
Cada regla tiene:
  - collections: filtros para extraer entidades de la BD
  - aggregation: campo por el cual agrupar
  - analysis: método de análisis (threshold, outlier, etc.)
  - headline: plantilla para el resultado

Sintaxis de campos con prefijos:
  - source.<campo>: campo de la entidad origen en una relación
  - child.<campo>: campo de la entidad destino en una relación
  - entity.<campo>: campo de la entidad actual
  - <campo>: campo directo de la entidad (equivalente a entity.<campo>)
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator
from specter.osint_core.database import Database
from specter.osint_core.models import EntityNode, RelationEdge

# --- Modelos Pydantic para reglas YAML ---


class RuleMeta(BaseModel):
    """Metadatos de una regla de correlación."""

    name: str
    description: str
    risk: str = "INFO"


class CollectFilter(BaseModel):
    """Filtro individual dentro de un bloque collect."""

    method: str  # exact | regex
    field: str
    value: str | list[str]

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        if v not in ("exact", "regex"):
            raise ValueError(f"Método de colección inválido: {v}")
        return v


class CollectBlock(BaseModel):
    """Bloque de colección: lista de filtros AND."""

    collect: list[CollectFilter]


class AggregationConfig(BaseModel):
    """Configuración de agrupación."""

    field: str


class AnalysisConfig(BaseModel):
    """Configuración de análisis."""

    method: str  # threshold | outlier | first_collection_only | match_all_to_first_collection
    field: str | None = None
    minimum: int | None = None
    maximum_percent: float | None = None
    count_unique_only: bool = False

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        valid = ("threshold", "outlier", "first_collection_only", "match_all_to_first_collection")
        if v not in valid:
            raise ValueError(f"Método de análisis inválido: {v}. Válidos: {valid}")
        return v


class CorrelationRule(BaseModel):
    """Regla de correlación completa."""

    id: str
    version: int = 1
    meta: RuleMeta
    collections: list[CollectBlock]
    aggregation: AggregationConfig | None = None
    analysis: list[AnalysisConfig] | None = None
    headline: str


# --- Motor de correlación ---


class CorrelationResult:
    """Resultado de una correlación ejecutada."""

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        risk: str,
        headline: str,
        entities: list[EntityNode],
        details: dict[str, Any] | None = None,
    ):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.risk = risk
        self.headline = headline
        self.entities = entities
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "risk": self.risk,
            "headline": self.headline,
            "entities": [
                {
                    "id": e.id,
                    "type": e.type.value,
                    "value": e.value,
                    "label": e.label,
                    "confidence": e.confidence,
                }
                for e in self.entities
            ],
            "entity_count": len(self.entities),
            "details": self.details,
        }


class CorrelationRulesEngine:
    """Motor que ejecuta reglas de correlación YAML contra la BD."""

    def __init__(self, db: Database, rules_dir: str | Path | None = None):
        self.db = db
        self.rules_dir = Path(rules_dir) if rules_dir else self._default_rules_dir()
        self._rules: dict[str, CorrelationRule] = {}
        self._current_case_id: str | None = None

    @staticmethod
    def _default_rules_dir() -> Path:
        """Directorio por defecto de reglas: engine/specter/correlations."""
        return Path(__file__).resolve().parent.parent / "correlations"

    def load_rules(self) -> dict[str, CorrelationRule]:
        """Carga todas las reglas YAML del directorio."""
        self._rules = {}
        if not self.rules_dir.exists():
            return self._rules

        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    raw = yaml.safe_load(f)
                if not raw:
                    continue
                rule = CorrelationRule(**raw)
                self._rules[rule.id] = rule
            except Exception:
                # Regla inválida: se omite en silencio
                continue

        return self._rules

    def get_rule(self, rule_id: str) -> CorrelationRule | None:
        """Obtiene una regla por ID."""
        if not self._rules:
            self.load_rules()
        return self._rules.get(rule_id)

    def list_rules(self) -> list[dict[str, str]]:
        """Lista todas las reglas cargadas."""
        if not self._rules:
            self.load_rules()
        return [
            {
                "id": r.id,
                "name": r.meta.name,
                "risk": r.meta.risk,
            }
            for r in self._rules.values()
        ]

    def execute_rule(self, case_id: str, rule_id: str) -> list[CorrelationResult]:
        """Ejecuta una regla específica contra un caso."""
        rule = self.get_rule(rule_id)
        if not rule:
            return []

        # Establecer el caso actual para que _find_entity_by_id pueda buscar en la BD
        self._current_case_id = case_id

        # Obtener todas las entidades del caso
        all_entities = self.db.get_case_entities(case_id)
        all_relations = self.db.get_case_relations(case_id)

        # Ejecutar colecciones
        collection_results: list[list[EntityNode]] = []
        for block in rule.collections:
            filtered = self._apply_collect_block(all_entities, all_relations, block)
            collection_results.append(filtered)

        if not collection_results:
            return []

        # Agregar entidades por campo de agregación
        agg_field = rule.aggregation.field if rule.aggregation else "data"

        # Ejecutar análisis
        results: list[CorrelationResult] = []

        if not rule.analysis:
            # Sin análisis: retornar todas las entidades de la primera colección
            if collection_results[0]:
                results.append(
                    CorrelationResult(
                        rule_id=rule.id,
                        rule_name=rule.meta.name,
                        risk=rule.meta.risk,
                        headline=rule.headline.format(data="multiple entities"),
                        entities=collection_results[0],
                    )
                )
        else:
            for analysis in rule.analysis:
                analysis_results = self._run_analysis(
                    case_id, rule, collection_results, agg_field, analysis, all_entities
                )
                results.extend(analysis_results)

        return results

    def execute_all_rules(self, case_id: str) -> list[CorrelationResult]:
        """Ejecuta todas las reglas cargadas contra un caso."""
        if not self._rules:
            self.load_rules()

        all_results: list[CorrelationResult] = []
        for rule_id in self._rules:
            results = self.execute_rule(case_id, rule_id)
            all_results.extend(results)

        return all_results

    def _apply_collect_block(
        self,
        entities: list[EntityNode],
        relations: list[RelationEdge],
        block: CollectBlock,
    ) -> list[EntityNode]:
        """Aplica los filtros de un bloque collect (AND lógico)."""
        result = entities

        for filt in block.collect:
            result = self._apply_filter(result, relations, filt)

        return result

    def _apply_filter(
        self,
        entities: list[EntityNode],
        relations: list[RelationEdge],
        filt: CollectFilter,
    ) -> list[EntityNode]:
        """Aplica un filtro individual a la lista de entidades."""
        filtered: list[EntityNode] = []

        for entity in entities:
            if self._entity_matches(entity, relations, filt):
                filtered.append(entity)

        return filtered

    def _entity_matches(
        self,
        entity: EntityNode,
        relations: list[RelationEdge],
        filt: CollectFilter,
    ) -> bool:
        """Verifica si una entidad coincide con un filtro."""
        field_value = self._resolve_field(entity, relations, filt.field)

        if filt.method == "exact":
            return self._match_exact(field_value, filt.value)
        elif filt.method == "regex":
            return self._match_regex(field_value, filt.value)

        return False

    def _resolve_field(
        self,
        entity: EntityNode,
        relations: list[RelationEdge],
        field: str,
    ) -> str:
        """Resuelve un campo con prefijos source., child., entity."""
        if field.startswith("source."):
            # Buscar en relaciones donde esta entidad es el target
            source_field = field[7:]
            for rel in relations:
                if rel.target_id == entity.id:
                    source_entity = self._find_entity_by_id(relations, rel.source_id)
                    if source_entity:
                        return self._get_entity_value(source_entity, source_field)
            return ""

        elif field.startswith("child."):
            # Buscar en relaciones donde esta entidad es el source
            child_field = field[6:]
            for rel in relations:
                if rel.source_id == entity.id:
                    child_entity = self._find_entity_by_id(relations, rel.target_id)
                    if child_entity:
                        return self._get_entity_value(child_entity, child_field)
            return ""

        elif field.startswith("entity."):
            entity_field = field[7:]
            return self._get_entity_value(entity, entity_field)

        else:
            # Campo directo (equivalente a entity.<campo>)
            return self._get_entity_value(entity, field)

    def _find_entity_by_id(
        self,
        relations: list[RelationEdge],
        entity_id: str,
    ) -> EntityNode | None:
        """Busca una entidad por ID en la BD.

        Primero intenta encontrar la entidad en la BD (para obtener sus atributos
        completos). Si no la existe, crea un stub basado en el ID.
        """
        # Buscar en la BD
        try:
            # Obtener todas las entidades del caso y buscar por ID
            # Nota: esto es ineficiente para casos grandes, pero correcto
            all_entities = self.db.get_case_entities(self._current_case_id)
            for entity in all_entities:
                if entity.id == entity_id:
                    return entity
        except Exception:
            pass

        # Si no se encuentra, crear un stub
        return EntityNode.from_node_id(entity_id)

    def _get_entity_value(self, entity: EntityNode, field: str) -> str:
        """Obtiene un valor de una entidad por nombre de campo."""
        if field == "type":
            return entity.type.value
        elif field in ("data", "value"):
            return entity.value
        elif field == "label":
            return entity.label or entity.value
        elif field == "id":
            return entity.id
        elif field == "confidence":
            return str(entity.confidence)
        else:
            # Buscar en attributes
            return str(entity.attributes.get(field, ""))

    def _match_exact(self, value: str, expected: str | list[str]) -> bool:
        """Coincidencia exacta."""
        if isinstance(expected, list):
            return value in expected
        return value == expected

    def _match_regex(self, value: str, patterns: str | list[str]) -> bool:
        """Coincidencia por regex (soporta 'not' para negación).

        Cuando se pasa una lista de patrones, la entidad debe coincidir con
        AL MENOS UNO de ellos (OR lógico). Los patrones con prefijo 'not '
        se tratan como negaciones: si coinciden, la entidad NO pasa el filtro.
        """
        if isinstance(patterns, str):
            patterns = [patterns]

        # Primero verificar negaciones: si alguna coincide, retorna False
        for pattern in patterns:
            if pattern.startswith("not "):
                actual_pattern = pattern[4:]
                if re.search(actual_pattern, value, re.IGNORECASE):
                    return False

        # Luego verificar patrones positivos: al menos uno debe coincidir
        positive_patterns = [p for p in patterns if not p.startswith("not ")]
        if not positive_patterns:
            return True

        return any(re.search(p, value, re.IGNORECASE) for p in positive_patterns)

    def _run_analysis(
        self,
        case_id: str,
        rule: CorrelationRule,
        collection_results: list[list[EntityNode]],
        agg_field: str,
        analysis: AnalysisConfig,
        all_entities: list[EntityNode],
    ) -> list[CorrelationResult]:
        """Ejecuta un método de análisis."""
        if analysis.method == "threshold":
            return self._analysis_threshold(rule, collection_results, agg_field, analysis)
        elif analysis.method == "outlier":
            return self._analysis_outlier(rule, collection_results, agg_field, analysis)
        elif analysis.method == "first_collection_only":
            return self._analysis_first_collection_only(rule, collection_results)
        elif analysis.method == "match_all_to_first_collection":
            return self._analysis_match_all_to_first(rule, collection_results, agg_field)

        return []

    def _analysis_threshold(
        self,
        rule: CorrelationRule,
        collection_results: list[list[EntityNode]],
        agg_field: str,
        analysis: AnalysisConfig,
    ) -> list[CorrelationResult]:
        """Análisis por umbral: agrupa por campo y filtra por mínimo."""
        minimum = analysis.minimum or 2
        count_unique = analysis.count_unique_only

        # Agrupar entidades por campo de agregación
        buckets: dict[str, list[EntityNode]] = defaultdict(list)
        for collection in collection_results:
            for entity in collection:
                key = self._get_entity_value(entity, agg_field)
                if key:
                    buckets[key].append(entity)

        results: list[CorrelationResult] = []
        for key, entities in buckets.items():
            if count_unique:
                # Contar tipos únicos
                unique_types = {e.type.value for e in entities}
                if len(unique_types) >= minimum:
                    results.append(
                        CorrelationResult(
                            rule_id=rule.id,
                            rule_name=rule.meta.name,
                            risk=rule.meta.risk,
                            headline=rule.headline.format(data=key),
                            entities=entities,
                            details={"unique_types": list(unique_types), "count": len(entities)},
                        )
                    )
            else:
                if len(entities) >= minimum:
                    results.append(
                        CorrelationResult(
                            rule_id=rule.id,
                            rule_name=rule.meta.name,
                            risk=rule.meta.risk,
                            headline=rule.headline.format(data=key),
                            entities=entities,
                            details={"count": len(entities)},
                        )
                    )

        return results

    def _analysis_outlier(
        self,
        rule: CorrelationRule,
        collection_results: list[list[EntityNode]],
        agg_field: str,
        analysis: AnalysisConfig,
    ) -> list[CorrelationResult]:
        """Análisis de valores atípicos: entidades en el X% menos frecuente."""
        max_percent = analysis.maximum_percent or 10.0

        # Contar frecuencia de cada valor
        frequency: dict[str, int] = defaultdict(int)
        total = 0
        for collection in collection_results:
            for entity in collection:
                key = self._get_entity_value(entity, agg_field)
                if key:
                    frequency[key] += 1
                    total += 1

        if total == 0:
            return []

        # Calcular umbral
        threshold = total * (max_percent / 100.0)

        # Filtrar outliers
        results: list[CorrelationResult] = []
        for key, count in frequency.items():
            if count <= threshold:
                # Encontrar las entidades con este valor
                entities = []
                for collection in collection_results:
                    for entity in collection:
                        if self._get_entity_value(entity, agg_field) == key:
                            entities.append(entity)

                results.append(
                    CorrelationResult(
                        rule_id=rule.id,
                        rule_name=rule.meta.name,
                        risk=rule.meta.risk,
                        headline=rule.headline.format(data=key),
                        entities=entities,
                        details={
                            "count": count,
                            "total": total,
                            "percent": round(count / total * 100, 2),
                        },
                    )
                )

        return results

    def _analysis_first_collection_only(
        self,
        rule: CorrelationRule,
        collection_results: list[list[EntityNode]],
    ) -> list[CorrelationResult]:
        """Retorna solo las entidades de la primera colección."""
        if not collection_results or not collection_results[0]:
            return []

        return [
            CorrelationResult(
                rule_id=rule.id,
                rule_name=rule.meta.name,
                risk=rule.meta.risk,
                headline=rule.headline.format(data="first collection"),
                entities=collection_results[0],
            )
        ]

    def _analysis_match_all_to_first(
        self,
        rule: CorrelationRule,
        collection_results: list[list[EntityNode]],
        agg_field: str,
    ) -> list[CorrelationResult]:
        """Match de todas las colecciones contra la primera."""
        if len(collection_results) < 2:
            return []

        first_collection = collection_results[0]
        other_collections = collection_results[1:]

        results: list[CorrelationResult] = []

        for entity in first_collection:
            key = self._get_entity_value(entity, agg_field)
            if not key:
                continue

            # Verificar si está en todas las otras colecciones
            found_in_all = True
            matched_entities = [entity]

            for other in other_collections:
                found = False
                for other_entity in other:
                    if self._get_entity_value(other_entity, agg_field) == key:
                        found = True
                        matched_entities.append(other_entity)
                        break
                if not found:
                    found_in_all = False
                    break

            if found_in_all:
                results.append(
                    CorrelationResult(
                        rule_id=rule.id,
                        rule_name=rule.meta.name,
                        risk=rule.meta.risk,
                        headline=rule.headline.format(data=key),
                        entities=matched_entities,
                    )
                )

        return results

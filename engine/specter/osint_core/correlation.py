"""
SpecterOSINT - Correlation Engine
Correlación de artefactos entre casos y resolución de identidades.

Tres capacidades, todas explicables (cada resultado lleva su motivo y score):

1. `cross_case_matches`  — el mismo dominio/email/alias/IP aparece en más de un
   caso: vínculo real entre investigaciones que hoy viven en silos de SQLite.
2. `case_similarity`     — solapamiento entre dos casos con veredicto y Jaccard.
3. `identity_candidates` — alias, email y perfil social que apuntan a la misma
   persona dentro de un caso, normalizando *handles* (@Alice / alice.dev / a.l.i.c.e).

Nada se escribe en el grafo automáticamente: son *candidatos* con score para que
el analista confirme con `link_entities` (y quede en la cadena de custodia).
"""

from __future__ import annotations

import itertools
import re
from collections import defaultdict
from urllib.parse import urlparse

from specter.osint_core.database import Database
from specter.osint_core.models import EntityNode, EntityType

# Resolución probabilística Fellegi-Sunter (opcional en runtime, import perezoso
# en el método identity_candidates_fs para no encadenar el arranque).

# Tipos que representan una identidad (persona, alias o cuenta).
IDENTITY_TYPES = frozenset(
    {
        EntityType.ALIAS,
        EntityType.PERSON,
        EntityType.SOCIAL_PROFILE,
        EntityType.EMAIL,
    }
)

SEPARATORS = re.compile(r"[\s._\-]+")
TRAILING_DIGITS = re.compile(r"\d{1,4}$")


def identity_value(entity: EntityNode) -> str:
    """Valor comparable de una entidad de identidad (sin URL ni dominio de email)."""
    value = entity.value.strip()
    if entity.type == EntityType.SOCIAL_PROFILE:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        tail = parsed.path.rstrip("/").rsplit("/", 1)[-1]
        return tail or parsed.netloc
    if entity.type == EntityType.EMAIL:
        return value.split("@", 1)[0]
    return value.lstrip("@")


def normalize_handle(value: str) -> str:
    """Normaliza un handle: minúsculas, sin '@' y sin separadores (a.l.i.c.e → alice)."""
    text = value.strip().lower().lstrip("@")
    return SEPARATORS.sub("", text)


def handle_keys(entity: EntityNode) -> set[str]:
    """Claves por las que una entidad puede coincidir con otra identidad.

    Se incluye la variante sin dígitos finales (alice42 → alice) porque es un
    patrón habitual de cuentas duplicadas; esa coincidencia puntúa más bajo.
    """
    key = normalize_handle(identity_value(entity))
    if not key:
        return set()
    keys = {key}
    stripped = TRAILING_DIGITS.sub("", key)
    if stripped and stripped != key:
        keys.add(stripped)
    return keys


def _tf_tokens(entity: EntityNode) -> set[str]:
    """Tokens de frecuencia de una entidad (los mismos que penaliza compare_pair).

    El handle normalizado, el email completo en minúsculas y la parte local del
    email normalizada: así un valor repetido (p. ej. 12 variantes de
    'carlos.garcia' procedentes del mismo pivot) baja su propio peso de acuerdo.
    """
    value = entity.value.strip().lower()
    if not value:
        return set()
    tokens = {normalize_handle(identity_value(entity))}
    if entity.type.value == "EMAIL":
        tokens.add(value)
        tokens.add(value.split("@", 1)[0].replace("+", "").replace(".", ""))
    return {t for t in tokens if t}


class CorrelationEngine:
    def __init__(self, db: Database):
        self.db = db

    def cross_case_matches(
        self, case_id: str | None = None, entity_types: list[str] | None = None
    ) -> dict:
        """Artefactos compartidos por dos o más casos (opcionalmente anclado a uno)."""
        shared = self.db.find_shared_entities(case_id=case_id, entity_types=entity_types)
        by_type: dict[str, int] = {}
        cases: set[str] = set()
        for row in shared:
            by_type[row["type"]] = by_type.get(row["type"], 0) + 1
            cases.update(row["case_ids"])

        return {
            "anchor_case": case_id,
            "total_shared_entities": len(shared),
            "cases_involved": sorted(cases),
            "cases_involved_count": len(cases),
            "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
            "matches": [
                {
                    "entity_id": row["id"],
                    "type": row["type"],
                    "value": row["value"],
                    "confidence": row["confidence"],
                    "case_count": row["case_count"],
                    "case_ids": row["case_ids"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                }
                for row in shared
            ],
        }

    def case_similarity(self, case_a: str, case_b: str) -> dict:
        """Solapamiento entre dos casos: cuántos artefactos comparten y cuáles."""
        entities_a = {e.id: e for e in self.db.get_case_entities(case_a)}
        entities_b = {e.id: e for e in self.db.get_case_entities(case_b)}
        shared_ids = set(entities_a) & set(entities_b)
        union = set(entities_a) | set(entities_b)
        jaccard = round(len(shared_ids) / len(union), 4) if union else 0.0

        shared_by_type: dict[str, int] = {}
        for entity_id in shared_ids:
            entity_type = entities_a[entity_id].type.value
            shared_by_type[entity_type] = shared_by_type.get(entity_type, 0) + 1

        if not shared_ids:
            verdict = "NONE"
        elif len(shared_ids) >= 3 or jaccard >= 0.25:
            verdict = "HIGH"
        else:
            verdict = "MODERATE"

        return {
            "case_a": case_a,
            "case_b": case_b,
            "entities_a": len(entities_a),
            "entities_b": len(entities_b),
            "shared_count": len(shared_ids),
            "jaccard": jaccard,
            "verdict": verdict,
            "shared_by_type": dict(sorted(shared_by_type.items(), key=lambda kv: -kv[1])),
            "shared_entities": [
                {
                    "entity_id": entity_id,
                    "type": entities_a[entity_id].type.value,
                    "value": entities_a[entity_id].value,
                    "confidence": max(
                        entities_a[entity_id].confidence, entities_b[entity_id].confidence
                    ),
                }
                for entity_id in sorted(shared_ids)
            ],
        }

    def identity_candidates(self, case_id: str, min_score: float = 0.7, limit: int = 50) -> dict:
        """Propuestas de resolución de identidad dentro de un caso, con score."""
        entities = [
            e
            for e in self.db.get_case_entities(case_id)
            if e.type in IDENTITY_TYPES and e.value.strip()
        ]

        groups: dict[str, list[EntityNode]] = defaultdict(list)
        for entity in entities:
            for key in handle_keys(entity):
                groups[key].append(entity)

        candidates: list[dict] = []
        seen_pairs: set[tuple[str, str]] = set()
        for key in sorted(groups):
            members = {e.id: e for e in groups[key]}
            if len(members) < 2:
                continue
            for left, right in itertools.combinations(sorted(members), 2):
                a, b = members[left], members[right]
                if (a.id, b.id) in seen_pairs:
                    continue
                seen_pairs.add((a.id, b.id))
                score, reason = self._pair_score(a, b, key)
                if score < min_score:
                    continue
                candidates.append(
                    {
                        "score": score,
                        "reason": reason,
                        "normalized_key": key,
                        "suggested_relation": "CORRELATED_WITH",
                        "entities": [
                            {
                                "entity_id": e.id,
                                "type": e.type.value,
                                "value": e.value,
                                "label": e.label or e.value,
                                "confidence": e.confidence,
                            }
                            for e in (a, b)
                        ],
                    }
                )

        candidates.sort(key=lambda c: -c["score"])
        return {
            "case_id": case_id,
            "analyzed_entities": len(entities),
            "total_candidates": len(candidates),
            "min_score": min_score,
            "candidates": candidates[:limit],
        }

    @staticmethod
    def _pair_score(a: EntityNode, b: EntityNode, key: str) -> tuple[float, str]:
        if a.value.strip().lower() == b.value.strip().lower():
            return 0.9, f"valor idéntico: '{a.value.strip()}' en {a.type.value} y {b.type.value}"
        if normalize_handle(identity_value(a)) == normalize_handle(identity_value(b)):
            if a.type != b.type:
                return (
                    0.85,
                    f"handle normalizado '{key}' compartido entre {a.type.value} y {b.type.value}",
                )
            return 0.8, f"handle normalizado '{key}' repetido en {a.type.value}"
        return 0.6, f"coincidencia débil por variante numérica '{key}'"

    # ------------------------------------------------------------- Fellegi-Sunter
    def identity_candidates_fs(
        self,
        case_id: str,
        match_threshold: float | None = None,
        review_threshold: float | None = None,
        field_weights: dict[str, float] | None = None,
        limit: int = 50,
    ) -> dict:
        """Resolución de identidad probabilística (Fellegi-Sunter).

        A diferencia de `identity_candidates` (heurística con scores fijos),
        aquí cada par recibe un score log2 aditivo y explicable campo a campo:
        R >= match_threshold → match propuesto; entre umbrales → revisión
        humana; debajo → no coincidencia. Ver `osint_core/entity_resolution.py`.
        """
        from specter.osint_core.entity_resolution import (
            DEFAULT_THRESHOLDS,
            reset_term_frequencies,
            set_term_frequencies,
        )

        thresholds = {**DEFAULT_THRESHOLDS}
        if match_threshold is not None:
            thresholds["match"] = float(match_threshold)
        if review_threshold is not None:
            thresholds["review"] = float(review_threshold)

        entities = [
            e
            for e in self.db.get_case_entities(case_id)
            if e.type in IDENTITY_TYPES and e.value.strip()
        ]

        # Ajuste de frecuencia del término (Splink: term-frequency-adjustments):
        # un valor repetido muchas veces en el caso (12 variantes del mismo
        # handle) no prueba identidad al acordar. Se calcula sobre los mismos
        # tokens que produce compare_pair.
        tf_counts: dict[str, int] = {}
        for entity in entities:
            for token in _tf_tokens(entity):
                tf_counts[token] = tf_counts.get(token, 0) + 1
        set_term_frequencies(tf_counts, total=len(entities))
        try:
            return self._fs_compare_batch(case_id, entities, thresholds, field_weights, limit)
        finally:
            reset_term_frequencies()

    def _fs_compare_batch(
        self,
        case_id: str,
        entities: list[EntityNode],
        thresholds: dict[str, float],
        field_weights: dict[str, float] | None,
        limit: int,
    ) -> dict:
        """Compara los pares bloqueados con las frecuencias ya cargadas."""
        from specter.osint_core.entity_resolution import compare_pair, explain_score

        groups: dict[str, list[EntityNode]] = defaultdict(list)
        for entity in entities:
            for key in handle_keys(entity):
                groups[key].append(entity)

        candidates: list[dict] = []
        seen_pairs: set[tuple[str, str]] = set()
        for key in sorted(groups):
            members = {e.id: e for e in groups[key]}
            if len(members) < 2:
                continue
            for left, right in itertools.combinations(sorted(members), 2):
                a, b = members[left], members[right]
                if (a.id, b.id) in seen_pairs:
                    continue
                seen_pairs.add((a.id, b.id))
                pair = compare_pair(a, b, field_weights=field_weights, thresholds=thresholds)
                if pair.verdict == "non_match":
                    continue
                candidates.append(
                    {
                        "score": pair.probability,
                        "weight_log2": pair.total_weight,
                        "verdict": pair.verdict,
                        "explanation": explain_score(pair),
                        "comparisons": [
                            {
                                "field": c.field,
                                "agreement": c.agreement_level,
                                "weight_log2": c.weight,
                                "detail": c.detail,
                            }
                            for c in pair.comparisons
                        ],
                        "normalized_key": key,
                        "suggested_relation": "CORRELATED_WITH",
                        "entities": [pair.entity_a, pair.entity_b],
                    }
                )

        candidates.sort(key=lambda c: (-c["weight_log2"], -c["score"]))
        return {
            "case_id": case_id,
            "model": "fellegi-sunter",
            "thresholds": thresholds,
            "analyzed_entities": len(entities),
            "compared_pairs": len(seen_pairs),
            "total_candidates": len(candidates),
            "candidates": candidates[:limit],
        }

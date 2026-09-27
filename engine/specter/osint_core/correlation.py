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

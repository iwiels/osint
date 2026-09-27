"""
SpecterOSINT - Person Investigator
Huella digital de un nombre completo, 100% pasiva (solo fuentes públicas indexadas).

Estrategia por capas:
  1. Derivar candidatos de username a partir del nombre (pivote posterior con
     el colector de identidad: investigate_identity).
  2. Dorks de documentos de identidad en filtraciones indexadas (DNI/NIE/
     pasaporte/CUIT + nombre en Pastebin/Rentry) y dorks de presencia pública.
  3. Estructura del nombre (tokens, doble apellido) para evaluar la riqueza
     del dato antes de recomendar pivotes.

Clasificación de hallazgos:
  - PERSON      -> el nombre canónico
  - ALIAS       -> cada candidato de username derivado
  - DOCUMENT_ID -> se crea al confirmar menciones vía hunt_documents_and_leaks
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from specter.collectors.base import BaseCollector
from specter.collectors.web import WebSearchCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

_ACADEMIC_KEYWORDS = (
    
    "universidad",
    "facultad",
    "estudiante",
    
    "tesis",
    "docente",
    "grado",
    "bachiller",
    "alumno",
)
_DOC_HOSTS = ("scribd", "academia.edu", "researchgate", "cybertesis", "repositorio")

# ---------------------------------------------------------------------------
# Derivación de usernames a partir de un nombre completo
# ---------------------------------------------------------------------------

# Partículas que no aportan a un handle (ES/LATAM/EN).
_STOP_PARTICLES = {
    "de",
    "del",
    "la",
    "las",
    "los",
    "el",
    "y",
    "e",
    "da",
    "di",
    "van",
    "von",
    "mc",
    "mac",
}


def strip_accents(value: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", value) if not unicodedata.combining(c))


def derive_username_candidates(full_name: str) -> list[str]:
    """`Ana María De la Cruz Pinto` -> [ana.delacruz, anadelacruz, ...]."""
    cleaned = strip_accents(full_name.lower())
    cleaned = re.sub(r"[^a-z0-9\s]", " ", cleaned)
    parts = [p for p in cleaned.split() if p and p not in _STOP_PARTICLES]
    if not parts:
        return []

    first = parts[0]
    last = parts[-1] if len(parts) > 1 else ""
    joined = "".join(parts)
    candidates: list[str] = []

    def add(c: str) -> None:
        if 3 <= len(c) <= 30 and c not in candidates:
            candidates.append(c)

    if last:
        add(f"{first}.{last}")
        add(f"{first}{last}")
        add(f"{first}_{last}")
        add(f"{first[0]}{last}")
        add(f"{first[0]}.{last}")
    else:
        add(first)
    add(joined[:30])
    return candidates[:12]


# ---------------------------------------------------------------------------
# Dorks pasivos (documentos de identidad + presencia pública)
# ---------------------------------------------------------------------------

_DOC_DORK_TEMPLATES = [
    '"dni" {name}',
    '"nie" {name}',
    '"pasaporte" {name}',
    '"cuit" {name}',
    '"cédula" {name}',
    'intext:"documento de identidad" {name}',
    "{name} (site:pastebin.com | site:rentry.co)",
]

_PRESENCE_DORK_TEMPLATES = [
    "{name} (site:linkedin.com | site:x.com | site:instagram.com)",
    "{name} (site:github.com | site:gitlab.com)",
    "{name} (filetype:pdf | filetype:doc | filetype:docx)",
    "{name} (site:academia.edu | site:researchgate.net)",
    "{name} (site:boe.es | site:infoleg.gob.ar | site:gob.es)",
    '{name} (intitle:"cv" | inurl:"cv")',
]


def build_document_dorks(full_name: str) -> list[str]:
    name_q = f'"{full_name}"'
    return [t.format(name=name_q) for t in _DOC_DORK_TEMPLATES]


def build_presence_dorks(full_name: str) -> list[str]:
    name_q = f'"{full_name}"'
    return [t.format(name=name_q) for t in _PRESENCE_DORK_TEMPLATES]


# ---------------------------------------------------------------------------
# Colector
# ---------------------------------------------------------------------------


class PersonInvestigator(BaseCollector):
    """Huella digital de nombre completo: usernames derivados + dorks de
    documentos/identidad y presencia pública. Sin interacción activa."""

    def __init__(self):
        super().__init__(name="person_investigator")

    async def collect(
        self, target: str, execute_search: bool = False, **kwargs: Any
    ) -> CollectorResult:
        full_name = " ".join(target.split())  # normaliza espacios
        if not full_name:
            raise ValueError("Nombre completo requerido")

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        report: dict[str, Any] = {"full_name": full_name}

        person_node = EntityNode.create(
            type=EntityType.PERSON,
            value=full_name,
            label=f"Persona: {full_name}",
            attributes={"derived_from": "direct_input"},
        )
        entities.append(person_node)

        # 1. Usernames derivados (pivote posterior con investigate_identity)
        username_candidates = derive_username_candidates(full_name)
        for candidate in username_candidates:
            alias_node = EntityNode.create(
                type=EntityType.ALIAS,
                value=candidate,
                label=f"Alias derivado: @{candidate}",
                attributes={"derived_from": "name_derivation"},
            )
            entities.append(alias_node)
            relations.append(
                RelationEdge(
                    source_id=person_node.id,
                    target_id=alias_node.id,
                    relation_type=RelationType.USES_ALIAS,
                )
            )

        # 2. Dorks de documentos de identidad y presencia pública
        doc_dorks = build_document_dorks(full_name)
        presence_dorks = build_presence_dorks(full_name)
        report["dorks"] = {
            "document_identity": doc_dorks,
            "presence": presence_dorks,
            "total": len(doc_dorks) + len(presence_dorks),
        }

        # 3. Búsqueda activa y enriquecimiento de evidencias si se solicita
        if execute_search or kwargs.get("execute_search"):
            try:
                search_collector = WebSearchCollector()
                search_res = await search_collector.collect(f'"{full_name}"', top_k=10)
                report["web_search"] = {
                    "results_count": search_res.metadata.get("results", 0),
                    "ok": search_res.metadata.get("ok", False),
                }
                seen_entity_keys: set[tuple[EntityType, str]] = {
                    (e.type, e.value) for e in entities
                }
                for hit_entity in search_res.entities:
                    if hit_entity.type == EntityType.ALIAS:
                        continue
                    url = hit_entity.value
                    title = str(hit_entity.attributes.get("title", "")).lower()
                    snippet = str(hit_entity.attributes.get("snippet", "")).lower()
                    combined = f"{url} {title} {snippet}"

                    # Detectar instituciones académicas
                    if any(kw in combined for kw in _ACADEMIC_KEYWORDS):
                        inst_name = (
                            "UNMSM"
                            if "unmsm" in combined or "san marcos" in combined
                            else "Institución Universitaria"
                        )
                        inst_key = (EntityType.ORGANIZATION, inst_name)
                        if inst_key not in seen_entity_keys:
                            seen_entity_keys.add(inst_key)
                            inst_node = EntityNode.create(
                                type=EntityType.ORGANIZATION,
                                value=inst_name,
                                label=f"Institución: {inst_name}",
                                attributes={"detected_from": url, "context": snippet[:200]},
                                confidence=0.85,
                            )
                            entities.append(inst_node)
                            relations.append(
                                RelationEdge(
                                    source_id=person_node.id,
                                    target_id=inst_node.id,
                                    relation_type=RelationType.ASSOCIATED_WITH,
                                    confidence=0.85,
                                )
                            )

                    # Detectar documentos / publicaciones
                    if (
                        any(doc_host in url.lower() for doc_host in _DOC_HOSTS)
                        or "filetype:pdf" in combined
                        or ".pdf" in url.lower()
                    ):
                        doc_key = (EntityType.FILE_ARTIFACT, url)
                        if doc_key not in seen_entity_keys:
                            seen_entity_keys.add(doc_key)
                            doc_node = EntityNode.create(
                                type=EntityType.FILE_ARTIFACT,
                                value=url,
                                label=f"Documento: {hit_entity.attributes.get('title', url)[:40]}",
                                attributes=dict(hit_entity.attributes),
                                confidence=0.85,
                            )
                            entities.append(doc_node)
                            relations.append(
                                RelationEdge(
                                    source_id=person_node.id,
                                    target_id=doc_node.id,
                                    relation_type=RelationType.NAMED_ON_DOCUMENT,
                                    confidence=0.85,
                                )
                            )
                    elif hit_entity.type == EntityType.SOCIAL_PROFILE:
                        prof_key = (hit_entity.type, hit_entity.value)
                        if prof_key not in seen_entity_keys:
                            seen_entity_keys.add(prof_key)
                            entities.append(hit_entity)
                            relations.append(
                                RelationEdge(
                                    source_id=person_node.id,
                                    target_id=hit_entity.id,
                                    relation_type=RelationType.ASSOCIATED_WITH,
                                    confidence=0.8,
                                )
                            )
            except Exception as exc:
                report["web_search"] = {"error": str(exc), "ok": False}

        # 4. Estructura del nombre (riqueza del dato para el analista)
        parts = [p for p in strip_accents(full_name.lower()).split() if p not in _STOP_PARTICLES]
        report["name_structure"] = {
            "tokens": len(parts),
            "has_two_surnames": len(parts) >= 3,
            "derived_usernames": len(username_candidates),
        }
        person_node.attributes["tokens"] = len(parts)

        return CollectorResult(
            collector_name=self.name,
            source_target=full_name,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(report, ensure_ascii=False, indent=2),
            metadata=report,
        )

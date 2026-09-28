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
    """Genera candidatos de username desde la estructura del nombre completo.

    Dinámico: no asume formato (LATAM/ES/EN). Tres familias de patrones sobre
    los tokens del nombre (partículas excluidas):
      1. Inicial del primer token + cada subconjunto contiguo del resto
         ('carlos andres mendoza garcia' → cmendoza, cmendozagarcia, cgarcia).
         Es la familia más distintiva en LATAM y la que el motor viejo
         perdió: sin ella el pivote único que identifica al sujeto no se
         genera nunca.
      2. Par head+tail de cada rango (i..j): carlos.garcia, carlos_mendoza,
         carlosgarcia, y sus iniciales (camg).
      3. Tokens sueltos y el nombre completo unido.

    Cap 24: más que el cap viejo de 12 porque la familia 1 añade los pivotes
    que separan homónimos; el orden prioriza patrones derivables del nombre.
    """
    cleaned = strip_accents(full_name.lower())
    cleaned = re.sub(r"[^a-z0-9\s]", " ", cleaned)
    parts = [p for p in cleaned.split() if p and p not in _STOP_PARTICLES]
    if not parts:
        return []
    n = len(parts)
    candidates: list[str] = []

    def add(c: str) -> None:
        if 3 <= len(c) <= 30 and c not in candidates:
            candidates.append(c)

    # El nombre completo unido es la derivación más fuerte: va primero y
    # nunca lo recorta el cap (anamariacruzpinto, carlosandresmendozagarcia).
    add("".join(parts))

    # 1. Inicial + subconjunto contiguo del resto (cmendozagarcia, cmendoza…)
    for i in range(n - 1):
        for s in range(i + 1, n):
            for e in range(s, n):
                add(f"{parts[i][0]}{''.join(parts[s : e + 1])}")

    # 2. head+tail por rango, con separadores e iniciales
    for i in range(n - 1):
        for j in range(i + 1, n):
            head, tail = parts[i], parts[j]
            add(f"{head}.{tail}")
            add(f"{head}_{tail}")
            add(f"{head}{tail}")
            add("".join(p[0] for p in parts[i : j + 1]))

    # 3. Tokens sueltos
    for p in parts:
        add(p)
    return candidates[:24]


# ---------------------------------------------------------------------------
# Dorks pasivos (documentos de identidad + presencia pública)
# ---------------------------------------------------------------------------

_DOC_DORK_TEMPLATES = [
    '"dni" {name}',
    '"nie" {name}',
    '"pasaporte" {name}',
    '"cuit" {name}',
    '"cédula" {name}',
    '"codigo universitario" {name}',
    'intext:"documento de identidad" {name}',
    "{name} (site:pastebin.com | site:rentry.co)",
]

# Repositorios de documentos académicos/profesionales: ahí es donde el motor
# era más vago frente al analista humano (Scribd, Studocu, CourseHero...).
_REPOSITORY_DORK_TEMPLATES = [
    "{name} (site:scribd.com | site:studocu.com | site:coursehero.com)",
    "{name} (site:academia.edu | site:researchgate.net | site:slideshare.net)",
    "{name} (site:docs.google.com | site:drive.google.com | site:1lib.us)",
]

_PRESENCE_DORK_TEMPLATES = [
    "{name} (site:linkedin.com | site:x.com | site:instagram.com)",
    "{name} (site:github.com | site:gitlab.com)",
    "{name} (filetype:pdf | filetype:doc | filetype:docx)",
    '{name} (intitle:"cv" | inurl:"cv")',
    "{name} (site:pinterest.com | site:youtube.com | site:tiktok.com)",
]

# TLD → dorks de fuentes oficiales: se elige por el país del objetivo, no al
# revés. El colector deriva el país del contexto (dominio de la entidad o
# TLD del caso) y solo entonces aplica las plantillas.
_OFFICIAL_DORKS_BY_TLD: dict[str, list[str]] = {
    "pe": ["{name} (site:gob.pe | site:unmsm.edu.pe)", '"{name}" reniec'],
    "ar": [
        "{name} (site:boletinoficial.gob.ar | site:infoleg.gob.ar | site:pjn.gov.ar)",
        "{name} (site:argentina.gob.ar)",
    ],
    "es": ["{name} (site:boe.es | site:gob.es)", '"{name}" boe'],
    "mx": ["{name} (site:gob.mx)", '"{name}" curp'],
    "co": ["{name} (site:gob.co | site:gov.co)", '"{name}" registraduria'],
    "cl": ["{name} (site:gob.cl)", '"{name}" registro civil'],
    "ec": ["{name} (site:gob.ec)", '"{name}" registro civil'],
    "do": ["{name} (site:gob.do)", '"{name}" cedula'],
    "com": ['"{name}" (licencia OR credencial OR nomina OR "acta")'],
}
_DEFAULT_OFFICIAL_DORKS = _OFFICIAL_DORKS_BY_TLD["com"]
_COUNTRY_NAMES = {
    "pe": ("peru", "perú"),
    "ar": ("argentina",),
    "es": ("spain", "españa", "espana"),
    "mx": ("mexico", "méxico"),
    "co": ("colombia",),
    "cl": ("chile",),
    "ec": ("ecuador",),
    "do": ("dominican republic", "republica dominicana", "república dominicana"),
}


def detect_context_tld(text: str) -> str:
    """TLD cc de un texto (URLs, dominios) para derivar el país del objetivo.

    Dinámico: examina los hosts presentes y devuelve el ccTLD más frecuente
    que tengamos dorks oficiales. Sin coincidencia → 'com' (genérico).
    """
    found: dict[str, int] = {}
    for host in re.findall(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", text.lower()):
        parts = host.rstrip(".").split(".")
        if len(parts) >= 2 and parts[-1] in _OFFICIAL_DORKS_BY_TLD:
            found[parts[-1]] = found.get(parts[-1], 0) + 1
    specific = {tld: count for tld, count in found.items() if tld != "com"}
    if specific:
        return max(specific.items(), key=lambda kv: kv[1])[0]

    normalized = strip_accents(text).casefold()
    country_hits: dict[str, int] = {}
    for tld, names in _COUNTRY_NAMES.items():
        for phrase in {strip_accents(name).casefold() for name in names}:
            if re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", normalized):
                country_hits[tld] = country_hits.get(tld, 0) + 1
    if country_hits:
        return max(country_hits.items(), key=lambda kv: kv[1])[0]
    return "com"


def build_document_dorks(full_name: str) -> list[str]:
    name_q = f'"{full_name}"'
    return [t.format(name=name_q) for t in _DOC_DORK_TEMPLATES]


def build_presence_dorks(full_name: str) -> list[str]:
    name_q = f'"{full_name}"'
    return [t.format(name=name_q) for t in _PRESENCE_DORK_TEMPLATES]


def build_repository_dorks(full_name: str) -> list[str]:
    """Dorks de repositorios de documentos: Scribd, Studocu, CourseHero, etc."""
    name_q = f'"{full_name}"'
    return [t.format(name=name_q) for t in _REPOSITORY_DORK_TEMPLATES]


def build_official_dorks(full_name: str, tld: str) -> list[str]:
    """Dorks de fuentes oficiales según el país detectado (TLD del contexto)."""
    name_q = f'"{full_name}"'
    return [t.format(name=name_q) for t in _OFFICIAL_DORKS_BY_TLD.get(tld, _DEFAULT_OFFICIAL_DORKS)]


def build_person_search_queries(full_name: str, context: str = "") -> list[str]:
    """Crea consultas literales, variantes de nombre y dorks temáticos."""
    context_tld = detect_context_tld(f"{full_name} {context}")
    folded = strip_accents(full_name)
    candidates = [f'"{full_name}"', full_name]
    if folded.casefold() != full_name.casefold():
        candidates.append(f'"{folded}"')

    parts = [part for part in full_name.split() if part]
    if len(parts) >= 3:
        candidates.extend(
            (
                f'"{parts[0]} {parts[-1]}"',
                f'"{parts[-1]} {parts[0]}"',
                f'"{parts[-2]} {parts[-1]}"',
            )
        )

    candidates.extend(build_document_dorks(full_name))
    candidates.extend(build_presence_dorks(full_name))
    candidates.extend(build_repository_dorks(full_name))
    candidates.extend(build_official_dorks(full_name, context_tld))

    queries: list[str] = []
    seen: set[str] = set()
    for query in candidates:
        normalized = " ".join(query.split())
        key = normalized.casefold()
        if normalized and key not in seen:
            seen.add(key)
            queries.append(normalized)
        if len(queries) >= 40:
            break
    return queries


# ---------------------------------------------------------------------------
# Colector
# ---------------------------------------------------------------------------


class PersonInvestigator(BaseCollector):
    """Huella digital de nombre completo: usernames derivados + dorks de
    documentos/identidad y presencia pública. Sin interacción activa."""

    def __init__(self):
        super().__init__(name="person_investigator")

    async def collect(
        self,
        target: str,
        execute_search: bool = False,
        context: str = "",
        **kwargs: Any,
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

        # 2. Dorks de documentos de identidad, presencia pública, repositorios
        #    de documentos y fuentes oficiales del país detectado.
        doc_dorks = build_document_dorks(full_name)
        presence_dorks = build_presence_dorks(full_name)
        repository_dorks = build_repository_dorks(full_name)
        context_tld = detect_context_tld(f"{full_name} {context}")
        official_dorks = build_official_dorks(full_name, context_tld)
        report["dorks"] = {
            "document_identity": doc_dorks,
            "presence": presence_dorks,
            "repositories": repository_dorks,
            "official": official_dorks,
            "context_tld": context_tld,
            "total": len(doc_dorks)
            + len(presence_dorks)
            + len(repository_dorks)
            + len(official_dorks),
        }

        # 3. Búsqueda activa y enriquecimiento de evidencias si se solicita
        if execute_search or kwargs.get("execute_search"):
            try:
                search_collector = WebSearchCollector()
                queries = build_person_search_queries(full_name, context=context)
                report["search_queries"] = queries
                search_res = await search_collector.collect_many(queries, top_k=10, concurrency=3)
                report["web_search"] = {
                    "results_count": search_res.metadata.get("results", 0),
                    "ok": search_res.metadata.get("ok", False),
                    "status": search_res.metadata.get("status"),
                    "queries_attempted": search_res.metadata.get("queries_attempted", 0),
                    "provider_status": search_res.metadata.get("provider_status", {}),
                    "query_runs": search_res.metadata.get("query_runs", []),
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
                                attributes={
                                    "detected_from": url,
                                    "context": snippet[:200],
                                    "candidate": True,
                                    "observations": hit_entity.attributes.get("observations", []),
                                },
                                confidence=0.45,
                            )
                            entities.append(inst_node)
                            relations.append(
                                RelationEdge(
                                    source_id=person_node.id,
                                    target_id=inst_node.id,
                                    relation_type=RelationType.ASSOCIATED_WITH,
                                    confidence=0.45,
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
                                attributes={**hit_entity.attributes, "candidate": True},
                                confidence=0.55,
                            )
                            entities.append(doc_node)
                            relations.append(
                                RelationEdge(
                                    source_id=person_node.id,
                                    target_id=doc_node.id,
                                    relation_type=RelationType.NAMED_ON_DOCUMENT,
                                    confidence=0.55,
                                )
                            )
                    elif hit_entity.type == EntityType.SOCIAL_PROFILE:
                        prof_key = (hit_entity.type, hit_entity.value)
                        if prof_key not in seen_entity_keys:
                            seen_entity_keys.add(prof_key)
                            profile = EntityNode.create(
                                hit_entity.type,
                                hit_entity.value,
                                hit_entity.label,
                                attributes={**hit_entity.attributes, "candidate": True},
                                confidence=0.45,
                            )
                            entities.append(profile)
                            relations.append(
                                RelationEdge(
                                    source_id=person_node.id,
                                    target_id=profile.id,
                                    relation_type=RelationType.ASSOCIATED_WITH,
                                    confidence=0.45,
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

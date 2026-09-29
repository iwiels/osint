"""
WraithOSINT - Triage de artefactos
Clasifica un artefacto crudo y recomienda la tool de investigación correcta.
Lo usa la tool MCP `triage_entity` (entrada libre del analista o del agente).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from specter.osint_core.models import EntityType

# IPv4 con octetos 0-255 (evita aceptar 999.1.1.1)
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
_IPV6_RE = re.compile(r"^(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
_HASH_RE = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.IGNORECASE)

# Documentos de identidad (ES/LATAM) validados por estructura
_DNI_ES_RE = re.compile(r"^\d{8}[A-Z]$", re.IGNORECASE)  # 12345678Z
_NIE_ES_RE = re.compile(r"^[XYZ]\d{7}[A-Z]$", re.IGNORECASE)  # X1234567L
_CUIT_RE = re.compile(r"^\d{2}-?\d{8}-?\d$", re.IGNORECASE)  # 20-12345678-9
_RUT_CL_RE = re.compile(r"^\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]$")  # 12.345.678-5
_PHONE_RE = re.compile(r"^\+?\d[\d\s\-()]{6,19}$")

# DNI argentino sin letra (7-8 dígitos desnuros, sin separadores)
_DNI_AR_RE = re.compile(r"^\d{7,8}$")

_USERNAME_HINTS_RE = re.compile(r"^[a-z0-9_.@-]{3,30}$", re.IGNORECASE)

# TLDs que delatan un subdominio de servicio y no un dominio raíz
_MULTI_PART_SUFFIXES = {"co.uk", "com.ar", "com.br", "com.mx", "gob.es", "gob.ar"}


@dataclass(frozen=True)
class TriageVerdict:
    artifact: str
    entity_type: EntityType
    tool: str  # tool MCP recomendada
    args: dict[str, str]
    notes: list[str]


def _is_probable_subdomain(value: str) -> bool:
    """`mail.google.com` es subdominio; `google.com` es dominio raíz."""
    labels = value.rstrip(".").lower().split(".")
    if len(labels) < 3:
        return False
    last_two = ".".join(labels[-2:])
    return last_two not in _MULTI_PART_SUFFIXES


def triage_artifact(raw: str) -> TriageVerdict:
    value = raw.strip()
    lowered = value.lower()

    if _EMAIL_RE.match(value):
        return TriageVerdict(value, EntityType.EMAIL, "investigate_email", {"email": value}, [])
    if _IPV4_RE.match(value):
        return TriageVerdict(value, EntityType.IP_ADDRESS, "investigate_ip", {"ip": value}, [])
    if ":" in value and _IPV6_RE.match(value):
        return TriageVerdict(value, EntityType.IP_ADDRESS, "investigate_ip", {"ip": value}, [])

    if _DNI_ES_RE.match(value) or _NIE_ES_RE.match(value):
        return TriageVerdict(
            value.upper(),
            EntityType.DOCUMENT_ID,
            "hunt_documents_and_leaks",
            {"target": value},
            [
                "Documento español validado por estructura; busca apariciones en filtraciones indexadas"
            ],
        )
    if _CUIT_RE.match(value) or _RUT_CL_RE.match(value):
        return TriageVerdict(
            value,
            EntityType.DOCUMENT_ID,
            "hunt_documents_and_leaks",
            {"target": value},
            ["Documento LATAM validado por estructura"],
        )

    if _HASH_RE.match(value):
        return TriageVerdict(
            value.lower(),
            EntityType.FILE_ARTIFACT,
            "hunt_documents_and_leaks",
            {"target": value},
            ["Hash de archivo: búscalo en repositorios de filtraciones"],
        )

    if _DOMAIN_RE.match(lowered):
        if _is_probable_subdomain(lowered):
            return TriageVerdict(
                lowered,
                EntityType.SUBDOMAIN,
                "investigate_domain",
                {"domain": lowered},
                ["Parece subdominio (3+ etiquetas); se investiga como dominio"],
            )
        return TriageVerdict(
            lowered, EntityType.DOMAIN, "investigate_domain", {"domain": lowered}, []
        )

    if _DNI_AR_RE.match(value):
        return TriageVerdict(
            value,
            EntityType.DOCUMENT_ID,
            "hunt_documents_and_leaks",
            {"target": value},
            [
                "Número desnudo de 7-8 dígitos: DNI argentino sin letra; busca el literal en filtraciones y registros"
            ],
        )

    if _PHONE_RE.match(value) and any(c.isdigit() for c in value):
        return TriageVerdict(
            value,
            EntityType.PHONE,
            "hunt_documents_and_leaks",
            {"target": f'"{value}"'},
            ["Teléfono: se busca como literal en filtraciones y documentos"],
        )

    # Un nombre propio largo (2+ palabras alfabéticas) es una persona
    words = [w for w in re.split(r"\s+", value) if w]
    if len(words) >= 2 and all(re.match(r"^[A-ZÁÉÍÓÚÑÇÜ][a-záéíóúñçü·']+$", w) for w in words):
        return TriageVerdict(
            value,
            EntityType.PERSON,
            "investigate_person",
            {"full_name": value},
            ["Nombre propio compuesto: se lanza huella digital de persona"],
        )

    if _USERNAME_HINTS_RE.match(value):
        return TriageVerdict(
            value.lstrip("@"),
            EntityType.ALIAS,
            "investigate_identity",
            {"username": value.lstrip("@")},
            [],
        )

    return TriageVerdict(
        value,
        EntityType.ALIAS,
        "investigate_identity",
        {"username": value},
        ["Artefacto no clasificado: se intenta como identidad digital"],
    )

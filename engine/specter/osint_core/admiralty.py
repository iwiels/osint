"""
WraithOSINT - Helpers de fiabilidad inspirados en la matriz del Almirantazgo.

La matriz 6x6 del Almirantazgo cualifica cada evidencia con DOS ejes:

1. LETRA A-F: fiabilidad probada de la FUENTE emisora.
   A: juicio del analista / evidencia sellada propia (no se auto-otorga)
   B: fuente primaria o registro oficial (RDAP, crt.sh, DNS, GitHub API, WARC)
   C: feed curado o existencia verificada (ThreatFox, VT, Shodan, WMN, Gravatar)
   D: búsqueda web / snippets / HTML parseado (DDG, dorks, Wayback contenido)
   E: (reservado) fuente dudosa con historial de error
   F: fiabilidad indeterminable (fallbacks, parseos parciales)

2. DÍGITO 1-6: credibilidad del HECHO concreto que reporta la fuente.
   1: confirmado por otras fuentes independientes
   2: probablemente cierto (fuente fiable, sin contradicción, sin 2ª fuente)
   3: posiblemente cierto (fuente fiable, no corroborada ni contradicha)
   4: dudoso (fuente fiable posible contradicción, o fuente usualmente fiable
      sorprendida en error puntual)
   5: improbable (fuente dudosa, contradicha por otra fuente creíble)
   6: veracidad indeterminable (no puede juzgarse)

Composición completa: "B2" = registro oficial probablemente cierto.

Además aplica freshness decay: la confianza de artefactos volátiles (IPs
dinámicas, teléfonos, whois) se atenúa con decaimiento exponencial — mitad
de vida configurable, 90 días por defecto — porque el titular pudo cambiar.

Alcance actual: `rate_source` se adjunta en los caminos comunes de ingesta;
`assess_evidence`, `freshness_decay` y `needs_corroboration` son helpers. No se
aplican de forma uniforme a cada entidad, no están calibrados contra un corpus
etiquetado y no bloquean ni rebajan automáticamente relaciones del grafo. La
regla de corroboración debe tratarse como una recomendación del analista.
"""

from __future__ import annotations

from dataclasses import dataclass

SOURCE_RELIABILITY: dict[str, str] = {
    # Registros oficiales y APIs primarias
    "dns_collector": "B",
    "crt_sh_collector": "B",
    "tls_collector": "B",
    "ip_enricher": "B",
    "github_forensics": "B",
    "browser_snapshot": "B",
    "browser_screenshot": "B",
    "browser_capture_warc": "B",
    # Feeds curados y existencia verificada
    "username_investigator": "C",
    "email_investigator": "C",
    "internetdb": "C",
    "threatfox": "C",
    "virustotal": "C",
    "shodan": "C",
    "greynoise": "C",
    "abuseipdb": "C",
    "hunter": "C",
    "urlscan": "C",
    "hackertarget_reverse": "C",
    "file_forensics": "C",
    "office_doc_hunter": "C",
    "censys": "C",
    "haveibeenpwned": "C",
    "hibp": "C",
    # Búsqueda web y parseo HTML
    "web_search_collector": "D",
    "web_fetch_collector": "D",
    "document_hunter": "D",
    "wayback": "D",
    "person_investigator": "D",
}

CREDIBILITY_DIGITS: dict[int, str] = {
    1: "confirmado por otras fuentes independientes",
    2: "probablemente cierto (fuente fiable, sin corroborar ni contradecir)",
    3: "posiblemente cierto (fuente fiable sin 2ª fuente)",
    4: "dudoso (posible contradicción o antecedente de error)",
    5: "improbable (contradicho por fuente creíble)",
    6: "veracidad indeterminable",
}

# Tipos de artefacto VOLÁTILES: su titularidad puede cambiar con el tiempo
# (decay agresivo). Los criptográficos (hashes) no decaen jamás.
VOLATILE_ARTIFACTS = frozenset({"IP_ADDRESS", "PHONE", "DOMAIN", "SUBDOMAIN"})
HALF_LIFE_DAYS_DEFAULT = 90.0
MIN_DECAYED_CONFIDENCE = 0.05


def rate_source(collector_name: str) -> str:
    """Letra de fiabilidad para un colector (F si es desconocido)."""
    return SOURCE_RELIABILITY.get(collector_name, "F")


def needs_corroboration(confidence: float) -> bool:
    """Links >= 0.85 exigen corroboración independiente o revisión analista."""
    return confidence >= 0.85


def credibility_digit(
    corroborated: bool | None = None,
    contradicted: bool = False,
    single_reliable_source: bool = False,
) -> int:
    """Dígito 1-6 de credibilidad del hecho según su contexto probatorio.

    - corroborado=True → 1 (confirmación independiente).
    - contradicted=True → 5 (salvo corroborado, que gana).
    - corroborated=False y single_reliable_source=True → 2.
    - corroborated=False genérico → 3.
    - corroborated=None (no se evaluó) → 6 (indeterminable).
    """
    if corroborated is True:
        return 1
    if contradicted:
        return 5
    if corroborated is None:
        return 6
    return 2 if single_reliable_source else 3


def freshness_decay(
    confidence: float,
    age_days: float | None,
    *,
    entity_type: str | None = None,
    half_life_days: float = HALF_LIFE_DAYS_DEFAULT,
) -> float:
    """Atenúa la confianza de artefactos antiguos (decaimiento exponencial).

    conf' = conf * 0.5 ** (edad / vida_media). Los artefactos criptográficos
    (hashes, certificados observados) no decaen; los volátiles (IP, teléfono,
    dominio) sí. Sin edad conocida, la confianza se mantiene (no se castiga la
    ignorancia) pero la auditoría lo reporta como sin freshness.
    """
    if age_days is None or age_days <= 0:
        return round(min(1.0, max(0.0, confidence)), 4)
    if entity_type is not None and entity_type not in VOLATILE_ARTIFACTS:
        return round(min(1.0, max(0.0, confidence)), 4)
    decayed = confidence * (0.5 ** (float(age_days) / max(half_life_days, 1e-6)))
    return round(max(MIN_DECAYED_CONFIDENCE, decayed), 4)


@dataclass(frozen=True)
class AdmiraltyGrade:
    """Cualificación completa de una evidencia (letra + dígito + decay)."""

    reliability: str  # A-F
    credibility: int  # 1-6
    raw_confidence: float
    decayed_confidence: float
    age_days: float | None
    rationale: str = ""

    @property
    def grade(self) -> str:
        """Notación estándar del sistema: 'B2', 'C3', 'D6'…"""
        return f"{self.reliability}{self.credibility}"

    def as_dict(self) -> dict[str, object]:
        return {
            "grade": self.grade,
            "reliability": self.reliability,
            "credibility": self.credibility,
            "credibility_meaning": CREDIBILITY_DIGITS.get(self.credibility, ""),
            "raw_confidence": self.raw_confidence,
            "decayed_confidence": self.decayed_confidence,
            "age_days": self.age_days,
            "rationale": self.rationale,
        }


def assess_evidence(
    collector_name: str,
    confidence: float,
    *,
    corroborated: bool | None = None,
    contradicted: bool = False,
    single_reliable_source: bool = False,
    age_days: float | None = None,
    entity_type: str | None = None,
    half_life_days: float = HALF_LIFE_DAYS_DEFAULT,
) -> AdmiraltyGrade:
    """Cualificación Almirantazgo completa de una evidencia de colector."""
    letter = rate_source(collector_name)
    digit = credibility_digit(
        corroborated=corroborated,
        contradicted=contradicted,
        single_reliable_source=single_reliable_source,
    )
    decayed = freshness_decay(
        confidence, age_days, entity_type=entity_type, half_life_days=half_life_days
    )
    rationale = (
        f"fuente {letter} ({'conocida' if collector_name in SOURCE_RELIABILITY else 'indeterminable'}), "
        f"hecho {digit} ({CREDIBILITY_DIGITS[digit]})"
    )
    if age_days is not None and age_days > 0 and (entity_type in VOLATILE_ARTIFACTS):
        rationale += f"; decay aplicado ({age_days:.0f} días, vida media {half_life_days:.0f})"
    return AdmiraltyGrade(
        reliability=letter,
        credibility=digit,
        raw_confidence=confidence,
        decayed_confidence=decayed,
        age_days=age_days,
        rationale=rationale,
    )

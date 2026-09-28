"""
SpecterOSINT - Resolución de entidades probabilística (Fellegi-Sunter).

Modelo clásico de enlace de registros (Fellegi & Sunter, 1969) tal como lo
implementa Splink: cada par de registros (A, B) produce un vector de
comparación γ = [γ1..γk] donde cada campo aporta una razón de verosimilitud

    w_i = log2( P(γ_i | M) / P(γ_i | U) )

con M = pares que son la misma entidad y U = pares distintos. La suma de
pesos es el score log2 del par: +1 significa el doble de probable que sea
coincidencia, -3 significa 8 veces menos probable. El nivel de acuerdo
(agreement level) de cada campo indica cuánto contribuyó.

Umbrales heurísticos iniciales del proyecto (no calibrados en un corpus propio):
  - match_threshold (2.0): encima, candidato de alta similitud para revisión.
  - review_threshold (0.0): entre ambos, zona de indecisión (revisión humana).

Corrección de dependencia entre campos (lección de Splink #2462 y
term-frequency-adjustments): el modelo asume campos independientes. Si un
caso llenó el grafo con 30 variantes del mismo handle (un solo pivot de
enumeración), dos de esas variantes "coincidiendo" NO es corroboración: es
el mismo hecho visto dos veces. Mecanismo: la u del acuerdo se ajusta a la
frecuencia real del valor en el caso, u_tf = max(u_base, count/N). Un handle
único en el caso conserva su peso fuerte; uno repetido N veces degrada
suavemente hasta anularse. En batch lo carga identity_candidates_fs (con
set_term_frequencies); fuera de batch compare_pair no ajusta nada.

Diferencia con el motor heurístico de `correlation.py` (scores fijos 0.6-0.9):
aquí los pesos son aditivos y explicables campo a campo. El score logístico usa
priors implícitos iguales y supuestos de independencia; sin entrenamiento y
calibración con pares etiquetados, `probability` no es una probabilidad empírica
fiable. Nada se escribe en el grafo automáticamente: los candidatos son
propuestas para `link_entities` del analista.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from specter.osint_core.correlation import identity_value, normalize_handle
from specter.osint_core.models import EntityNode

# --------------------------------------------------------------------------- #
# Pesos por defecto (log2 odds, calibrables por el analista)                   #
# --------------------------------------------------------------------------- #
# Escalas por campo (1.0 = neutro): el analista puede subir/bajar la
# contribución de un campo según la calidad de sus fuentes.
DEFAULT_FIELD_SCALES: dict[str, float] = {
    "email": 1.0,
    "email_local": 1.0,
    "handle_exact": 1.0,
    "handle_close": 1.0,
    "name_jw": 0.45,  # un nombre parecido solo no prueba identidad
    "alias_of_name": 1.0,  # alias derivable del nombre completo del sujeto
}

DEFAULT_THRESHOLDS: dict[str, float] = {
    "match": 2.0,  # R >= T_match → candidato de alta similitud, no fusión
    "review": 0.0,  # T_review <= R < T_match → supervisión del analista
}


# Priors (m, u) por campo y nivel de acuerdo, de la literatura de enlace de
# registros: m = P(acuerdo | misma entidad), u = P(acuerdo | entidades distintas).
# El peso del nivel es log2(m/u); el desacuerdo aporta evidencia negativa fija.
_KIND_PARAMS: dict[str, dict[str, tuple[float, float]]] = {
    "email": {"agree": (0.95, 0.001), "close": (0.60, 0.05)},
    "email_local": {"agree": (0.60, 0.05)},
    "handle_exact": {"agree": (0.85, 0.01), "close": (0.60, 0.20)},
    "handle_close": {"agree": (0.60, 0.20)},
    "name_jw": {"agree": (0.80, 0.05), "close": (0.60, 0.15)},
    "alias_of_name": {"agree": (0.85, 0.08)},
}
_DISAGREEMENT_WEIGHT = -1.0


@dataclass
class FieldComparison:
    """Resultado de comparar un campo entre dos registros."""

    field: str
    agreement_level: str  # exact | close | weak | disagree
    weight: float
    detail: str = ""


@dataclass
class PairwiseScore:
    """Score Fellegi-Sunter de un par de entidades (explicable campo a campo)."""

    entity_a: dict[str, Any]
    entity_b: dict[str, Any]
    total_weight: float
    probability: float  # estimación logística sin calibración empírica
    verdict: str  # match (candidato) | review | non_match
    comparisons: list[FieldComparison] = field(default_factory=list)
    independent_sources: int = 2  # fuentes de procedencia distintas en el par
    frequency_penalty: float = 0.0  # log2-odds restados por término frecuente


def jaro_winkler(s1: str, s2: str, scaling: float = 0.1) -> float:
    """Similitud Jaro-Winkler (0..1) sin dependencias externas.

    Variante Winkler: bonifica prefijos comunes de hasta 4 caracteres, la
    estándar para nombres propios en sistemas de enlace de registros.
    """
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    len1, len2 = len(s1), len(s2)
    match_window = max(len1, len2) // 2 - 1
    match_window = max(match_window, 0)

    flags1 = [False] * len1
    flags2 = [False] * len2
    matches = 0
    for i in range(len1):
        start = max(0, i - match_window)
        end = min(i + match_window + 1, len2)
        for j in range(start, end):
            if flags2[j] or s1[i] != s2[j]:
                continue
            flags1[i] = flags2[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0

    # Transposiciones (pares de caracteres emparejados en desorden).
    transpositions = 0
    k = 0
    for i in range(len1):
        if not flags1[i]:
            continue
        while not flags2[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    transpositions //= 2

    jaro = (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0

    prefix = 0
    for a, b in zip(s1[:4], s2[:4], strict=False):
        if a != b:
            break
        prefix += 1
    return jaro + prefix * scaling * (1.0 - jaro)


_PHONE_STRIP = re.compile(r"\D+")


# Registro de frecuencia de valores del caso actual: lo rellena
# CorrelationEngine.identity_candidates_fs antes de comparar pares
# (set_term_frequencies) y _adjusted_u lo consume. Fuera de batch queda a 0
# y compare_pair no ajusta nada (comportamiento canónico de los tests unitarios).
_TF_COUNTS: dict[str, int] = {}
_TF_TOTAL: int = 0


def set_term_frequencies(counts: dict[str, int], total: int) -> None:
    """Carga la frecuencia de valores del caso para el ajuste TF del batch.

    La llama `CorrelationEngine.identity_candidates_fs` antes de comparar pares;
    las claves son los mismos tokens que produce compare_pair (handles
    normalizados, locales de email, emails completos en minúsculas) y `total`
    es el número de entidades de identidad del caso (denominador de la
    frecuencia).
    """
    global _TF_COUNTS, _TF_TOTAL
    _TF_COUNTS = {k: v for k, v in (counts or {}).items() if v > 1}
    _TF_TOTAL = max(int(total), 0)


def reset_term_frequencies() -> None:
    """Limpia el registro de frecuencias (entre batches / tests)."""
    global _TF_COUNTS, _TF_TOTAL
    _TF_COUNTS = {}
    _TF_TOTAL = 0


# Cobertura mínima de tokens del nombre para considerar un alias "derivado"
# del nombre completo: cmendozagarcia cubre 3/4 tokens de 'Carlos Andres
# Mendoza Garcia' (inicial+j2 apellidos); carlosgarcia solo 2/4 (nombre + último
# apellido) — el patrón típico de homónimo genérico.
_ALIAS_COVERAGE_MIN = 0.7

# Partículas que no aportan a un handle ni a la cobertura de un alias
# (ES/LATAM/EN). Fuente compartida con collectors.person.derive_username_candidates.
NAME_STOP_PARTICLES = frozenset(
    {
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
)


def _alias_name_coverage(alias: str, person_name: str) -> float:
    """Fracción de tokens del nombre que representa un alias (0..1).

    Dinámico (sin listas de apellidos por país): el alias debe reconstruirse
    como cabeza (primer token completo o su inicial) + sufijo contiguo del
    resto de tokens. La cobertura cuenta tokens representados (completos o
    por inicial) sobre el total. 'cmendozagarcia' → 3/4 = 0.75 (derivable);
    'carlosgarcia' → 2/4 = 0.50 (homónimo genérico, no suma evidencia);
    'carlosandresmendozagarcia' → 4/4. Es la prueba que separa al alias del
    sujeto del material de homónimos sin hardcodear ningún formato nacional.
    """
    text = unicodedata.normalize("NFKD", person_name.lower())
    text = "".join(c for c in text if not unicodedata.combining(c))
    tokens = [
        t for t in re.findall(r"[a-z0-9]+", text) if len(t) >= 2 and t not in NAME_STOP_PARTICLES
    ]
    key = normalize_handle(alias)
    if len(tokens) < 2 or len(key) < 4:
        return 0.0
    if key == "".join(tokens):  # nombre completo unido
        return 1.0
    best = 0.0
    for i in range(1, len(tokens)):
        tail = "".join(tokens[i:])
        for head in (tokens[0], tokens[0][0]):
            if key == f"{head}{tail}":
                # Cabeza (1 token, completo o inicial) + (len - i) tokens de cola.
                best = max(best, (1 + (len(tokens) - i)) / len(tokens))
    return best


def _adjusted_u(base_u: float, token: str) -> float:
    """u ajustada por frecuencia del término (Splink: term-frequency-adjustments).

    u_tf = max(u_base, count/N) acotada a 0.9: un valor presente en la mitad
    del caso coincide por azar la mitad de las veces, sin importar cuán
    'exacto' parezca. Sólo se ajustan valores REPETIDOS (count >= 2): un
    handle único en un caso pequeño (N bajo) tendría 1/N alta y penalización
    injusta; su población es exactamente la que describe la u base. Sin batch
    cargado (total 0) devuelve la u base.
    """
    if _TF_TOTAL <= 0 or not token:
        return base_u
    count = _TF_COUNTS.get(token, 1)  # lo visto en el par existe al menos 1 vez
    if count < 2:
        return base_u
    freq = count / _TF_TOTAL
    return min(max(base_u, freq), 0.9)


def _normalized_email_local(email_value: str) -> str:
    """Parte local de un email, normalizada (alice.dev+spam → alicedev)."""
    local = email_value.split("@", 1)[0].lower()
    local = local.split("+", 1)[0]  # sub-addressing de Gmail
    return re.sub(r"[^a-z0-9]", "", local)


def _normalized_phone(value: str) -> str | None:
    digits = _PHONE_STRIP.sub("", value)
    return digits if len(digits) >= 7 else None


def _count_sources(*attrs: dict[str, Any] | None) -> int:
    """Cuenta fuentes de procedencia distintas entre los atributos de un par."""
    urls: set[str] = set()
    for attr in attrs:
        if not attr:
            continue
        url = attr.get("source_url") or attr.get("url")
        if url:
            urls.add(str(url))
    return max(len(urls), 1)


def compare_pair(
    a: EntityNode,
    b: EntityNode,
    field_weights: dict[str, float] | None = None,
    thresholds: dict[str, float] | None = None,
) -> PairwiseScore:
    """Compara dos entidades de identidad con el modelo Fellegi-Sunter."""
    weights = {**DEFAULT_FIELD_SCALES, **(field_weights or {})}
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    comparisons: list[FieldComparison] = []
    freq_penalty = 0.0  # log2-odds que el ajuste TF restó en total

    def _weight(kind: str, level: str, detail: str = "", token: str = "") -> FieldComparison:
        nonlocal freq_penalty
        if level == "disagree":
            w = _DISAGREEMENT_WEIGHT
        else:
            m, u = _KIND_PARAMS.get(kind, {}).get(level, (0.5, 0.1))
            scale = weights.get(kind, 1.0)
            w = scale * math.log2(m / u)
            u_adj = _adjusted_u(u, token)
            if u_adj > u:
                w_adj = scale * math.log2(m / u_adj)
                freq_penalty += w - w_adj
                w = w_adj
        return FieldComparison(field=kind, agreement_level=level, weight=round(w, 4), detail=detail)

    va, vb = a.value.strip(), b.value.strip()
    la, lb = va.lower(), vb.lower()

    # 1. Email completo
    if a.type.value == "EMAIL" and b.type.value == "EMAIL":
        if la == lb:
            comparisons.append(_weight("email", "agree", va, token=la))
        elif _normalized_email_local(va) and _normalized_email_local(va) == _normalized_email_local(
            vb
        ):
            comparisons.append(
                _weight(
                    "email_local",
                    "agree",
                    f"buzón '{_normalized_email_local(va)}' en dominios distintos",
                    token=_normalized_email_local(va),
                )
            )
        else:
            comparisons.append(_weight("email", "disagree"))
    elif a.type.value == "EMAIL" or b.type.value == "EMAIL":
        # Email contra alias/handle: comparar la parte local como handle.
        local_a = (
            _normalized_email_local(va)
            if a.type.value == "EMAIL"
            else normalize_handle(identity_value(a))
        )
        local_b = (
            _normalized_email_local(vb)
            if b.type.value == "EMAIL"
            else normalize_handle(identity_value(b))
        )
        if local_a and local_a == local_b:
            comparisons.append(
                _weight("handle_exact", "agree", f"buzón '{local_a}'", token=local_a)
            )
        else:
            comparisons.append(_weight("email", "disagree"))

    # 2. Handles / alias / perfiles
    if a.type.value != "EMAIL" and b.type.value != "EMAIL":
        ha, hb = normalize_handle(identity_value(a)), normalize_handle(identity_value(b))
        # Variante cercana: uno es prefijo del otro quitando dígitos finales.
        from specter.osint_core.correlation import TRAILING_DIGITS

        sa, sb = TRAILING_DIGITS.sub("", ha), TRAILING_DIGITS.sub("", hb)
        if ha and ha == hb:
            comparisons.append(_weight("handle_exact", "agree", f"'{ha}'", token=ha))
        elif ha and sa and sa in (hb, sb):
            comparisons.append(_weight("handle_close", "agree", f"'{ha}' vs '{hb}'", token=sa))
        else:
            comparisons.append(_weight("handle_exact", "disagree"))

    # 3. Nombre propio (PERSON vs cualquier cosa con valor textual)
    if a.type.value == "PERSON" or b.type.value == "PERSON":
        name_a = (va if a.type.value == "PERSON" else identity_value(a)).lower()
        name_b = (vb if b.type.value == "PERSON" else identity_value(b)).lower()
        if name_a != name_b:
            similarity = jaro_winkler(name_a, name_b)
            if similarity >= 0.92:
                comparisons.append(_weight("name_jw", "agree", f"JW={similarity:.2f}"))
            elif similarity >= 0.85:
                comparisons.append(_weight("name_jw", "close", f"JW={similarity:.2f}"))
            else:
                comparisons.append(_weight("name_jw", "disagree", f"JW={similarity:.2f}"))
        # Alias derivable del nombre completo con cobertura suficiente: la
        # señal que separa al sujeto de los homónimos ('cmendozagarcia' cubre
        # nombre+ambos apellidos; 'carlosgarcia' deja el apellido paterno fuera).
        person_value = va if a.type.value == "PERSON" else vb
        other = b if a.type.value == "PERSON" else a
        coverage = (
            _alias_name_coverage(identity_value(other), person_value)
            if other.type.value != "PERSON"
            else 0.0
        )
        if coverage >= _ALIAS_COVERAGE_MIN:
            comparisons.append(
                _weight(
                    "alias_of_name",
                    "agree",
                    f"'{identity_value(other)}' deriva del nombre (cobertura {coverage:.0%})",
                )
            )

    # Agregación: los disagreements negativos sólo cuentan si no hay ningún
    # acuerdo (un alias contra su PERSON "discrepa" en handle y en nombre
    # literal; el acuerdo es la señal). El ajuste TF ya está dentro de cada
    # peso de acuerdo. Las fuentes de procedencia van como contexto.
    sources = _count_sources(a.attributes, b.attributes)
    agreements = [c for c in comparisons if c.weight > 0]
    total = sum(c.weight for c in (agreements if agreements else comparisons))

    # odds = 2^R → probabilidad logística p = 2^R / (1 + 2^R), acotada [-20, 20].
    clamped = max(-20.0, min(total, 20.0))
    odds = 2.0**clamped
    probability = odds / (1.0 + odds)
    if total >= thresholds["match"]:
        # Un valor frecuente en el caso (u ajustada por TF) nunca produce
        # match automático sin una segunda fuente independiente: es el arma
        # anti-467-matches. Queda en revisión humana.
        verdict = "review" if freq_penalty > 0.0 and sources < 2 else "match"
    elif total >= thresholds["review"]:
        verdict = "review"
    else:
        verdict = "non_match"

    return PairwiseScore(
        entity_a={"entity_id": a.id, "type": a.type.value, "value": a.value},
        entity_b={"entity_id": b.id, "type": b.type.value, "value": b.value},
        total_weight=round(total, 4),
        probability=round(probability, 4),
        verdict=verdict,
        comparisons=comparisons,
        independent_sources=sources,
        frequency_penalty=freq_penalty,
    )


def explain_score(pair: PairwiseScore) -> str:
    """Explicación legible del score (para el dossier y el analista)."""
    parts = [f"{c.field}={c.agreement_level}({c.weight:+.2f})" for c in pair.comparisons]
    return f"R={pair.total_weight:+.2f} ({pair.verdict}) [{' '.join(parts) or 'sin comparaciones'}]"

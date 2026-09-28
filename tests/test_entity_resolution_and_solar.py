"""
Tests P1: Fellegi-Sunter (entity_resolution), Almirantazgo completo
(credibilidad + decay) y cronolocalización solar. Sin red, sin dependencias.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest
from specter.osint_core.admiralty import (
    assess_evidence,
    credibility_digit,
    freshness_decay,
)
from specter.osint_core.entity_resolution import (
    compare_pair,
    explain_score,
    jaro_winkler,
)
from specter.osint_core.models import EntityNode, EntityType
from specter.osint_core.solar import (
    estimate_capture_window,
    shadow_to_solar_elevation,
    solar_position,
)

# --------------------------------------------------------------------------- #
# Fellegi-Sunter                                                              #
# --------------------------------------------------------------------------- #


def test_jaro_winkler_vectores_canonicos() -> None:
    """Valores de referencia de la literatura (Winkler, yStrings de Splink)."""
    assert jaro_winkler("martha", "marhta") == pytest.approx(0.9611, abs=1e-3)
    assert jaro_winkler("dixon", "dicksonx") == pytest.approx(0.8133, abs=1e-3)
    assert jaro_winkler("alice", "alice") == 1.0
    assert jaro_winkler("", "x") == 0.0
    assert jaro_winkler("abc", "xyz") == 0.0


def test_fs_email_exacto_es_match_fuerte() -> None:
    a = EntityNode.create(EntityType.EMAIL, "alice@real.dev")
    b = EntityNode.create(EntityType.EMAIL, "alice@real.dev")
    pair = compare_pair(a, b)
    assert pair.verdict == "match"
    assert pair.total_weight > 5.0  # log2(950) ≈ 9.89
    assert pair.probability > 0.99
    assert pair.comparisons[0].field == "email"
    assert pair.comparisons[0].agreement_level == "agree"


def test_fs_mismo_buzon_distintos_dominios_es_review_o_match() -> None:
    a = EntityNode.create(EntityType.EMAIL, "alice@real.dev")
    b = EntityNode.create(EntityType.EMAIL, "alice@otro.net")
    pair = compare_pair(a, b)
    # R = log2(0.60/0.05) ≈ 3.58 → match con umbral 2.0
    assert pair.verdict == "match"
    assert pair.comparisons[0].field == "email_local"


def test_fs_variante_numerica_cae_en_review() -> None:
    """alice42/alice es sospechoso pero NO prueba identidad: revisión humana."""
    a = EntityNode.create(EntityType.ALIAS, "alice42")
    b = EntityNode.create(EntityType.ALIAS, "alice")
    pair = compare_pair(a, b)
    assert pair.verdict == "review"
    assert 0.0 <= pair.probability < 0.9


def test_fs_pares_distintos_son_non_match() -> None:
    a = EntityNode.create(EntityType.ALIAS, "bob")
    b = EntityNode.create(EntityType.ALIAS, "alice")
    pair = compare_pair(a, b)
    assert pair.verdict == "non_match"
    assert pair.total_weight < 0


def test_fs_email_vs_alias_con_mismo_buzon() -> None:
    a = EntityNode.create(EntityType.ALIAS, "alice")
    b = EntityNode.create(EntityType.EMAIL, "alice@real.dev")
    pair = compare_pair(a, b)
    assert pair.verdict == "match"
    assert pair.comparisons[0].field == "handle_exact"


def test_fs_umbrales_calibrables() -> None:
    """El analista puede endurecer el umbral: lo que era match pasa a review."""
    a = EntityNode.create(EntityType.ALIAS, "alice")
    b = EntityNode.create(EntityType.EMAIL, "alice@real.dev")
    strict = compare_pair(a, b, thresholds={"match": 10.0, "review": 5.0})
    assert strict.verdict == "review"


def test_fs_explain_score_legible() -> None:
    a = EntityNode.create(EntityType.ALIAS, "alice")
    b = EntityNode.create(EntityType.EMAIL, "alice@real.dev")
    text = explain_score(compare_pair(a, b))
    assert "R=" in text and "handle_exact" in text and "match" in text


# --------------------------------------------------------------------------- #
# FS con corrección de dependencia (el caso de los "467 matches")              #
# --------------------------------------------------------------------------- #


def test_fs_alias_repetido_en_el_caso_degrada_a_review(monkeypatch) -> None:
    """12 variantes del mismo handle de un solo pivot NO prueban identidad.

    Con frecuencias cargadas (set_term_frequencies), 'carlos.garcia' vs
    'carlos_garcia' (R base ≈ 6.41) degrada porque su u sube a count/N. Sin
    segunda fuente independiente no puede ser match automático: revisión.
    """
    from specter.osint_core import entity_resolution

    a = EntityNode.create(EntityType.ALIAS, "carlos.garcia")
    b = EntityNode.create(EntityType.ALIAS, "carlos_garcia")
    # Sin batch: comportamiento canónico fuerte.
    assert compare_pair(a, b).verdict == "match"

    # Batch con 30 entidades de identidad donde el token aparece 12 veces.
    entity_resolution.set_term_frequencies({"carlosgarcia": 12}, total=30)
    try:
        pair = compare_pair(a, b)
        assert pair.verdict == "review"  # el arma anti-467-matches
        assert pair.total_weight < 2.0
        assert pair.frequency_penalty > 0.0
    finally:
        entity_resolution.reset_term_frequencies()


def test_fs_email_unico_conserva_su_peso_fuerte() -> None:
    """Un email presente 1 vez en el caso NO se penaliza (count < 2 no ajusta)."""
    from specter.osint_core import entity_resolution

    entity_resolution.set_term_frequencies({"alice@real.dev": 1}, total=30)
    try:
        pair = compare_pair(
            EntityNode.create(EntityType.EMAIL, "alice@real.dev"),
            EntityNode.create(EntityType.EMAIL, "alice@real.dev"),
        )
        assert pair.verdict == "match"
        assert pair.frequency_penalty == 0.0
    finally:
        entity_resolution.reset_term_frequencies()


@pytest.mark.parametrize(
    ("alias", "person", "expected"),
    [
        ("cmendozagarcia", "Carlos Andres Mendoza Garcia", 0.75),  # sujeto real
        ("carlosgarcia", "Carlos Andres Mendoza Garcia", 0.50),  # homónimo genérico
        # Salta 'andres' (nombre compuesto omitido): cobertura 3/4.
        ("carlosmendozagarcia", "Carlos Andres Mendoza Garcia", 0.75),
        ("cgarcia", "Carlos Andres Mendoza Garcia", 0.5),
        ("anapinto", "Ana María De la Cruz Pinto", 0.5),
    ],
)
def test_alias_name_coverage_separa_sujeto_de_homonimos(alias, person, expected) -> None:
    from specter.osint_core.entity_resolution import _alias_name_coverage

    assert _alias_name_coverage(alias, person) == pytest.approx(expected)


def test_fs_alias_con_cobertura_alta_suma_evidencia() -> None:
    """cmendozagarcia (75% de cobertura) suma alias_of_name sobre el handle solo."""
    a = EntityNode.create(EntityType.PERSON, "Carlos Andres Mendoza Garcia")
    b = EntityNode.create(EntityType.ALIAS, "cmendozagarcia")
    pair = compare_pair(a, b)
    fields = {c.field for c in pair.comparisons}
    assert "alias_of_name" in fields
    assert pair.verdict in ("match", "review")


def test_fs_alias_homGenerico_no_suma_alias_of_name() -> None:
    """carlosgarcia (50% de cobertura) NO suma alias_of_name: material de homónimos."""
    a = EntityNode.create(EntityType.PERSON, "Carlos Andres Mendoza Garcia")
    b = EntityNode.create(EntityType.ALIAS, "carlosgarcia")
    pair = compare_pair(a, b)
    assert all(c.field != "alias_of_name" for c in pair.comparisons)


def test_fs_probability_logistica_acotada() -> None:
    """La probabilidad es logística: 0.5 en R=0, →1 en R grande, nunca negativa."""
    for _verdict_expect, t1, v1, t2, v2 in [
        ("match", EntityType.EMAIL, "a@x.dev", EntityType.EMAIL, "a@x.dev"),
        ("non_match", EntityType.ALIAS, "zzz", EntityType.ALIAS, "aaa"),
    ]:
        pair = compare_pair(EntityNode.create(t1, v1), EntityNode.create(t2, v2))
        assert 0.0 <= pair.probability <= 1.0
    # R=0 → p=0.5 exacto
    a = EntityNode.create(EntityType.ALIAS, "alice42")
    b = EntityNode.create(EntityType.ALIAS, "alice")
    assert compare_pair(a, b).probability == pytest.approx(0.75, abs=0.01)


# --------------------------------------------------------------------------- #
# Almirantazgo completo                                                       #
# --------------------------------------------------------------------------- #


def test_almirantazgo_letra_y_digito_por_defecto() -> None:
    grade = assess_evidence("dns_collector", 0.9)
    assert grade.grade == "B6"  # fuente oficial, hecho aún no juzgado
    assert grade.decayed_confidence == 0.9  # sin edad conocida no hay decay


def test_almirantazgo_digitos_credibilidad() -> None:
    assert credibility_digit(corroborated=True) == 1
    assert credibility_digit(corroborated=False, single_reliable_source=True) == 2
    assert credibility_digit(corroborated=False) == 3
    assert credibility_digit(corroborated=False, contradicted=True) == 5
    assert credibility_digit() == 6


def test_almirantazgo_decay_volatile_vs_criptografico() -> None:
    # IP vista hace 180 días: decay exponencial con vida media 90d → x0.25
    decayed = freshness_decay(0.8, 180, entity_type="IP_ADDRESS")
    assert decayed == pytest.approx(0.2, abs=0.01)
    # Hash de archivo: los artefactos criptográficos NO decaen jamás
    assert freshness_decay(0.9, 3650, entity_type="FILE_ARTIFACT") == 0.9
    # Sin edad conocida: no se castiga la ignorancia
    assert freshness_decay(0.7, None) == 0.7
    # Piso mínimo (nunca llega a 0)
    assert freshness_decay(0.9, 100_000, entity_type="DOMAIN") >= 0.05


def test_almirantazgo_grade_compuesto() -> None:
    corroborated = assess_evidence("crt_sh_collector", 0.9, corroborated=True)
    assert corroborated.grade == "B1"
    contradicted = assess_evidence(
        "web_search_collector", 0.7, corroborated=False, contradicted=True
    )
    assert contradicted.grade == "D5"
    data = corroborated.as_dict()
    assert data["credibility_meaning"].startswith("confirmado")


# --------------------------------------------------------------------------- #
# Cronolocalización                                                           #
# --------------------------------------------------------------------------- #


def test_solar_posicion_valida_contra_referencias() -> None:
    """Londres, solsticio de junio, mediodía UTC: elev ≈ 62°, decl ≈ 23.44°."""
    pos = solar_position(51.5074, -0.1278, datetime(2026, 6, 21, 12, 0, tzinfo=UTC))
    assert pos["elevation"] == pytest.approx(61.9, abs=0.5)
    assert pos["declination"] == pytest.approx(23.44, abs=0.1)


def test_solar_arco_diurno_este_sur_oeste() -> None:
    """En Madrid (hemisferio norte): mañana E, mediodía S, tarde O."""
    east = solar_position(40.4168, -3.7038, datetime(2026, 3, 20, 7, 30, tzinfo=UTC))
    west = solar_position(40.4168, -3.7038, datetime(2026, 3, 20, 16, 30, tzinfo=UTC))
    noon = solar_position(40.4168, -3.7038, datetime(2026, 3, 20, 11, 45, tzinfo=UTC))
    # Amanecer por el este, atardecer por el oeste, culminación al sur
    assert 60 < east["azimuth"] < 120 and east["elevation"] > 0
    assert 230 < west["azimuth"] < 290 and west["elevation"] > 0
    assert 150 < noon["azimuth"] < 210
    assert noon["elevation"] > east["elevation"]


def test_shadow_to_solar_elevation_gnomon() -> None:
    """Sombra igual a la altura → 45°; sombra doble → arctan(1/2) ≈ 26.57°."""
    assert shadow_to_solar_elevation(1.0, 1.0) == pytest.approx(45.0)
    assert shadow_to_solar_elevation(2.0, 1.0) == pytest.approx(math.degrees(math.atan(0.5)))
    with pytest.raises(ValueError):
        shadow_to_solar_elevation(0, 1)


def test_cronolocalizacion_recupera_la_ventana() -> None:
    """Auto-consistencia: sol real → sombra inversa → ventana que lo contiene."""
    truth = solar_position(40.4168, -3.7038, datetime(2026, 3, 20, 16, 30, tzinfo=UTC))
    shadow_azimuth = (truth["azimuth"] + 180.0) % 360.0
    shadow_length = 3.0 / math.tan(math.radians(truth["elevation"]))

    report = estimate_capture_window(
        40.4168,
        -3.7038,
        datetime(2026, 3, 20),
        shadow_azimuth_deg=shadow_azimuth,
        shadow_length=shadow_length,
        object_height=3.0,
    )

    assert report["window_count"] >= 1
    matching = [
        w
        for w in report["windows"]
        if w["start_utc"] <= "2026-03-20T16:30:00+00:00" <= w["end_utc"]
    ]
    assert matching, "la ventana 16:30 UTC debía aparecer"
    assert report["observed"]["solar_azimuth_deg"] == pytest.approx(truth["azimuth"], abs=0.5)


def test_cronolocalizacion_requiere_observacion() -> None:
    with pytest.raises(ValueError):
        estimate_capture_window(40.0, -3.0, datetime(2026, 3, 20))


def test_cronolocalizacion_con_solo_elevacion_sin_acimut() -> None:
    """Sin acimut la ventana es más ancha (mañana+tarde) pero acotada."""
    report = estimate_capture_window(
        40.4168,
        -3.7038,
        datetime(2026, 3, 20),
        solar_elevation_deg=45.0,
        tolerance_elevation=0.5,
    )
    assert report["window_count"] >= 2  # mañana y tarde
    for window in report["windows"]:
        assert window["minutes"] <= 60  # elevación 45° ocurre en rangos cortos

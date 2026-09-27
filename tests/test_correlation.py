"""
Tests del motor de correlación: artefactos compartidos entre casos, similitud
de casos y candidatos de resolución de identidad.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from specter.osint_core.correlation import (
    CorrelationEngine,
    handle_keys,
    identity_value,
    normalize_handle,
)
from specter.osint_core.database import Database
from specter.osint_core.models import CaseMetadata, EntityNode, EntityType


@pytest.fixture()
def db(engine_env: Path) -> Database:
    return Database(engine_env)


def _case(db: Database, case_id: str) -> str:
    db.create_case(
        CaseMetadata(case_id=case_id, name=case_id, description="d", investigator="pytest")
    )
    return case_id


def _seed(db: Database, case_id: str, values: list[tuple[EntityType, str]]) -> list[EntityNode]:
    entities = [EntityNode.create(t, v) for t, v in values]
    db.upsert_entities(case_id, entities)
    return entities


def _two_cases(db: Database) -> None:
    _case(db, "case-a")
    _case(db, "case-b")
    _seed(
        db,
        "case-a",
        [
            (EntityType.DOMAIN, "shared.test"),
            (EntityType.EMAIL, "alice@real.dev"),
            (EntityType.IP_ADDRESS, "203.0.113.9"),
        ],
    )
    _seed(
        db,
        "case-b",
        [
            (EntityType.DOMAIN, "shared.test"),
            (EntityType.EMAIL, "alice@real.dev"),
            (EntityType.DOMAIN, "solo-de-b.test"),
        ],
    )


def test_cross_case_matches_detecta_artefactos_compartidos(db):
    _two_cases(db)

    report = CorrelationEngine(db).cross_case_matches()

    assert report["total_shared_entities"] == 2
    assert report["cases_involved"] == ["case-a", "case-b"]
    assert report["cases_involved_count"] == 2
    assert report["by_type"] == {"DOMAIN": 1, "EMAIL": 1}

    match = next(m for m in report["matches"] if m["type"] == "DOMAIN")
    assert match["entity_id"] == "domain:shared.test"
    assert match["value"] == "shared.test"
    assert match["case_count"] == 2
    assert match["case_ids"] == ["case-a", "case-b"]
    assert match["confidence"] == 1.0
    assert match["first_seen"] <= match["last_seen"]


def test_cross_case_matches_anclado_a_un_caso_excluye_terceros(db):
    _two_cases(db)
    _case(db, "case-c")
    _seed(db, "case-c", [(EntityType.DOMAIN, "solo-de-b.test")])

    anchored = CorrelationEngine(db).cross_case_matches(case_id="case-a")

    assert [m["entity_id"] for m in anchored["matches"]] == [
        "domain:shared.test",
        "email:alice@real.dev",
    ]
    assert "case-c" not in anchored["cases_involved"]
    # Sin ancla, el dominio compartido por b y c también aparece.
    assert {m["entity_id"] for m in CorrelationEngine(db).cross_case_matches()["matches"]} == {
        "domain:shared.test",
        "email:alice@real.dev",
        "domain:solo-de-b.test",
    }


def test_cross_case_matches_filtra_por_tipo(db):
    _two_cases(db)

    report = CorrelationEngine(db).cross_case_matches(entity_types=["email"])

    assert [m["entity_id"] for m in report["matches"]] == ["email:alice@real.dev"]
    assert report["by_type"] == {"EMAIL": 1}


def test_case_similarity_veredicto_alto(db):
    _two_cases(db)
    _seed(db, "case-a", [(EntityType.SUBDOMAIN, "vpn.shared.test"), (EntityType.ALIAS, "alice")])
    _seed(db, "case-b", [(EntityType.ALIAS, "alice")])

    report = CorrelationEngine(db).case_similarity("case-a", "case-b")

    assert report["shared_count"] == 3
    assert report["verdict"] == "HIGH"
    assert report["entities_a"] == 5 and report["entities_b"] == 4
    assert 0 < report["jaccard"] < 1
    assert report["shared_by_type"] == {"DOMAIN": 1, "EMAIL": 1, "ALIAS": 1}
    assert [e["value"] for e in report["shared_entities"]] == [
        "alice",
        "shared.test",
        "alice@real.dev",
    ]
    assert report["shared_entities"][1]["type"] == "DOMAIN"


def test_case_similarity_mismo_caso_y_sin_solapamiento(db):
    _two_cases(db)

    mismo = CorrelationEngine(db).case_similarity("case-a", "case-a")
    assert mismo["jaccard"] == 1.0
    assert mismo["shared_count"] == mismo["entities_a"] == 3
    assert mismo["verdict"] == "HIGH"

    vacio = CorrelationEngine(db).case_similarity("case-a", "case-inexistente")
    assert vacio["verdict"] == "NONE"
    assert vacio["shared_count"] == 0 and vacio["jaccard"] == 0.0
    assert vacio["entities_b"] == 0


def test_identity_candidates_propone_resolucion_de_identidad(db):
    _case(db, "case-id")
    _seed(
        db,
        "case-id",
        [
            (EntityType.ALIAS, "alice"),
            (EntityType.ALIAS, "@A.L.I.C.E."),
            (EntityType.EMAIL, "alice@real.dev"),
            (EntityType.SOCIAL_PROFILE, "https://github.com/alice"),
            (EntityType.ALIAS, "alice42"),
            (EntityType.DOMAIN, "alice.dev"),
        ],
    )

    report = CorrelationEngine(db).identity_candidates("case-id")

    assert report["analyzed_entities"] == 5  # el dominio no es identidad
    assert report["total_candidates"] == 6
    assert all(c["score"] >= 0.7 for c in report["candidates"])
    assert report["candidates"][0]["score"] == 0.85
    assert report["candidates"][0]["suggested_relation"] == "CORRELATED_WITH"
    assert {e["entity_id"] for c in report["candidates"] for e in c["entities"]} == {
        "alias:alice",
        "alias:@a.l.i.c.e.",
        "email:alice@real.dev",
        "social_profile:https://github.com/alice",
    }
    assert all(c["normalized_key"] == "alice" for c in report["candidates"])

    # La variante numérica (alice42) sólo aparece si el analista baja el umbral.
    weak = CorrelationEngine(db).identity_candidates("case-id", min_score=0.5)
    assert weak["total_candidates"] == 10
    assert weak["candidates"][-1]["score"] == 0.6
    assert "variante numérica" in weak["candidates"][-1]["reason"]

    limited = CorrelationEngine(db).identity_candidates("case-id", limit=2)
    assert len(limited["candidates"]) == 2
    assert limited["total_candidates"] == 6


def test_identity_candidates_valor_identico(db):
    """Mismo valor en dos tipos distintos: el id canónico difiere, la identidad no."""
    _case(db, "case-dup")
    _seed(db, "case-dup", [(EntityType.ALIAS, "alice"), (EntityType.PERSON, "alice")])

    report = CorrelationEngine(db).identity_candidates("case-dup")

    assert report["total_candidates"] == 1
    candidate = report["candidates"][0]
    assert candidate["score"] == 0.9
    assert candidate["reason"] == "valor idéntico: 'alice' en ALIAS y PERSON"
    assert {e["type"] for e in candidate["entities"]} == {"ALIAS", "PERSON"}


def test_identity_candidates_caso_vacio(db):
    _case(db, "case-vacio")

    report = CorrelationEngine(db).identity_candidates("case-vacio")

    assert report == {
        "case_id": "case-vacio",
        "analyzed_entities": 0,
        "total_candidates": 0,
        "min_score": 0.7,
        "candidates": [],
    }


@pytest.mark.parametrize(
    ("entity_type", "value", "expected"),
    [
        (EntityType.ALIAS, "@Alice", "Alice"),
        (EntityType.EMAIL, "Alice@Real.DEV", "Alice"),
        (EntityType.SOCIAL_PROFILE, "https://github.com/alice/", "alice"),
        (EntityType.SOCIAL_PROFILE, "https://t.me/alice", "alice"),
        (EntityType.SOCIAL_PROFILE, "https://gravatar.com/abc123", "abc123"),
        (EntityType.PERSON, "Alice Doe", "Alice Doe"),
    ],
)
def test_identity_value_extrae_el_handle(entity_type, value, expected):
    assert identity_value(EntityNode.create(entity_type, value)) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("@Alice", "alice"),
        ("a.l.i.c.e", "alice"),
        ("alice_doe-01", "alicedoe01"),
        ("  ALICE  ", "alice"),
    ],
)
def test_normalize_handle(value, expected):
    assert normalize_handle(value) == expected


def test_handle_keys_incluye_variante_sin_digitos():
    entity = EntityNode.create(EntityType.ALIAS, "alice42")

    assert handle_keys(entity) == {"alice42", "alice"}
    assert handle_keys(EntityNode.create(EntityType.ALIAS, "   ")) == set()

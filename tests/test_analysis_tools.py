"""
Tests Fase C: herramientas de análisis expuestas (path, candidatos, similitud,
STIX) y confianza por arista en el dossier. Sin red.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from specter.osint_core.models import (
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

pytestmark = pytest.mark.asyncio


def _seed_chain(engine) -> tuple[str, str, str]:
    """Caso con cadena alias -> email -> dominio para path y candidatos."""
    import specter.server as server

    case_id = json.loads(server.create_case("Caso C", "d"))["case_id"]
    alice = EntityNode.create(EntityType.ALIAS, "alice", "Alias: @alice")
    email = EntityNode.create(EntityType.EMAIL, "alice@real.dev", "Email: alice@real.dev")
    domain = EntityNode.create(EntityType.DOMAIN, "real.dev", "Domain: real.dev")
    engine.db.upsert_entities(case_id, [alice, email, domain])
    engine.db.upsert_relations(
        case_id,
        [
            RelationEdge(
                source_id=alice.id,
                target_id=email.id,
                relation_type=RelationType.USES_ALIAS,
                confidence=0.7,
            ),
            RelationEdge(
                source_id=email.id,
                target_id=domain.id,
                relation_type=RelationType.HOSTED_ON,
                confidence=0.9,
            ),
        ],
    )
    return case_id, alice.id, domain.id


def test_find_entity_path_mide_saltos(engine) -> None:
    import specter.server as server

    case_id, src, dst = _seed_chain(engine)
    body = json.loads(server.find_entity_path(case_id, src, dst))
    assert body["status"] == "COMPLETED"
    assert body["hops"] == 2
    assert [n["id"] for n in body["path"]] == [src, "email:alice@real.dev", dst]

    missing = json.loads(server.find_entity_path(case_id, src, "alias:nadie"))
    assert missing["path"] == [] and missing["hops"] is None
    assert "error" in json.loads(server.find_entity_path("case-nope", "a", "b"))


def test_suggest_identity_links_propone_con_score(engine) -> None:
    import specter.server as server

    case_id, _, _ = _seed_chain(engine)
    body = json.loads(server.suggest_identity_links(case_id))
    assert body["status"] == "COMPLETED"
    assert body["total_candidates"] >= 1
    first = body["candidates"][0]
    assert first["score"] >= 0.7 and first["suggested_relation"] == "CORRELATED_WITH"
    assert body["candidates"] == sorted(body["candidates"], key=lambda c: -c["score"])


def test_compare_cases_detecta_infraestructura_comun(engine) -> None:
    import specter.server as server

    case_id, _, _ = _seed_chain(engine)
    other = json.loads(server.create_case("Caso D", "d"))["case_id"]
    engine.db.upsert_entities(
        other, [EntityNode.create(EntityType.DOMAIN, "real.dev", "Domain: real.dev")]
    )
    body = json.loads(server.compare_cases(case_id, other))
    assert body["status"] == "COMPLETED"
    assert body["verdict"] in ("MODERATE", "HIGH")

    unknown = json.loads(server.compare_cases(case_id, "case-nope"))
    assert "error" in unknown


def test_export_case_stix_bundle_valido(engine, tmp_path) -> None:
    import specter.server as server
    from specter.visualizer.exporter import DossierExporter

    case_id, _, _ = _seed_chain(engine)
    out = tmp_path / "caso.json"
    path = DossierExporter(engine.db).export_stix(case_id, out)
    bundle = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle" and bundle["spec_version"] == "2.1"
    kinds = {o["type"] for o in bundle["objects"]}
    assert {"identity", "domain-name", "email-addr", "user-account"} <= kinds
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert rels and all(o["confidence"] in (70, 90) for o in rels)

    via_tool = json.loads(server.export_case_stix(case_id))
    assert via_tool["status"] == "STIX_EXPORTED" and via_tool["format"] == "stix2.1"
    assert json.loads(server.export_case_stix("case-nope")).get("error")


def test_dossier_md_incluye_relaciones_con_confianza(engine, tmp_path) -> None:
    from specter.visualizer.exporter import DossierExporter

    case_id, _, _ = _seed_chain(engine)
    out = DossierExporter(engine.db).export_markdown(case_id, tmp_path / "d.md")
    md = pathlib.Path(out).read_text(encoding="utf-8")
    assert "## 2b. Relaciones con Confianza" in md
    assert "USES_ALIAS" in md and "70%" in md and "90%" in md

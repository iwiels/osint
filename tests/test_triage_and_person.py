"""Tests de triage de artefactos y del colector de personas (investigate_person)."""

import pytest
from specter import triage
from specter.collectors.person import PersonInvestigator, derive_username_candidates
from specter.osint_core.models import EntityType, RelationType

# ---------------------------------------------------------------------------
# Triage de artefactos
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_tool"),
    [
        ("juan.perez@ejemplo.test", EntityType.EMAIL, "investigate_email"),
        ("198.51.100.7", EntityType.IP_ADDRESS, "investigate_ip"),
        ("2001:db8::1", EntityType.IP_ADDRESS, "investigate_ip"),
        ("google.com", EntityType.DOMAIN, "investigate_domain"),
        ("mail.google.com", EntityType.SUBDOMAIN, "investigate_domain"),
        ("12345678Z", EntityType.DOCUMENT_ID, "hunt_documents_and_leaks"),
        ("X1234567L", EntityType.DOCUMENT_ID, "hunt_documents_and_leaks"),
        ("20-12345678-9", EntityType.DOCUMENT_ID, "hunt_documents_and_leaks"),
        ("12.345.678-5", EntityType.DOCUMENT_ID, "hunt_documents_and_leaks"),
        ("99999999", EntityType.DOCUMENT_ID, "hunt_documents_and_leaks"),
        ("1234567", EntityType.DOCUMENT_ID, "hunt_documents_and_leaks"),
        ("Ana María Pinto", EntityType.PERSON, "investigate_person"),
        ("elvis", EntityType.ALIAS, "investigate_identity"),
    ],
)
def test_triage_classifies(raw, expected_type, expected_tool):
    verdict = triage.triage_artifact(raw)
    assert verdict.entity_type == expected_type
    assert verdict.tool == expected_tool


def test_triage_rejects_invalid_ipv4():
    verdict = triage.triage_artifact("999.999.999.999")
    assert verdict.entity_type != EntityType.IP_ADDRESS


def test_triage_username_strips_at():
    verdict = triage.triage_artifact("@elvispinto")
    assert verdict.entity_type == EntityType.ALIAS
    assert verdict.args["username"] == "elvispinto"


def test_triage_person_is_tool_ready():
    verdict = triage.triage_artifact("Ana María Pinto")
    assert verdict.args == {"full_name": "Ana María Pinto"}


# ---------------------------------------------------------------------------
# Derivación de usernames
# ---------------------------------------------------------------------------


def test_derive_usernames_from_full_name():
    candidates = derive_username_candidates("Ana María De la Cruz Pinto")
    assert "ana.pinto" in candidates
    assert "anapinto" in candidates
    assert "anamariacruzpinto" in candidates  # nombre + apellidos unidos
    assert all(3 <= len(c) <= 30 for c in candidates)


def test_derive_usernames_single_word():
    assert derive_username_candidates("Madonna") == ["madonna"]


# ---------------------------------------------------------------------------
# Colector PersonInvestigator
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "data"))
    from specter.osint_core.database import Database

    return Database(tmp_path / "triage_osint.db")


async def test_person_collector_builds_person_and_aliases(temp_db):

    from specter.osint_core.graph import OSINTGraph
    from specter.osint_core.models import CaseMetadata

    temp_db.create_case(
        CaseMetadata(case_id="case-triage-test", name="Triage", description="", investigator="t")
    )
    graph = OSINTGraph(temp_db)
    collector = PersonInvestigator()
    res = await collector.collect("Ana María Pinto")

    assert any(e.type == EntityType.PERSON and e.value == "Ana María Pinto" for e in res.entities)
    aliases = [e for e in res.entities if e.type == EntityType.ALIAS]
    assert len(aliases) >= 3
    # Todas las relaciones conectan la persona con sus alias derivados
    person_id = next(e.id for e in res.entities if e.type == EntityType.PERSON)
    assert all(
        r.source_id == person_id and r.relation_type == RelationType.USES_ALIAS
        for r in res.relations
    )

    # La ingesta al grafo funciona end-to-end
    graph.ingest_collector_result("case-triage-test", res)
    subgraph = graph.query_subgraph("case-triage-test")
    values = {n["value"] for n in subgraph["nodes"]}
    assert "Ana María Pinto" in values
    assert any("." in v for v in values)  # algún alias derivado


async def test_person_collector_rejects_empty(temp_db):
    collector = PersonInvestigator()
    with pytest.raises(ValueError):
        await collector.collect("   ")


async def test_person_collector_with_active_search(temp_db):
    from unittest.mock import AsyncMock, patch

    from specter.osint_core.models import CollectorResult, EntityNode, EntityType

    collector = PersonInvestigator()
    mock_search_result = CollectorResult(
        collector_name="web_search",
        source_target='"Carlos Andres Mendoza Garcia"',
        entities=[
            EntityNode.create(EntityType.ALIAS, "root"),
            EntityNode.create(
                EntityType.DOMAIN,
                "https://universidad.test/estudiantes/carlos-mendoza",
                attributes={
                    "title": "Carlos Andres Mendoza Garcia - Universidad Base 22",
                    "snippet": "Estudiante de ingeniería de sistemas.",
                },
            ),
            EntityNode.create(
                EntityType.DOMAIN,
                "https://es.scribd.com/document/12345/trabajo-grupal",
                attributes={
                    "title": "Trabajo de Computación en la Nube - Scribd",
                    "snippet": "Autores: Carlos Mendoza Garcia y otros.",
                },
            ),
            EntityNode.create(
                EntityType.DOMAIN,
                "https://universidad.test/profesores/otra-mencion",
                attributes={
                    "title": "Facultad de Sistemas",
                    "snippet": "Mención del alumno Carlos.",
                },
            ),
        ],
        relations=[],
        metadata={"results": 3, "ok": True},
    )

    with patch(
        "specter.collectors.web.WebSearchCollector.collect_many",
        new_callable=AsyncMock,
        return_value=mock_search_result,
    ):
        res = await collector.collect("Carlos Andres Mendoza Garcia", execute_search=True)

        # El nombre de la institución se deriva del host del hallazgo: el
        # colector no conoce ninguna universidad concreta.
        academic_orgs = [
            e
            for e in res.entities
            if e.type == EntityType.ORGANIZATION and e.value == "universidad.test"
        ]
        assert len(academic_orgs) == 1
        assert any(
            e.type == EntityType.FILE_ARTIFACT and "scribd.com" in e.value for e in res.entities
        )
        assert res.metadata["web_search"]["ok"] is True
        assert res.metadata["web_search"]["results_count"] == 3


# ---------------------------------------------------------------------------
# Tools MCP registradas
# ---------------------------------------------------------------------------


async def test_new_mcp_tools_registered():
    from specter.server import mcp_server

    tools = await mcp_server.list_tools()
    names = {t.name for t in tools}
    assert "investigate_person" in names
    assert "triage_entity" in names

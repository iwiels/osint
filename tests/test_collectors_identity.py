"""
Tests de los colectores de identidad: huella de username por plataformas,
dataset WhatsMyName y enriquecimiento de email.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from http_mock import MockRouter, patch_network
from specter.collectors import identity
from specter.collectors.identity import (
    EmailInvestigator,
    UsernameInvestigator,
    is_wmn_match,
)
from specter.osint_core.models import EntityType, RelationType

PLATFORM_HTML_TELEGRAM = "<div class='tgme_page_action'>View in Telegram</div>"


def _platform_router() -> MockRouter:
    return (
        MockRouter()
        .add("GET", r"api\.github\.com/users/alice$", json={"login": "alice"})
        .add("GET", r"gitlab\.com/alice$", text="not found", status_code=404)
        .add("GET", r"hacker-news\.firebaseio\.com/v0/user/alice\.json", json={"id": "alice"})
        .add("GET", r"hub\.docker\.com/v2/users/alice", json={"username": "alice"})
        .add("GET", r"keybase\.io/_/api/1\.0/user/lookup\.json", json={"them": [None]})
        .add("GET", r"t\.me/alice$", text=PLATFORM_HTML_TELEGRAM)
        .add("GET", r"reddit\.com/user/alice/about\.json", json={"data": {"is_suspended": False}})
    )


async def test_username_investigator_detecta_plataformas(monkeypatch):
    patch_network(monkeypatch, _platform_router(), {})

    result = await UsernameInvestigator().collect("@alice")

    platforms = {
        e.attributes["platform"] for e in result.entities if e.type == EntityType.SOCIAL_PROFILE
    }
    assert platforms == {"GitHub", "HackerNews", "DockerHub", "Telegram", "Reddit"}
    assert result.metadata["matches_found"] == len(platforms)
    assert result.metadata["unicode_normalized"] is False

    alias_edges = [r for r in result.relations if r.relation_type == RelationType.REGISTERED_WITH]
    assert len(alias_edges) == len(platforms)
    assert {r.source_id for r in alias_edges} == {"alias:alice"}


async def test_username_investigator_descarta_perfiles_suspendidos(monkeypatch):
    router = _platform_router()
    router.add("GET", r"reddit\.com/user/bob/about\.json", json={"data": {"is_suspended": True}})
    router.add("GET", r"t\.me/bob$", text="<div>perfil inexistente</div>")
    router.add("GET", r"api\.github\.com/users/bob$", text="", status_code=404)
    patch_network(monkeypatch, router, {})

    result = await UsernameInvestigator().collect("bob")

    assert result.metadata["matches_found"] == 0
    assert [e.type for e in result.entities] == [EntityType.ALIAS]


async def test_username_investigator_normaliza_homoglifos(monkeypatch):
    patch_network(monkeypatch, _platform_router(), {})

    result = await UsernameInvestigator().collect("\uff41lice")  # 'ａ' fullwidth → 'a'

    assert result.metadata["unicode_normalized"] is True
    norm = next(e for e in result.entities if e.attributes.get("homoglyph_of"))
    assert norm.value == "alice"
    assert any(r.relation_type == RelationType.USES_ALIAS for r in result.relations)
    # El segundo barrido no debe duplicar perfiles ya encontrados.
    urls = [e.value for e in result.entities if e.type == EntityType.SOCIAL_PROFILE]
    assert len(urls) == len(set(urls))
    assert result.metadata["matches_found"] == 5


async def test_username_investigator_consume_dataset_wmn(engine_env: Path, monkeypatch):
    data_dir = engine_env.parent
    (data_dir / "wmn-data.json").write_text(
        json.dumps(
            {
                "sites": [
                    {
                        "name": "MatchSite",
                        "uri_check": "https://match.test/{account}",
                        "uri_pretty": "https://match.test/u/{account}",
                        "cat": "social",
                        "e_code": 200,
                        "e_string": "seguidores",
                    },
                    {
                        "name": "MissSite",
                        "uri_check": "https://miss.test/{account}",
                        "e_code": 200,
                        "e_string": "bienvenido",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(identity, "WMN_SITES", [])  # invalida la caché de módulo

    router = _platform_router()
    router.add("GET", r"match\.test/alice", text="<h1>seguidores 42</h1>")
    router.add("GET", r"miss\.test/alice", text="<h1>cuenta no encontrada</h1>")
    patch_network(monkeypatch, router, {})

    result = await UsernameInvestigator().collect("alice")

    match = next(e for e in result.entities if e.attributes.get("platform") == "MatchSite")
    assert match.value == "https://match.test/u/alice"
    assert match.attributes["category"] == "social"
    assert result.metadata["platforms_checked"] == len(identity.PLATFORM_DEFINITIONS) + 2


async def test_username_investigator_sin_dataset_wmn(engine_env: Path, monkeypatch):
    monkeypatch.setattr(identity, "WMN_SITES", [])
    patch_network(monkeypatch, _platform_router(), {})

    result = await UsernameInvestigator().collect("alice")

    assert result.metadata["platforms_checked"] == len(identity.PLATFORM_DEFINITIONS)


@pytest.mark.parametrize(
    ("site", "code", "body", "expected"),
    [
        ({"e_code": 200, "e_string": "ok"}, 200, "todo ok", True),
        ({"e_code": 200, "e_string": "ok"}, 200, "sin marca", False),
        ({"m_code": 404, "e_code": 200}, 404, "cualquiera", False),
        ({"m_string": "no existe", "e_code": 200}, 200, "no existe", False),
        ({}, 200, "cualquiera", True),
        ({}, 404, "cualquiera", False),
    ],
)
def test_is_wmn_match_aplica_marcadores(site, code, body, expected):
    assert is_wmn_match(site, code, body) is expected


async def test_email_investigator_enriquece_con_mx_y_gravatar(monkeypatch):
    router = MockRouter().add("HEAD", r"gravatar\.com/avatar/", text="", status_code=200)
    zone = {"real.dev/mx": ["mail.real.dev"]}
    patch_network(monkeypatch, router, zone)

    result = await EmailInvestigator().collect("Alice@Real.DEV")

    assert result.source_target == "alice@real.dev"
    report = json.loads(result.raw_payload)
    assert report["valid_syntax"] is True
    assert report["is_disposable_domain"] is False
    assert report["mx_records"] == ["mail.real.dev"]
    assert report["has_gravatar"] is True
    assert len(report["hashes"]["md5"]) == 32 and len(report["hashes"]["sha256"]) == 64

    assert {e.type for e in result.entities} == {
        EntityType.EMAIL,
        EntityType.ALIAS,
        EntityType.DOMAIN,
        EntityType.SOCIAL_PROFILE,
    }
    assert result.metadata["has_mx"] is True
    assert any(r.relation_type == RelationType.HOSTED_ON for r in result.relations)


async def test_email_pivota_username_en_plataformas_rapidas(monkeypatch):
    """holehe-lite: el local-part se chequea en las 7 rápidas (señal, conf 0.7)."""
    router = _platform_router().add("HEAD", r"gravatar\.com/avatar/", text="", status_code=200)
    zone = {"real.dev/mx": ["mail.real.dev"]}
    patch_network(monkeypatch, router, zone)

    result = await EmailInvestigator().collect("alice@real.dev")

    report = json.loads(result.raw_payload)
    assert len(report["username_pivot"]) >= 3
    pivots = [
        e
        for e in result.entities
        if e.type == EntityType.SOCIAL_PROFILE and e.attributes.get("via") == "email-username-pivot"
    ]
    assert {e.attributes["platform"] for e in pivots} >= {"GitHub", "Telegram"}
    assert all(e.confidence == 0.7 for e in pivots)
    assert any(
        r.relation_type == RelationType.USES_ALIAS and r.confidence == 0.7 for r in result.relations
    )


async def test_email_investigator_sin_gravatar_ni_mx(monkeypatch):
    router = MockRouter().add("HEAD", r"gravatar\.com/avatar/", text="", status_code=404)
    patch_network(monkeypatch, router, {})

    result = await EmailInvestigator().collect("bob@desconocido.test")

    report = json.loads(result.raw_payload)
    assert report["has_gravatar"] is False
    assert report["mx_records"] == [] and "mx_error" in report
    assert result.metadata["has_mx"] is False
    assert EntityType.SOCIAL_PROFILE not in {e.type for e in result.entities}


async def test_email_investigator_dominio_desechable(monkeypatch):
    patch_network(monkeypatch, MockRouter(), {})

    result = await EmailInvestigator().collect("alice@mailinator.com")

    node = next(e for e in result.entities if e.type == EntityType.EMAIL)
    assert node.attributes["disposable"] is True
    assert json.loads(result.raw_payload)["is_disposable_domain"] is True


async def test_email_investigator_sintaxis_invalida(monkeypatch):
    patch_network(monkeypatch, MockRouter(), {})

    result = await EmailInvestigator().collect("no-es-un-email")

    assert result.metadata == {"valid": False}
    assert len(result.entities) == 1 and not result.relations
    assert json.loads(result.raw_payload)["valid_syntax"] is False


async def test_username_investigator_marca_objetivo_numerico(monkeypatch):
    """Un handle puramente numérico no es identidad atribuida: confianza 0.5 + aviso."""
    router = MockRouter().add(
        "GET", r"api\.github\.com/users/99999999$", json={"login": "99999999"}
    )
    patch_network(monkeypatch, router, {})

    result = await UsernameInvestigator().collect("99999999")

    assert result.metadata["numeric_target"] is True
    assert result.metadata["matches_found"] == 1
    profile = next(e for e in result.entities if e.type == EntityType.SOCIAL_PROFILE)
    assert profile.confidence == 0.5
    assert "numeric_handle_warning" in profile.attributes
    edge = next(r for r in result.relations if r.relation_type == RelationType.REGISTERED_WITH)
    assert edge.confidence == 0.5

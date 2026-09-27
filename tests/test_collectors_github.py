"""
Tests del colector de GitHub con la API mockeada (perfil, claves, repos y commits).
"""

from __future__ import annotations

import json

from http_mock import MockRouter, patch_httpx
from specter.collectors.github_forensics import GitHubForensics
from specter.osint_core.models import EntityType, RelationType

PROFILE = {
    "login": "alice",
    "name": "Alice Doe",
    "html_url": "https://github.com/alice",
    "bio": "Reverse engineer",
    "company": "@acme",
    "location": "Madrid",
    "blog": "https://alice.test",
    "public_repos": 3,
    "created_at": "2019-04-01T10:00:00Z",
}

REPOS = [
    {"name": "demo", "description": "Bot https://discord.gg/abc123 y nada más"},
    {"name": "tool", "description": None},
]

COMMITS = [
    {"commit": {"author": {"email": "alice@real.dev", "name": "Alice Doe"}}},
    {"commit": {"author": {"email": "1234+alice@users.noreply.github.com", "name": "Alice"}}},
]


def _router() -> MockRouter:
    return (
        MockRouter()
        .add("GET", r"api\.github\.com/users/alice$", json=PROFILE)
        .add(
            "GET",
            r"github\.com/alice\.keys",
            text="ssh-rsa AAAAB3NzaC1yc2E alice@laptop\nssh-ed25519 AAAAC3Nza alice@laptop",
        )
        .add("GET", r"api\.github\.com/users/alice/repos", json=REPOS)
        .add("GET", r"api\.github\.com/repos/alice/demo/commits", json=COMMITS)
        .add("GET", r"api\.github\.com/repos/alice/tool/commits", json=[])
    )


async def test_github_forensics_mina_perfil_claves_y_emails_de_commits(monkeypatch):
    router = patch_httpx(monkeypatch, _router())

    result = await GitHubForensics().collect("@alice")

    types = {e.type for e in result.entities}
    assert {
        EntityType.ALIAS,
        EntityType.SOCIAL_PROFILE,
        EntityType.PERSON,
        EntityType.FILE_ARTIFACT,
        EntityType.EMAIL,
    } <= types

    emails = {e.value for e in result.entities if e.type == EntityType.EMAIL}
    assert emails == {"alice@real.dev"}  # los noreply se descartan

    report = json.loads(result.raw_payload)
    assert report["repositories"] == ["demo", "tool"]
    assert report["external_links"] == ["https://discord.gg/abc123"]
    assert report["discovered_commit_emails"] == [["alice@real.dev", "Alice Doe"]]

    assert result.metadata == {
        "repos_analyzed": 2,
        "emails_extracted": 1,
        "external_links_found": 1,
    }
    assert router.count(r"repos/alice/demo/commits") == 1


async def test_github_forensics_relaciones_tipadas(monkeypatch):
    patch_httpx(monkeypatch, _router())

    result = await GitHubForensics().collect("alice")

    alias_id = "alias:alice"
    profile_id = "social_profile:https://github.com/alice"
    assert any(
        r.source_id == alias_id
        and r.target_id == profile_id
        and r.relation_type == RelationType.REGISTERED_WITH
        for r in result.relations
    )
    assert any(
        r.relation_type == RelationType.USES_ALIAS and r.source_id == "person:alice doe"
        for r in result.relations
    )
    email_edge = next(r for r in result.relations if r.target_id == "email:alice@real.dev")
    assert email_edge.confidence == 0.98
    assert email_edge.attributes == {}


async def test_github_forensics_usuario_inexistente(monkeypatch):
    patch_httpx(monkeypatch, MockRouter().add("GET", r"users/ghost$", json={}, status_code=404))

    result = await GitHubForensics().collect("ghost")

    assert [e.type for e in result.entities] == [EntityType.ALIAS]
    payload = json.loads(result.raw_payload)
    assert payload["status"] == 404
    assert "not found" in payload["error"]
    assert result.metadata == {}

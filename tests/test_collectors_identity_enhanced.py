"""
Tests for enhanced identity collectors: MaigretHunter, HoleheHunter, and IdentityCollector.
Verifies parsing of profiles, bio snippets, avatars, person/email/alias entities,
edge linking (HAS_ACCOUNT, LINKED_TO, OWNS, REGISTERED_ON), and 100% graceful degradation.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from http_mock import MockRouter, patch_network
from specter.collectors.identity import (
    EmailInvestigator,
    HoleheHunter,
    IdentityCollector,
    MaigretHunter,
    UsernameInvestigator,
    is_holehe_available,
    is_maigret_available,
)
from specter.osint_core.models import EntityType, RelationType


@pytest.fixture(autouse=True)
def mock_all_network(monkeypatch):
    router = (
        MockRouter()
        .add("GET", r"api\.github\.com/users/", json={"login": "alice"})
        .add("GET", r"gitlab\.com/", text="not found", status_code=404)
        .add("GET", r"hacker-news\.firebaseio\.com/", json={"id": "alice"})
        .add("GET", r"hub\.docker\.com/", json={"username": "alice"})
        .add("GET", r"keybase\.io/", json={"them": [None]})
        .add("GET", r"t\.me/", text="<div class='tgme_page_action'>View in Telegram</div>")
        .add("GET", r"reddit\.com/", json={"data": {"is_suspended": False}})
        .add("HEAD", r"gravatar\.com/avatar/", text="", status_code=200)
    )
    zone = {"example.com/mx": ["mail.example.com"], "target.com/mx": ["mail.target.com"]}
    patch_network(monkeypatch, router, zone)


# ---------------------------------------------------------------------------
# Availability Checks
# ---------------------------------------------------------------------------
def test_maigret_and_holehe_availability_detection():
    # In the current test environment, both are installed
    assert is_maigret_available() is True
    assert is_holehe_available() is True


def test_maigret_availability_fallback_on_import_error(monkeypatch):
    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "_ensure_maigret_compat", lambda: None)

    with patch.dict("sys.modules", {"maigret": None}):
        assert id_mod.is_maigret_available() is False


def test_holehe_availability_fallback_on_import_error():
    import specter.collectors.identity as id_mod

    with patch.dict("sys.modules", {"holehe": None}):
        assert id_mod.is_holehe_available() is False


# ---------------------------------------------------------------------------
# MaigretHunter Tests
# ---------------------------------------------------------------------------
class DummyStatus:
    def __init__(self, name="CLAIMED", ids_data=None, ids_usernames=None):
        self.name = name
        self.status = name
        self.ids_data = ids_data or {}
        self.ids_usernames = ids_usernames or {}

    def __str__(self):
        return self.name


async def test_maigret_hunter_parses_profiles_bio_avatar_person_and_edges(monkeypatch):
    """
    Verifies that MaigretHunter properly parses found profiles and extracts:
    - SOCIAL_PROFILE entities with HAS_ACCOUNT edges
    - PERSON entity with OWNS edge from profile and LINKED_TO from alias
    - EMAIL entity with LINKED_TO edge
    - Linked ALIAS entity with LINKED_TO edge
    """
    mock_results = {
        "GitHub": {
            "url_main": "https://github.com",
            "url_user": "https://github.com/alice",
            "status": DummyStatus(
                "CLAIMED",
                ids_data={
                    "bio": "Open Source Intelligence Researcher & Software Engineer",
                    "avatar": "https://avatars.githubusercontent.com/u/12345",
                    "fullname": "Alice Wonderland",
                    "email": "alice@wonderland.sec",
                },
                ids_usernames={"alice_coder": "twitter"},
            ),
            "rank": 50,
            "category": "Code/Tech",
        },
        "Reddit": {
            "url_main": "https://reddit.com",
            "url_user": "https://reddit.com/user/alice",
            "status": DummyStatus("CLAIMED", ids_data={"bio": "OSINT fan"}),
            "rank": 20,
            "category": "Social Media",
        },
        "UnclaimedSite": {
            "url_main": "https://unknown.org",
            "url_user": "https://unknown.org/user/alice",
            "status": DummyStatus("AVAILABLE"),
            "rank": 1000,
        },
    }

    mock_run = AsyncMock(return_value=mock_results)
    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "_get_run_maigret", lambda: mock_run)

    hunter = MaigretHunter(timeout=10.0, top_sites_limit=50)
    result = await hunter.collect("alice")

    assert result.collector_name == "maigret_hunter"
    assert result.source_target == "alice"
    assert result.metadata["matches_found"] == 2
    assert result.metadata["timeout"] is False

    # Entities check
    entities_by_type: dict[EntityType, list] = {}
    for e in result.entities:
        entities_by_type.setdefault(e.type, []).append(e)

    assert EntityType.ALIAS in entities_by_type
    alias_vals = {e.value for e in entities_by_type[EntityType.ALIAS]}
    assert "alice" in alias_vals
    assert "alice_coder" in alias_vals

    assert EntityType.SOCIAL_PROFILE in entities_by_type
    prof_urls = {e.value for e in entities_by_type[EntityType.SOCIAL_PROFILE]}
    assert "https://github.com/alice" in prof_urls
    assert "https://reddit.com/user/alice" in prof_urls

    gh_node = next(
        e for e in entities_by_type[EntityType.SOCIAL_PROFILE] if "github.com" in e.value
    )
    assert gh_node.attributes["platform"] == "GitHub"
    assert gh_node.attributes["bio"] == "Open Source Intelligence Researcher & Software Engineer"
    assert gh_node.attributes["avatar_url"] == "https://avatars.githubusercontent.com/u/12345"

    assert EntityType.PERSON in entities_by_type
    person_node = entities_by_type[EntityType.PERSON][0]
    assert person_node.value == "Alice Wonderland"
    assert person_node.attributes["discovered_on"] == "GitHub"

    assert EntityType.EMAIL in entities_by_type
    email_node = entities_by_type[EntityType.EMAIL][0]
    assert email_node.value == "alice@wonderland.sec"

    # Relations check
    relations_by_type: dict[RelationType, list] = {}
    for r in result.relations:
        relations_by_type.setdefault(r.relation_type, []).append(r)

    assert RelationType.HAS_ACCOUNT in relations_by_type
    has_account_edges = relations_by_type[RelationType.HAS_ACCOUNT]
    assert len(has_account_edges) == 2
    assert {e.source_id for e in has_account_edges} == {"alias:alice"}

    assert RelationType.OWNS in relations_by_type
    owns_edge = relations_by_type[RelationType.OWNS][0]
    assert owns_edge.source_id == gh_node.id
    assert owns_edge.target_id == person_node.id

    assert RelationType.LINKED_TO in relations_by_type
    linked_edges = relations_by_type[RelationType.LINKED_TO]
    target_ids = {r.target_id for r in linked_edges}
    assert person_node.id in target_ids
    assert email_node.id in target_ids
    linked_alias_node = next(e for e in result.entities if e.value == "alice_coder")
    assert linked_alias_node.id in target_ids


async def test_maigret_hunter_site_list_filtering(monkeypatch):
    passed_site_data = {}

    async def mock_run(username, site_data, **kwargs):
        nonlocal passed_site_data
        passed_site_data = dict(site_data)
        return {}

    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "_get_run_maigret", lambda: mock_run)
    monkeypatch.setattr(
        id_mod,
        "_load_maigret_sites",
        lambda: {
            "SiteA": {"url": "https://a.test/{username}", "rank": 10},
            "SiteB": {"url": "https://b.test/{username}", "rank": 20},
            "SiteC": {"url": "https://c.test/{username}", "rank": 30},
        },
    )

    hunter = MaigretHunter(site_list=["SiteA", "SiteC"])
    await hunter.collect("bob")
    assert set(passed_site_data.keys()) == {"SiteA", "SiteC"}


async def test_maigret_hunter_top_sites_limit(monkeypatch):
    passed_site_data = {}

    async def mock_run(username, site_data, **kwargs):
        nonlocal passed_site_data
        passed_site_data = dict(site_data)
        return {}

    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "_get_run_maigret", lambda: mock_run)
    monkeypatch.setattr(
        id_mod,
        "_load_maigret_sites",
        lambda: {
            "Site1": {"url": "https://1.test/{username}", "rank": 100},
            "Site2": {"url": "https://2.test/{username}", "rank": 10},
            "Site3": {"url": "https://3.test/{username}", "rank": 50},
        },
    )

    hunter = MaigretHunter(top_sites_limit=2)
    await hunter.collect("charlie")
    assert set(passed_site_data.keys()) == {"Site2", "Site3"}


async def test_maigret_hunter_graceful_degradation_on_exception(monkeypatch):
    """If Maigret throws an exception, it falls back cleanly to UsernameInvestigator."""

    async def faulty_run(*args, **kwargs):
        raise ConnectionResetError("Remote host terminated connection unexpectedly")

    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "_get_run_maigret", lambda: faulty_run)

    hunter = MaigretHunter()
    result = await hunter.collect("alice")

    assert result.metadata.get("maigret_fallback") is True
    assert "Remote host terminated" in result.metadata.get("maigret_error", "")
    assert any(e.type == EntityType.ALIAS for e in result.entities)


async def test_maigret_hunter_graceful_degradation_on_timeout(monkeypatch):
    """If Maigret times out with 0 matches, it falls back to UsernameInvestigator."""

    async def slow_run(*args, **kwargs):
        raise TimeoutError()

    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "_get_run_maigret", lambda: slow_run)

    hunter = MaigretHunter(timeout=0.1)
    result = await hunter.collect("alice")

    assert result.metadata.get("maigret_timeout") is True
    assert result.metadata.get("maigret_fallback") is True
    assert any(e.type == EntityType.ALIAS for e in result.entities)


async def test_maigret_hunter_when_not_available(monkeypatch):
    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "is_maigret_available", lambda: False)

    hunter = MaigretHunter()
    result = await hunter.collect("alice")

    assert result.metadata.get("maigret_fallback") is True
    assert any(e.type == EntityType.ALIAS for e in result.entities)


async def test_maigret_hunter_empty_target():
    hunter = MaigretHunter()
    result = await hunter.collect("   ")
    assert result.metadata["valid"] is False


# ---------------------------------------------------------------------------
# HoleheHunter Tests
# ---------------------------------------------------------------------------
async def test_holehe_hunter_parses_registered_services_and_edges(monkeypatch):
    """
    Verifies that HoleheHunter yields:
    - EntityNode of type EMAIL
    - EntityNode of type SOCIAL_PROFILE for registered services
    - RelationEdge of type REGISTERED_ON connecting EMAIL to SOCIAL_PROFILE
    """
    mock_holehe_out = [
        {
            "name": "twitter",
            "domain": "twitter.com",
            "method": "register",
            "rateLimit": False,
            "exists": True,
            "emailrecovery": "a***@gmail.com",
            "phoneNumber": "******89",
            "others": None,
        },
        {
            "name": "instagram",
            "domain": "instagram.com",
            "method": "register",
            "rateLimit": False,
            "exists": True,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        },
        {
            "name": "github",
            "domain": "github.com",
            "method": "register",
            "rateLimit": False,
            "exists": True,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        },
        {
            "name": "spotify",
            "domain": "spotify.com",
            "method": "login",
            "rateLimit": False,
            "exists": False,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        },
    ]

    import specter.collectors.identity as id_mod

    monkeypatch.setattr(
        id_mod.HoleheHunter,
        "_run_holehe_checks",
        AsyncMock(return_value=mock_holehe_out),
    )

    hunter = HoleheHunter(timeout=5.0)
    result = await hunter.collect("alice@example.com")

    assert result.collector_name == "holehe_hunter"
    assert result.source_target == "alice@example.com"
    assert result.metadata["services_checked"] == 4
    assert result.metadata["matches_found"] == 3
    assert result.metadata["rate_limited_count"] == 0

    # Entity verification
    emails = [e for e in result.entities if e.type == EntityType.EMAIL]
    assert len(emails) == 1
    assert emails[0].value == "alice@example.com"

    profiles = [e for e in result.entities if e.type == EntityType.SOCIAL_PROFILE]
    assert len(profiles) == 3
    plat_names = {p.attributes["platform"] for p in profiles}
    assert plat_names == {"twitter", "instagram", "github"}

    tw_prof = next(p for p in profiles if p.attributes["platform"] == "twitter")
    assert tw_prof.attributes["recovery_email"] == "a***@gmail.com"
    assert tw_prof.attributes["phone_hint"] == "******89"

    # Relation verification
    reg_edges = [r for r in result.relations if r.relation_type == RelationType.REGISTERED_ON]
    assert len(reg_edges) == 3
    assert all(r.source_id == emails[0].id for r in reg_edges)
    assert {r.target_id for r in reg_edges} == {p.id for p in profiles}


async def test_holehe_hunter_rate_limiting_and_errors(monkeypatch):
    """Verifies that rate limits and errors are counted without throwing exceptions."""
    mock_holehe_out = [
        {
            "name": "rate_limited_site",
            "domain": "rate.test",
            "rateLimit": True,
            "exists": False,
            "error": "HTTP 429 Too Many Requests",
        },
        {
            "name": "error_site",
            "domain": "error.test",
            "rateLimit": True,
            "exists": False,
            "error": "Connection timeout",
        },
        {
            "name": "ok_site",
            "domain": "ok.test",
            "rateLimit": False,
            "exists": True,
        },
    ]

    import specter.collectors.identity as id_mod

    monkeypatch.setattr(
        id_mod.HoleheHunter,
        "_run_holehe_checks",
        AsyncMock(return_value=mock_holehe_out),
    )

    hunter = HoleheHunter()
    result = await hunter.collect("bob@example.com")

    assert result.metadata["matches_found"] == 1
    assert result.metadata["rate_limited_count"] == 2
    assert result.metadata["services_checked"] == 3


async def test_holehe_hunter_graceful_degradation_on_timeout(monkeypatch):
    """If Holehe times out, it falls back to EmailInvestigator."""
    import specter.collectors.identity as id_mod

    monkeypatch.setattr(
        id_mod.HoleheHunter,
        "_run_holehe_checks",
        AsyncMock(side_effect=TimeoutError()),
    )

    hunter = HoleheHunter(timeout=0.1)
    result = await hunter.collect("bob@example.com")

    assert result.metadata.get("holehe_timeout") is True
    assert result.metadata.get("holehe_fallback") is True
    assert any(e.type == EntityType.EMAIL for e in result.entities)


async def test_holehe_hunter_graceful_degradation_on_exception(monkeypatch):
    """If Holehe raises unexpected exception, it falls back cleanly."""
    import specter.collectors.identity as id_mod

    monkeypatch.setattr(
        id_mod.HoleheHunter,
        "_run_holehe_checks",
        AsyncMock(side_effect=RuntimeError("Subprocess failed")),
    )

    hunter = HoleheHunter()
    result = await hunter.collect("bob@example.com")

    assert result.metadata.get("holehe_fallback") is True
    assert "Subprocess failed" in result.metadata.get("holehe_error", "")


async def test_holehe_hunter_missing_library(monkeypatch):
    import specter.collectors.identity as id_mod

    monkeypatch.setattr(id_mod, "is_holehe_available", lambda: False)

    hunter = HoleheHunter()
    result = await hunter.collect("bob@example.com")

    assert result.metadata.get("holehe_fallback") is True


async def test_holehe_hunter_invalid_email_syntax():
    hunter = HoleheHunter()
    result = await hunter.collect("not-an-email")
    assert result.metadata["valid"] is False
    assert len(result.entities) == 0


# ---------------------------------------------------------------------------
# IdentityCollector Tests (Unified Orchestrator)
# ---------------------------------------------------------------------------
async def test_identity_collector_dispatches_username_target(monkeypatch):
    """Target without '@' routes to username investigation (Built-in + Maigret)."""
    import specter.collectors.identity as id_mod

    mock_maigret_results = {
        "Twitch": {
            "url_user": "https://twitch.tv/targetuser",
            "status": DummyStatus("CLAIMED"),
            "rank": 30,
        }
    }
    monkeypatch.setattr(
        id_mod,
        "_get_run_maigret",
        lambda: AsyncMock(return_value=mock_maigret_results),
    )

    collector = IdentityCollector()
    result = await collector.collect("targetuser")

    assert result.collector_name == "identity_collector"
    assert result.source_target == "targetuser"
    assert result.metadata["maigret_enabled"] is True

    # Has alias
    assert any(e.type == EntityType.ALIAS and e.value == "targetuser" for e in result.entities)
    # Has Twitch profile from Maigret
    assert any("twitch.tv/targetuser" in e.value for e in result.entities)


# ---------------------------------------------------------------------------
# Integration with Existing Collectors (use_maigret / use_holehe)
# ---------------------------------------------------------------------------
async def test_username_investigator_with_use_maigret_flag(monkeypatch):
    import specter.collectors.identity as id_mod

    mock_maigret_results = {
        "Spotify": {
            "url_user": "https://open.spotify.com/user/alice",
            "status": DummyStatus("CLAIMED"),
            "rank": 40,
        }
    }
    monkeypatch.setattr(
        id_mod,
        "_get_run_maigret",
        lambda: AsyncMock(return_value=mock_maigret_results),
    )

    collector = UsernameInvestigator()
    result = await collector.collect("alice", use_maigret=True)

    assert "maigret" in result.metadata
    assert any("spotify.com/user/alice" in e.value for e in result.entities)
    assert any(r.relation_type == RelationType.HAS_ACCOUNT for r in result.relations)


async def test_email_investigator_with_use_holehe_flag(monkeypatch):
    import specter.collectors.identity as id_mod

    mock_holehe_out = [
        {
            "name": "chess",
            "domain": "chess.com",
            "method": "register",
            "rateLimit": False,
            "exists": True,
            "emailrecovery": None,
            "phoneNumber": None,
            "others": None,
        }
    ]
    monkeypatch.setattr(
        id_mod.HoleheHunter,
        "_run_holehe_checks",
        AsyncMock(return_value=mock_holehe_out),
    )

    collector = EmailInvestigator()
    result = await collector.collect("alice@target.com", use_holehe=True)

    assert "holehe" in result.metadata
    assert any("chess.com" in e.value for e in result.entities)
    assert any(r.relation_type == RelationType.REGISTERED_ON for r in result.relations)

"""
Tests de los colectores de social media (Twitter, Flickr, SlideShare,
MySpace, Venmo, Keybase). Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.social_media import (
    FlickrCollector,
    KeybaseCollector,
    MySpaceCollector,
    SlideShareCollector,
    TwitterCollector,
    VenmoCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        # --- Twitter (nitter) ---
        .add(
            "GET",
            r"nitter\.net/testuser",
            text="""
            <html><body>
            <a class="fullname" href="/testuser">Test User</a>
            <div class="bio">Test bio</div>
            <div class="location">Test Location</div>
            <span class="followers"><strong>100</strong></span>
            </body></html>
            """,
        )
        # --- Flickr ---
        .add(
            "GET",
            r"flickr\.com/search",
            text="""
            <html><body>
            <a href="https://www.flickr.com/photos/testuser1">Photo 1</a>
            <a href="https://www.flickr.com/photos/testuser2">Photo 2</a>
            </body></html>
            """,
        )
        # --- SlideShare ---
        .add(
            "GET",
            r"slideshare\.net/testuser",
            text="""
            <html><body>
            <meta property="slideshare:name" content="Test User" />
            <meta property="slideshare:location" content="Test Location" />
            </body></html>
            """,
        )
        # --- MySpace ---
        .add(
            "GET",
            r"myspace\.com/testuser",
            text="""
            <html><body>
            <h1>Test User</h1>
            <div class="location_123" data-display-text="Test Location"></div>
            </body></html>
            """,
        )
        # --- Venmo ---
        .add(
            "GET",
            r"api\.venmo\.com/v1/users/testuser",
            json={
                "data": {
                    "display_name": "Test User",
                    "first_name": "Test",
                    "last_name": "User",
                }
            },
        )
        # --- Keybase ---
        .add(
            "GET",
            r"keybase\.io/_/api/1\.0/user/lookup\.json",
            json={
                "status": {"code": 0},
                "them": [
                    {
                        "basics": {"username": "testuser"},
                        "profile": {
                            "full_name": "Test User",
                            "location": "Test Location",
                        },
                        "proofs_summary": {
                            "all": [
                                {
                                    "proof_type": "twitter",
                                    "service_url": "https://twitter.com/testuser",
                                }
                            ]
                        },
                    }
                ],
            },
        )
    )


# --- TwitterCollector ---


async def test_twitter_extrae_perfil(monkeypatch) -> None:
    """TwitterCollector extrae información del perfil de Twitter."""
    patch_httpx(monkeypatch, _router())
    collector = TwitterCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is True
    assert result.metadata["platform"] == "Twitter"
    assert result.metadata["username"] == "testuser"
    assert result.metadata["full_name"] == "Test User"
    assert result.metadata["followers"] == 100
    assert len(result.entities) > 0


async def test_twitter_maneja_error_de_red(monkeypatch) -> None:
    """TwitterCollector maneja errores de red gracefully."""
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    collector = TwitterCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is False
    assert result.entities == []


# --- FlickrCollector ---


async def test_flickr_extrae_perfiles(monkeypatch) -> None:
    """FlickrCollector extrae perfiles de Flickr."""
    patch_httpx(monkeypatch, _router())
    collector = FlickrCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is True
    assert result.metadata["platform"] == "Flickr"
    assert result.metadata["profiles_found"] == 2
    assert len(result.entities) > 0


async def test_flickr_maneja_error_de_red(monkeypatch) -> None:
    """FlickrCollector maneja errores de red gracefully."""
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    collector = FlickrCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is False
    assert result.entities == []


# --- SlideShareCollector ---


async def test_slideshare_extrae_perfil(monkeypatch) -> None:
    """SlideShareCollector extrae información del perfil de SlideShare."""
    patch_httpx(monkeypatch, _router())
    collector = SlideShareCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is True
    assert result.metadata["platform"] == "SlideShare"
    assert result.metadata["username"] == "testuser"
    assert result.metadata["full_name"] == "Test User"
    assert len(result.entities) > 0


async def test_slideshare_maneja_error_de_red(monkeypatch) -> None:
    """SlideShareCollector maneja errores de red gracefully."""
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    collector = SlideShareCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is False
    assert result.entities == []


# --- MySpaceCollector ---


async def test_myspace_extrae_perfil(monkeypatch) -> None:
    """MySpaceCollector extrae información del perfil de MySpace."""
    patch_httpx(monkeypatch, _router())
    collector = MySpaceCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is True
    assert result.metadata["platform"] == "MySpace"
    assert result.metadata["username"] == "testuser"
    assert result.metadata["full_name"] == "Test User"
    assert len(result.entities) > 0


async def test_myspace_maneja_error_de_red(monkeypatch) -> None:
    """MySpaceCollector maneja errores de red gracefully."""
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    collector = MySpaceCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is False
    assert result.entities == []


# --- VenmoCollector ---


async def test_venmo_extrae_perfil(monkeypatch) -> None:
    """VenmoCollector extrae información del perfil de Venmo."""
    patch_httpx(monkeypatch, _router())
    collector = VenmoCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is True
    assert result.metadata["platform"] == "Venmo"
    assert result.metadata["username"] == "testuser"
    assert result.metadata["display_name"] == "Test User"
    assert len(result.entities) > 0


async def test_venmo_maneja_error_de_red(monkeypatch) -> None:
    """VenmoCollector maneja errores de red gracefully."""
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    collector = VenmoCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is False
    assert result.entities == []


# --- KeybaseCollector ---


async def test_keybase_extrae_perfil(monkeypatch) -> None:
    """KeybaseCollector extrae información del perfil de Keybase."""
    patch_httpx(monkeypatch, _router())
    collector = KeybaseCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is True
    assert result.metadata["platform"] == "Keybase"
    assert result.metadata["username"] == "testuser"
    assert result.metadata["full_name"] == "Test User"
    assert result.metadata["social_profiles"] == 1
    assert len(result.entities) > 0


async def test_keybase_maneja_error_de_red(monkeypatch) -> None:
    """KeybaseCollector maneja errores de red gracefully."""
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    collector = KeybaseCollector()
    result = await collector.collect("testuser")
    assert result.metadata["ok"] is False
    assert result.entities == []

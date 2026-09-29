"""
Tests del colector SubdomainTakeover.
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.subdomain_takeover import SubdomainTakeoverCollector

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        # AWS S3 - vulnerable (bucket no existe)
        .add(
            "GET",
            r"test\.s3\.amazonaws\.com",
            text=(
                "<Error><Code>NoSuchBucket</Code>"
                "<Message>The specified bucket does not exist</Message></Error>"
            ),
            status_code=404,
        )
        # GitHub Pages - no vulnerable (sitio existe)
        .add(
            "GET",
            r"user\.github\.io",
            text="<html><body>GitHub Pages site</body></html>",
            status_code=200,
        )
        # Heroku - vulnerable (app no existe)
        .add(
            "GET",
            r"app\.herokuapp\.com",
            text="<html><body>No such app</body></html>",
            status_code=404,
        )
        # Netlify - vulnerable
        .add(
            "GET",
            r"test\.netlify\.app",
            text="<html><body>Not Found - The site you're looking for is not here</body></html>",
            status_code=404,
        )
    )


async def test_subdomain_takeover_detecta_vulnerables(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await SubdomainTakeoverCollector().collect(
        "test.s3.amazonaws.com, user.github.io, app.herokuapp.com, test.netlify.app"
    )
    assert result.metadata["ok"] is True
    assert result.metadata["vulnerable"] == 3
    values = [e.value for e in result.entities]
    assert "test.s3.amazonaws.com" in values
    assert "app.herokuapp.com" in values
    assert "test.netlify.app" in values
    # GitHub Pages no es vulnerable
    assert "user.github.io" not in values


async def test_subdomain_takeover_sin_vulnerables(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r".*",
        text="<html><body>OK</body></html>",
        status_code=200,
    )
    patch_httpx(monkeypatch, router)
    result = await SubdomainTakeoverCollector().collect("user.github.io")
    assert result.metadata["ok"] is True
    assert result.metadata["vulnerable"] == 0


async def test_subdomain_takeover_lista_vacia(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await SubdomainTakeoverCollector().collect("")
    assert result.metadata["ok"] is True
    assert result.metadata["checked"] == 0


async def test_subdomain_takeover_servicio_desconocido(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await SubdomainTakeoverCollector().collect("test.example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["checked"] == 0


async def test_subdomain_takeover_sobrevive_a_error_de_red(monkeypatch) -> None:
    patch_httpx(monkeypatch, MockRouter())  # todo 599
    result = await SubdomainTakeoverCollector().collect("test.s3.amazonaws.com")
    assert result.metadata["ok"] is True
    assert result.metadata["vulnerable"] == 0


async def test_subdomain_takeover_genera_subdominios_comunes(monkeypatch) -> None:
    router = MockRouter().add(
        "GET",
        r".*",
        text="<html><body>OK</body></html>",
        status_code=200,
    )
    patch_httpx(monkeypatch, router)
    result = await SubdomainTakeoverCollector().collect("example.com")
    assert result.metadata["ok"] is True
    # Los subdominios generados no coinciden con servicios conocidos
    assert result.metadata["checked"] == 0

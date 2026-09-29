"""
Tests de los colectores de Cloud Buckets (S3, Azure, GCS, DigitalOcean, Grayhat).
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.cloud_buckets import (
    AzureBlobFinderCollector,
    DigitalOceanSpaceFinderCollector,
    GoogleCloudStorageFinderCollector,
    GrayhatWarfareCollector,
    S3BucketFinderCollector,
)

pytestmark = pytest.mark.asyncio


def _router() -> MockRouter:
    return (
        MockRouter()
        # S3: bucket listable
        .add(
            "GET",
            r"ejemplo\.test\.s3\.amazonaws\.com",
            text=(
                '<?xml version="1.0"?>'
                "<ListBucketResult><Contents><Key>file1.txt</Key></Contents></ListBucketResult>"
            ),
        )
        # S3: bucket no listable (403)
        .add(
            "GET",
            r"private\.test\.s3\.amazonaws\.com",
            status_code=403,
            text="AccessDenied",
        )
        # Azure: contenedor listable
        .add(
            "GET",
            r"ejemplo\.test\.blob\.core\.windows\.net",
            text=(
                '<?xml version="1.0"?>'
                "<EnumerationResults><Blob><Name>blob1</Name></Blob></EnumerationResults>"
            ),
        )
        # DigitalOcean: space listable
        .add(
            "GET",
            r"ejemplo\.test\.nyc3\.digitaloceanspaces\.com",
            text=(
                '<?xml version="1.0"?>'
                "<ListBucketResult><Contents><Key>file1.txt</Key></Contents></ListBucketResult>"
            ),
        )
        # GCS: bucket listable
        .add(
            "GET",
            r"storage\.googleapis\.com/ejemplo\.test",
            text=(
                '<?xml version="1.0"?>'
                "<ListBucketResult><Contents><Key>file1.txt</Key></Contents></ListBucketResult>"
            ),
        )
        # Grayhat Warfare: API con buckets
        .add(
            "GET",
            r"buckets\.grayhatwarfare\.com/api/v1/buckets/ejemplo\.test",
            json=[
                {"bucket": "ejemplo-test", "url": "https://ejemplo-test.s3.amazonaws.com"},
                {"bucket": "ejemplo-backups", "url": "https://ejemplo-backups.s3.amazonaws.com"},
            ],
        )
    )


async def test_s3bucket_encuentra_bucket_listable(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await S3BucketFinderCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["buckets_found"] >= 1
    # Verificar que encontró el bucket listable
    bucket_names = [e.value for e in result.entities]
    assert "ejemplo.test" in bucket_names


async def test_s3bucket_bucket_privado_no_listable(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await S3BucketFinderCollector().collect("private.test")
    assert result.metadata["ok"] is True
    # El bucket existe (403) pero no es listable
    assert result.metadata["buckets_found"] >= 1


async def test_azureblob_encuentra_contenedor(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await AzureBlobFinderCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["buckets_found"] >= 1


async def test_digitalocean_space_encuentra_space(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await DigitalOceanSpaceFinderCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["buckets_found"] >= 1


async def test_gcs_encuentra_bucket(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await GoogleCloudStorageFinderCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["buckets_found"] >= 1


async def test_grayhat_warfare_encuentra_buckets(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await GrayhatWarfareCollector().collect("ejemplo.test")
    assert result.metadata["ok"] is True
    assert result.metadata["buckets_found"] == 2
    bucket_names = [e.value for e in result.entities]
    assert "ejemplo-test" in bucket_names
    assert "ejemplo-backups" in bucket_names


async def test_s3bucket_maneja_error_red(monkeypatch) -> None:
    """Verifica que un error de red no rompe el colector."""
    router = MockRouter()  # Sin rutas = 599
    patch_httpx(monkeypatch, router)
    result = await S3BucketFinderCollector().collect("error.test")
    # El colector maneja errores gracefully: no lanza excepción
    # y retorna un resultado válido (ok=True con 0 buckets encontrados)
    assert result.metadata["ok"] is True
    assert result.metadata["buckets_found"] == 0


async def test_grayhat_warfare_maneja_error_red(monkeypatch) -> None:
    """Verifica que un error de red no rompe el colector."""
    router = MockRouter()  # Sin rutas = 599
    patch_httpx(monkeypatch, router)
    result = await GrayhatWarfareCollector().collect("error.test")
    assert result.metadata["ok"] is False

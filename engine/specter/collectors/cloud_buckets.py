"""
WraithOSINT - Cloud Bucket Enumeration Collectors
Colectores para descubrir buckets de almacenamiento cloud asociados a un dominio.

Fuentes gratuitas sin API key:
- S3BucketFinderCollector: AWS S3 (verifica existencia y listabilidad)
- AzureBlobFinderCollector: Azure Blob Storage
- DigitalOceanSpaceFinderCollector: DigitalOcean Spaces
- GoogleCloudStorageFinderCollector: Google Cloud Storage
- GrayhatWarfareCollector: API de Grayhat Warfare (buckets cloud asociados)
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

import httpx
from specter.collectors.base import BaseCollector
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
)

logger = logging.getLogger("specter.collectors.cloud_buckets")

_TIMEOUT = 12.0
_UA = {"User-Agent": "WraithOSINT/0.3 (+cloud-bucket-enumeration)"}


def _collector_key(vault_name: str) -> str | None:
    """Key de la bóveda local o su env equivalente. None = no configurada."""
    import os

    from specter import secrets as vault

    env_var = vault.ALLOWED_SECRETS.get(vault_name, "")
    return os.environ.get(env_var) or vault.get_secret(vault_name) or None


def _missing_key_result(name: str, target: str, vault_name: str) -> CollectorResult:
    return CollectorResult(
        collector_name=name,
        source_target=target,
        raw_payload=json.dumps({"target": target, "skipped": f"requiere {vault_name}"}),
        metadata={"ok": False, "requires_key": vault_name},
    )


def _is_listable_s3(body: str) -> bool:
    """Detecta si un bucket S3 es listable (contiene ListBucketResult)."""
    return "ListBucketResult" in body or "<Contents>" in body


def _is_listable_azure(body: str) -> bool:
    """Detecta si un contenedor Azure es listable."""
    return "EnumerationResults" in body or "<Blob>" in body


def _is_listable_gcs(body: str) -> bool:
    """Detecta si un bucket GCS es listable."""
    return "<ListBucketResult>" in body or "<Contents>" in body


def _is_listable_do(body: str) -> bool:
    """Detecta si un space de DigitalOcean es listable."""
    return "ListBucketResult" in body or "<Contents>" in body


class S3BucketFinderCollector(BaseCollector):
    """AWS S3: busca buckets asociados al dominio y verifica si son listables."""

    def __init__(self) -> None:
        super().__init__(name="s3bucket")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        urls_to_try = [
            f"https://{domain}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{domain}",
        ]

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found_buckets: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                for url in urls_to_try:
                    try:
                        resp = await client.get(url, headers=_UA)
                        if resp.status_code == 200:
                            is_listable = _is_listable_s3(resp.text)
                            bucket_name = domain
                            bucket_node = EntityNode.create(
                                EntityType.ALIAS,
                                bucket_name,
                                f"S3 Bucket: {bucket_name}",
                                attributes={
                                    "url": url,
                                    "accessible": True,
                                    "listable": is_listable,
                                    "source": "s3bucket",
                                },
                                confidence=0.9 if is_listable else 0.7,
                            )
                            entities.append(bucket_node)
                            found_buckets.append(
                                {
                                    "name": bucket_name,
                                    "url": url,
                                    "accessible": True,
                                    "listable": is_listable,
                                }
                            )
                        elif resp.status_code == 403:
                            # El bucket existe pero no es listable
                            bucket_node = EntityNode.create(
                                EntityType.ALIAS,
                                domain,
                                f"S3 Bucket: {domain}",
                                attributes={
                                    "url": url,
                                    "accessible": True,
                                    "listable": False,
                                    "source": "s3bucket",
                                },
                                confidence=0.6,
                            )
                            entities.append(bucket_node)
                            found_buckets.append(
                                {
                                    "name": domain,
                                    "url": url,
                                    "accessible": True,
                                    "listable": False,
                                }
                            )
                        # 404 = no existe, continuar
                    except Exception as exc:
                        logger.debug("S3 check falló para %s: %s", url, exc)
                        continue
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "buckets": found_buckets}),
            metadata={"ok": True, "buckets_found": len(found_buckets)},
        )


class AzureBlobFinderCollector(BaseCollector):
    """Azure Blob: busca contenedores asociados al dominio."""

    def __init__(self) -> None:
        super().__init__(name="azureblob")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://{domain}.blob.core.windows.net"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found_buckets: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                try:
                    resp = await client.get(url, headers=_UA)
                    if resp.status_code == 200:
                        is_listable = _is_listable_azure(resp.text)
                        container_node = EntityNode.create(
                            EntityType.ALIAS,
                            domain,
                            f"Azure Container: {domain}",
                            attributes={
                                "url": url,
                                "accessible": True,
                                "listable": is_listable,
                                "source": "azureblob",
                            },
                            confidence=0.9 if is_listable else 0.7,
                        )
                        entities.append(container_node)
                        found_buckets.append(
                            {
                                "name": domain,
                                "url": url,
                                "accessible": True,
                                "listable": is_listable,
                            }
                        )
                    elif resp.status_code == 403:
                        container_node = EntityNode.create(
                            EntityType.ALIAS,
                            domain,
                            f"Azure Container: {domain}",
                            attributes={
                                "url": url,
                                "accessible": True,
                                "listable": False,
                                "source": "azureblob",
                            },
                            confidence=0.6,
                        )
                        entities.append(container_node)
                        found_buckets.append(
                            {
                                "name": domain,
                                "url": url,
                                "accessible": True,
                                "listable": False,
                            }
                        )
                except Exception as exc:
                    logger.debug("Azure check falló para %s: %s", url, exc)
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "buckets": found_buckets}),
            metadata={"ok": True, "buckets_found": len(found_buckets)},
        )


class DigitalOceanSpaceFinderCollector(BaseCollector):
    """DigitalOcean Spaces: busca spaces asociados al dominio."""

    def __init__(self) -> None:
        super().__init__(name="digitalocean_space")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        # Probar múltiples regiones de DO
        regions = ["nyc3", "ams3", "sgp1", "fra1"]
        urls_to_try = [f"https://{domain}.{region}.digitaloceanspaces.com" for region in regions]

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found_buckets: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                for url in urls_to_try:
                    try:
                        resp = await client.get(url, headers=_UA)
                        if resp.status_code == 200:
                            is_listable = _is_listable_do(resp.text)
                            space_node = EntityNode.create(
                                EntityType.ALIAS,
                                domain,
                                f"DO Space: {domain}",
                                attributes={
                                    "url": url,
                                    "accessible": True,
                                    "listable": is_listable,
                                    "source": "digitalocean_space",
                                },
                                confidence=0.9 if is_listable else 0.7,
                            )
                            entities.append(space_node)
                            found_buckets.append(
                                {
                                    "name": domain,
                                    "url": url,
                                    "accessible": True,
                                    "listable": is_listable,
                                }
                            )
                            break  # Encontrado, no seguir probando regiones
                        elif resp.status_code == 403:
                            space_node = EntityNode.create(
                                EntityType.ALIAS,
                                domain,
                                f"DO Space: {domain}",
                                attributes={
                                    "url": url,
                                    "accessible": True,
                                    "listable": False,
                                    "source": "digitalocean_space",
                                },
                                confidence=0.6,
                            )
                            entities.append(space_node)
                            found_buckets.append(
                                {
                                    "name": domain,
                                    "url": url,
                                    "accessible": True,
                                    "listable": False,
                                }
                            )
                            break
                    except Exception as exc:
                        logger.debug("DO Space check falló para %s: %s", url, exc)
                        continue
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "buckets": found_buckets}),
            metadata={"ok": True, "buckets_found": len(found_buckets)},
        )


class GoogleCloudStorageFinderCollector(BaseCollector):
    """Google Cloud Storage: busca buckets asociados al dominio."""

    def __init__(self) -> None:
        super().__init__(name="gcs")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://storage.googleapis.com/{domain}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found_buckets: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                try:
                    resp = await client.get(url, headers=_UA)
                    if resp.status_code == 200:
                        is_listable = _is_listable_gcs(resp.text)
                        bucket_node = EntityNode.create(
                            EntityType.ALIAS,
                            domain,
                            f"GCS Bucket: {domain}",
                            attributes={
                                "url": url,
                                "accessible": True,
                                "listable": is_listable,
                                "source": "gcs",
                            },
                            confidence=0.9 if is_listable else 0.7,
                        )
                        entities.append(bucket_node)
                        found_buckets.append(
                            {
                                "name": domain,
                                "url": url,
                                "accessible": True,
                                "listable": is_listable,
                            }
                        )
                    elif resp.status_code == 403:
                        bucket_node = EntityNode.create(
                            EntityType.ALIAS,
                            domain,
                            f"GCS Bucket: {domain}",
                            attributes={
                                "url": url,
                                "accessible": True,
                                "listable": False,
                                "source": "gcs",
                            },
                            confidence=0.6,
                        )
                        entities.append(bucket_node)
                        found_buckets.append(
                            {
                                "name": domain,
                                "url": url,
                                "accessible": True,
                                "listable": False,
                            }
                        )
                except Exception as exc:
                    logger.debug("GCS check falló para %s: %s", url, exc)
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "buckets": found_buckets}),
            metadata={"ok": True, "buckets_found": len(found_buckets)},
        )


class GrayhatWarfareCollector(BaseCollector):
    """Grayhat Warfare: API que retorna buckets cloud asociados a un dominio."""

    def __init__(self) -> None:
        super().__init__(name="grayhat_warfare")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        domain = target.strip().lower()
        url = f"https://buckets.grayhatwarfare.com/api/v1/buckets/{quote(domain)}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found_buckets: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        # La API retorna una lista de buckets
        buckets = data if isinstance(data, list) else data.get("buckets", [])
        for bucket in buckets[:20]:
            if isinstance(bucket, dict):
                bucket_name = str(bucket.get("bucket", bucket.get("name", "")))
                bucket_url = str(bucket.get("url", ""))
                if bucket_name:
                    bucket_node = EntityNode.create(
                        EntityType.ALIAS,
                        bucket_name,
                        f"Grayhat Bucket: {bucket_name}",
                        attributes={
                            "url": bucket_url,
                            "accessible": True,
                            "source": "grayhat_warfare",
                        },
                        confidence=0.8,
                    )
                    entities.append(bucket_node)
                    found_buckets.append(
                        {
                            "name": bucket_name,
                            "url": bucket_url,
                            "accessible": True,
                        }
                    )

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"domain": domain, "buckets": found_buckets}),
            metadata={"ok": True, "buckets_found": len(found_buckets)},
        )

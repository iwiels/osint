"""
SpecterOSINT - Forensic Artifacts & Metadata Collector
Extracción forense de hashes (MD5, SHA1, SHA256), metadatos EXIF/GPS de imágenes y metadatos de documentos PDF.
"""

import contextlib
import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any

import httpx
from PIL import ExifTags, Image
from pypdf import PdfReader
from specter import config as specter_config
from specter.collectors.base import BaseCollector
from specter.netguard import check_public_http_url, ssrf_enforce
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)

# C3/A6: tope de descarga y de lectura local (DoS disco/RAM).
ARTIFACT_MAX_BYTES = 25 * 1024 * 1024


def _forbidden_local(path: Path) -> str | None:
    """Secretos propios del engine: nunca analizables como 'evidencia'.

    El gate de permisos ya exige aprobación para esta tool, pero ni aprobado
    tiene sentido sellar la bóveda o la clave HMAC en el ledger.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return "ruta ilegible"
    own = {specter_config.secrets_path().resolve(), specter_config.ledger_key_path().resolve()}
    if resolved in own or resolved.suffix == ".key" or resolved.name == "secrets.json":
        return "secreto propio del engine"
    return None


def _convert_gps_to_decimal(coords: Any, ref: str) -> float | None:
    try:
        degrees = float(coords[0])
        minutes = float(coords[1])
        seconds = float(coords[2])
        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


class FileForensics(BaseCollector):
    def __init__(self):
        super().__init__(name="file_forensics")

    def _extract_hashes(self, data: bytes) -> dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def _extract_image_exif(
        self, file_path: Path
    ) -> tuple[dict[str, Any], tuple[float, float] | None]:
        metadata: dict[str, Any] = {}
        gps_coords: tuple[float, float] | None = None

        try:
            with Image.open(file_path) as img:
                metadata["format"] = img.format
                metadata["dimensions"] = f"{img.width}x{img.height}"
                exif_data = img._getexif()
                if not exif_data:
                    return metadata, None

                gps_raw = {}
                for tag_id, value in exif_data.items():
                    tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag_name == "GPSInfo":
                        for g_tag_id, g_val in value.items():
                            g_tag_name = ExifTags.GPSTAGS.get(g_tag_id, str(g_tag_id))
                            gps_raw[g_tag_name] = g_val
                    elif isinstance(value, (str, int, float)):
                        metadata[tag_name] = str(value)

                # Procesar Coordenadas GPS si existen
                if "GPSLatitude" in gps_raw and "GPSLatitudeRef" in gps_raw:
                    lat = _convert_gps_to_decimal(gps_raw["GPSLatitude"], gps_raw["GPSLatitudeRef"])
                    lon = _convert_gps_to_decimal(
                        gps_raw.get("GPSLongitude"), gps_raw.get("GPSLongitudeRef", "E")
                    )
                    if lat is not None and lon is not None:
                        gps_coords = (lat, lon)
                        metadata["gps"] = {"latitude": lat, "longitude": lon}

        except Exception as e:
            metadata["exif_error"] = str(e)

        return metadata, gps_coords

    def _extract_pdf_metadata(self, file_path: Path) -> tuple[dict[str, Any], str | None]:
        metadata: dict[str, Any] = {}
        author: str | None = None

        try:
            reader = PdfReader(str(file_path))
            info = reader.metadata
            metadata["pages_count"] = len(reader.pages)
            if info:
                for k, v in info.items():
                    clean_key = k.lstrip("/")
                    metadata[clean_key] = str(v)

                if info.author:
                    author = str(info.author).strip()
        except Exception as e:
            metadata["pdf_error"] = str(e)

        return metadata, author

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        file_path = Path(target)
        temp_downloaded = False
        source_url = target

        # Si el target es una URL, descargarlo temporalmente (con cotas A6 + NetGuard C2)
        if target.startswith("http://") or target.startswith("https://"):
            if ssrf_enforce() and (blocked := check_public_http_url(target)):
                raise ValueError(f"Bloqueada por NetGuard: {blocked}")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(target)
                resp.raise_for_status()
                length = resp.headers.get("content-length")
                if length and int(length) > ARTIFACT_MAX_BYTES:
                    raise ValueError(f"Descarga demasiado grande ({length} bytes, máx 25MB)")
                data = resp.content
                if len(data) > ARTIFACT_MAX_BYTES:
                    raise ValueError("Descarga demasiado grande (máx 25MB)")
                import tempfile

                with tempfile.NamedTemporaryFile(delete=False) as tf:
                    tf.write(data)
                    file_path = Path(tf.name)
                    temp_downloaded = True
        else:
            if not file_path.exists():
                raise FileNotFoundError(f"Archivo no encontrado: {target}")
            # C3: ni siquiera aprobado se sellan los secretos propios en el ledger.
            if forbidden := _forbidden_local(file_path):
                raise ValueError(f"Archivo bloqueado ({forbidden}): {target}")
            data = file_path.read_bytes()
            if len(data) > ARTIFACT_MAX_BYTES:
                raise ValueError("Archivo demasiado grande para analizar (máx 25MB)")

        try:
            hashes = self._extract_hashes(data)
            mime_type, _ = mimetypes.guess_type(str(file_path))
            file_size = len(data)

            entities: list[EntityNode] = []
            relations: list[RelationEdge] = []
            raw_report: dict[str, Any] = {
                "source": source_url,
                "hashes": hashes,
                "file_size": file_size,
                "mime_type": mime_type or "application/octet-stream",
            }

            file_node = EntityNode.create(
                type=EntityType.FILE_ARTIFACT,
                value=hashes["sha256"],
                label=f"File: {file_path.name[:20]} ({hashes['sha256'][:8]})",
                attributes={
                    "filename": file_path.name,
                    "hashes": hashes,
                    "size_bytes": file_size,
                    "mime_type": mime_type,
                },
            )
            entities.append(file_node)

            # Extracción según tipo
            if mime_type and (
                "image" in mime_type
                or file_path.suffix.lower() in [".jpg", ".jpeg", ".png", ".tiff"]
            ):
                img_meta, gps_coords = self._extract_image_exif(file_path)
                raw_report["image_metadata"] = img_meta
                file_node.attributes.update(img_meta)

                if gps_coords:
                    lat, lon = gps_coords
                    geo_node = EntityNode.create(
                        type=EntityType.GEO_LOCATION,
                        value=f"{lat},{lon}",
                        label=f"GPS: {lat}, {lon}",
                        attributes={
                            "latitude": lat,
                            "longitude": lon,
                            "google_maps": f"https://www.google.com/maps?q={lat},{lon}",
                        },
                    )
                    entities.append(geo_node)
                    relations.append(
                        RelationEdge(
                            source_id=file_node.id,
                            target_id=geo_node.id,
                            relation_type=RelationType.LOCATED_AT,
                        )
                    )

            elif mime_type == "application/pdf" or file_path.suffix.lower() == ".pdf":
                pdf_meta, author = self._extract_pdf_metadata(file_path)
                raw_report["pdf_metadata"] = pdf_meta
                file_node.attributes.update(pdf_meta)

                if author:
                    person_node = EntityNode.create(
                        type=EntityType.PERSON,
                        value=author,
                        label=f"Author: {author}",
                        attributes={"source": "PDF Metadata"},
                    )
                    entities.append(person_node)
                    relations.append(
                        RelationEdge(
                            source_id=file_node.id,
                            target_id=person_node.id,
                            relation_type=RelationType.CONTAINS_METADATA,
                        )
                    )

            return CollectorResult(
                collector_name=self.name,
                source_target=source_url,
                entities=entities,
                relations=relations,
                raw_payload=json.dumps(raw_report, indent=2),
                metadata={"sha256": hashes["sha256"]},
            )
        finally:
            if temp_downloaded and file_path.exists():
                with contextlib.suppress(Exception):
                    file_path.unlink()

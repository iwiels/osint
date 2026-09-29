"""
SpecterOSINT - Web Analytics (Google Analytics, GTM, Facebook Pixel, etc.).

Inspirado en SpiderFoot: sfp_webanalytics. Adaptado a la arquitectura desktop.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from specter.collectors.base import BaseCollector
from specter.httpx_transport import http_get
from specter.netguard import check_public_http_url, ssrf_enforce
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
)

logger = logging.getLogger("specter.collectors.web_analytics")

_TIMEOUT = 15.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+web analytics)"}

# Patrones de analytics
_GA_UA_RE = re.compile(r"\bUA-\d{4,10}-\d{1,4}\b")
_GA_G_RE = re.compile(r"\bG-[A-Z0-9]{6,12}\b")
_GTM_RE = re.compile(r"\bGTM-[A-Z0-9]{4,8}\b")
_FB_PIXEL_RE = re.compile(r"\b\d{15,16}\b")  # Facebook Pixel ID
_HOTJAR_RE = re.compile(r"\bHJ-[A-Z0-9]{6,10}\b")
_MIXPANEL_RE = re.compile(r"\bmp_[a-z0-9]{20,30}_[a-z0-9]{10,20}\b")
_SEGMENT_RE = re.compile(r"\b[a-z0-9]{32}\b")  # Segment write key
_AMPLITUDE_RE = re.compile(r"\b[a-f0-9]{32}\b")  # Amplitude API key


class WebAnalyticsExtractorCollector(BaseCollector):
    """Extractor de IDs de analytics (GA, GTM, Facebook Pixel, etc.)."""

    def __init__(self) -> None:
        super().__init__(name="web_analytics_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        url = target.strip()
        if not url.lower().startswith(("http://", "https://")):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": "Sólo se permite http(s)"}),
                metadata={"ok": False},
            )

        if ssrf_enforce() and (blocked := check_public_http_url(url)):
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": f"Bloqueada por NetGuard: {blocked}"}),
                metadata={"ok": False},
            )

        try:
            resp = await http_get(url, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                return CollectorResult(
                    collector_name=self.name,
                    source_target=url,
                    raw_payload=json.dumps({"url": url, "error": f"HTTP {resp.status_code}"}),
                    metadata={"ok": False},
                )
            content = resp.text
        except Exception as exc:
            logger.debug("web_analytics: error descargando %s: %s", url, exc)
            return CollectorResult(
                collector_name=self.name,
                source_target=url,
                raw_payload=json.dumps({"url": url, "error": str(exc)}),
                metadata={"ok": False},
            )

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []
        found: dict[str, list[str]] = {
            "google_analytics_ua": [],
            "google_analytics_g": [],
            "google_tag_manager": [],
            "facebook_pixel": [],
            "hotjar": [],
            "mixpanel": [],
            "segment": [],
            "amplitude": [],
        }

        # Google Analytics UA-
        for match in sorted(set(_GA_UA_RE.findall(content))):
            found["google_analytics_ua"].append(match)
            node = EntityNode.create(
                EntityType.ALIAS,
                match,
                f"Google Analytics UA: {match}",
                attributes={"source": "web_analytics", "analytics_type": "google_analytics_ua"},
                confidence=0.95,
            )
            entities.append(node)

        # Google Analytics G-
        for match in sorted(set(_GA_G_RE.findall(content))):
            found["google_analytics_g"].append(match)
            node = EntityNode.create(
                EntityType.ALIAS,
                match,
                f"Google Analytics 4: {match}",
                attributes={"source": "web_analytics", "analytics_type": "google_analytics_g"},
                confidence=0.95,
            )
            entities.append(node)

        # Google Tag Manager
        for match in sorted(set(_GTM_RE.findall(content))):
            found["google_tag_manager"].append(match)
            node = EntityNode.create(
                EntityType.ALIAS,
                match,
                f"Google Tag Manager: {match}",
                attributes={"source": "web_analytics", "analytics_type": "google_tag_manager"},
                confidence=0.95,
            )
            entities.append(node)

        # Facebook Pixel (heurística: números largos en scripts de tracking)
        for match in sorted(set(_FB_PIXEL_RE.findall(content))):
            # Filtrar falsos positivos (fechas, etc.)
            if len(match) >= 15 and not match.startswith("20"):
                found["facebook_pixel"].append(match)
                node = EntityNode.create(
                    EntityType.ALIAS,
                    match,
                    f"Facebook Pixel: {match}",
                    attributes={"source": "web_analytics", "analytics_type": "facebook_pixel"},
                    confidence=0.7,
                )
                entities.append(node)

        # Hotjar
        for match in sorted(set(_HOTJAR_RE.findall(content))):
            found["hotjar"].append(match)
            node = EntityNode.create(
                EntityType.ALIAS,
                match,
                f"Hotjar: {match}",
                attributes={"source": "web_analytics", "analytics_type": "hotjar"},
                confidence=0.9,
            )
            entities.append(node)

        # Mixpanel
        for match in sorted(set(_MIXPANEL_RE.findall(content))):
            found["mixpanel"].append(match)
            node = EntityNode.create(
                EntityType.ALIAS,
                match,
                f"Mixpanel: {match[:20]}...",
                attributes={"source": "web_analytics", "analytics_type": "mixpanel"},
                confidence=0.85,
            )
            entities.append(node)

        # Segment
        for match in sorted(set(_SEGMENT_RE.findall(content))):
            found["segment"].append(match)
            node = EntityNode.create(
                EntityType.ALIAS,
                match,
                f"Segment: {match[:16]}...",
                attributes={"source": "web_analytics", "analytics_type": "segment"},
                confidence=0.75,
            )
            entities.append(node)

        # Amplitude
        for match in sorted(set(_AMPLITUDE_RE.findall(content))):
            found["amplitude"].append(match)
            node = EntityNode.create(
                EntityType.ALIAS,
                match,
                f"Amplitude: {match[:16]}...",
                attributes={"source": "web_analytics", "analytics_type": "amplitude"},
                confidence=0.75,
            )
            entities.append(node)

        total = sum(len(v) for v in found.values())
        return CollectorResult(
            collector_name=self.name,
            source_target=url,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"url": url, "analytics": found}, ensure_ascii=False),
            metadata={"ok": True, "analytics_found": total, "types": list(found.keys())},
        )

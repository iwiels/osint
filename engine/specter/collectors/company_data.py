"""
SpecterOSINT - Company Data Collectors
Colectores para enriquecer información sobre empresas y organizaciones.

Fuentes:
- OpenCorporatesCollector: API gratuita de registro mercantil (sin key)
- GLEIFCollector: API gratuita de LEI (Legal Entity Identifier) (sin key)
- ClearbitCollector: API de enriquecimiento de empresa (requiere key)
- FullContactCollector: API de datos de empresa (requiere key)
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
    RelationType,
)

logger = logging.getLogger("specter.collectors.company_data")

_TIMEOUT = 12.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+company-data)"}


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


class OpenCorporatesCollector(BaseCollector):
    """OpenCorporates: registro mercantil global gratuito (sin API key)."""

    def __init__(self) -> None:
        super().__init__(name="opencorporates")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        company = target.strip()
        url = f"https://api.opencorporates.com/v0.40/companies/search?q={quote(company)}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=company,
                raw_payload=json.dumps({"company": company, "error": str(exc)}),
                metadata={"ok": False},
            )

        companies = data.get("results", {}).get("companies", [])
        for comp in companies[:10]:
            company_data = comp.get("company", {})
            name = str(company_data.get("name", ""))
            reg_number = str(company_data.get("company_number", ""))
            jurisdiction = str(company_data.get("jurisdiction_code", ""))
            status = str(company_data.get("current_status", ""))

            if name:
                company_node = EntityNode.create(
                    EntityType.ORGANIZATION,
                    name,
                    f"OpenCorporates: {name}",
                    attributes={
                        "registration_number": reg_number,
                        "jurisdiction": jurisdiction,
                        "status": status,
                        "source": "opencorporates",
                    },
                    confidence=0.85,
                )
                entities.append(company_node)

                # Agregar directores si están disponibles
                for officer in company_data.get("officers", [])[:5]:
                    officer_name = str(officer.get("officer", {}).get("name", ""))
                    if officer_name:
                        officer_node = EntityNode.create(
                            EntityType.PERSON,
                            officer_name,
                            f"Director: {officer_name}",
                            attributes={
                                "position": officer.get("officer", {}).get("position"),
                                "source": "opencorporates",
                            },
                            confidence=0.7,
                        )
                        entities.append(officer_node)
                        relations.append(
                            RelationEdge(
                                source_id=officer_node.id,
                                target_id=company_node.id,
                                relation_type=RelationType.REGISTERED_BY,
                            )
                        )

        return CollectorResult(
            collector_name=self.name,
            source_target=company,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"company": company, "results": len(companies)}),
            metadata={"ok": True, "companies_found": len(entities)},
        )


class GLEIFCollector(BaseCollector):
    """GLEIF: Legal Entity Identifier (LEI) - API gratuita sin key."""

    def __init__(self) -> None:
        super().__init__(name="gleif")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        company = target.strip()
        url = f"https://api.gleif.org/api/v1/lei-records?filter[fulltext]={quote(company)}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=_UA)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=company,
                raw_payload=json.dumps({"company": company, "error": str(exc)}),
                metadata={"ok": False},
            )

        records = data.get("data", [])
        for record in records[:10]:
            lei = str(record.get("id", ""))
            attrs = record.get("attributes", {})
            entity = attrs.get("entity", {})
            name = str(entity.get("legalName", {}).get("name", ""))
            country = str(entity.get("legalAddress", {}).get("country", ""))
            status = str(entity.get("status", ""))

            if name:
                company_node = EntityNode.create(
                    EntityType.ORGANIZATION,
                    name,
                    f"GLEIF: {name}",
                    attributes={
                        "lei": lei,
                        "country": country,
                        "status": status,
                        "source": "gleif",
                    },
                    confidence=0.9,
                )
                entities.append(company_node)

        return CollectorResult(
            collector_name=self.name,
            source_target=company,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps({"company": company, "records": len(records)}),
            metadata={"ok": True, "records_found": len(entities)},
        )


class ClearbitCollector(BaseCollector):
    """Clearbit: enriquecimiento de empresa (requiere API key)."""

    def __init__(self) -> None:
        super().__init__(name="clearbit")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("clearbit_api_key")
        domain = target.strip().lower()
        if key is None:
            return _missing_key_result(self.name, domain, "clearbit_api_key")

        url = f"https://company.clearbit.com/v2/companies/find?domain={quote(domain)}"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers={**_UA, "Authorization": f"Bearer {key}"})
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=domain,
                        raw_payload=json.dumps({"domain": domain, "present": False}),
                        metadata={"ok": True, "present": False},
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        name = str(data.get("name", ""))
        sector = str(data.get("sector", ""))
        industry = str(data.get("industry", ""))
        employees = data.get("metrics", {}).get("employees", 0)
        location = str(data.get("location", ""))
        tech = data.get("tech", [])

        if name:
            company_node = EntityNode.create(
                EntityType.ORGANIZATION,
                name,
                f"Clearbit: {name}",
                attributes={
                    "sector": sector,
                    "industry": industry,
                    "employees": employees,
                    "location": location,
                    "technology": tech,
                    "source": "clearbit",
                },
                confidence=0.9,
            )
            entities.append(company_node)

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "name": name,
                    "sector": sector,
                    "employees": employees,
                }
            ),
            metadata={"ok": True, "present": True},
        )


class FullContactCollector(BaseCollector):
    """FullContact: datos de empresa (requiere API key)."""

    def __init__(self) -> None:
        super().__init__(name="fullcontact")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("fullcontact_api_key")
        domain = target.strip().lower()
        if key is None:
            return _missing_key_result(self.name, domain, "fullcontact_api_key")

        url = "https://api.fullcontact.com/v3/company.enrich"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    url,
                    json={"domain": domain},
                    headers={**_UA, "Authorization": f"Bearer {key}"},
                )
                if resp.status_code == 404:
                    return CollectorResult(
                        collector_name=self.name,
                        source_target=domain,
                        raw_payload=json.dumps({"domain": domain, "present": False}),
                        metadata={"ok": True, "present": False},
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                source_target=domain,
                raw_payload=json.dumps({"domain": domain, "error": str(exc)}),
                metadata={"ok": False},
            )

        name = str(data.get("name", ""))
        sector = str(data.get("sector", ""))
        industry = str(data.get("industry", ""))
        employees = data.get("employees", 0)
        location = str(data.get("location", ""))

        if name:
            company_node = EntityNode.create(
                EntityType.ORGANIZATION,
                name,
                f"FullContact: {name}",
                attributes={
                    "sector": sector,
                    "industry": industry,
                    "employees": employees,
                    "location": location,
                    "source": "fullcontact",
                },
                confidence=0.85,
            )
            entities.append(company_node)

        return CollectorResult(
            collector_name=self.name,
            source_target=domain,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "domain": domain,
                    "name": name,
                    "sector": sector,
                    "employees": employees,
                }
            ),
            metadata={"ok": True, "present": True},
        )

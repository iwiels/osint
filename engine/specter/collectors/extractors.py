"""
WraithOSINT - Extractores de inteligencia (emails, teléfonos, nombres, hashes, CC, IBAN).

Inspirado en SpiderFoot: sfp_email, sfp_phone, sfp_names, sfp_hashes,
sfp_creditcard, sfp_iban. Adaptado a la arquitectura desktop de WraithOSINT.
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

logger = logging.getLogger("specter.collectors.extractors")

_TIMEOUT = 15.0
_UA = {"User-Agent": "WraithOSINT/0.3 (+extraccion de inteligencia)"}

# Regex para emails
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Regex para teléfonos (formatos internacionales)
_PHONE_RE = re.compile(
    r"(?:\+\d{1,3}[-.\s]?)?(?:\(?\d{1,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{0,4}"
)

# Regex para hashes MD5/SHA
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA512_RE = re.compile(r"\b[a-fA-F0-9]{128}\b")

# Regex para tarjetas de crédito
_CC_RE = re.compile(r"\b(?:\d{4}[-.\s]?){3}\d{4}\b")

# Regex para IBAN
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

# Patrones comunes de nombres (Nombre Apellido)
_NAME_RE = re.compile(r"\b[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){1,3}\b")


def _luhn_check(number: str) -> bool:
    """Validación Luhn para números de tarjeta de crédito."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _validate_iban(iban: str) -> bool:
    """Validación básica de IBAN (mod-97)."""
    # Mover los primeros 4 caracteres al final
    rearranged = iban[4:] + iban[:4]
    # Convertir letras a números (A=10, B=11, ..., Z=35)
    numeric_str = ""
    for char in rearranged:
        if char.isdigit():
            numeric_str += char
        elif char.isalpha():
            numeric_str += str(ord(char.upper()) - 55)
        else:
            return False
    # Verificar mod-97
    return int(numeric_str) % 97 == 1


def _is_valid_phone(phone: str) -> bool:
    """Filtra falsos positivos de teléfonos."""
    digits = re.sub(r"\D", "", phone)
    # Teléfonos válidos tienen entre 7 y 15 dígitos
    return 7 <= len(digits) <= 15


def _is_valid_name(name: str) -> bool:
    """Filtra falsos positivos de nombres comunes."""
    # Excluir palabras comunes que no son nombres
    common_words = {
        "The",
        "And",
        "For",
        "Are",
        "But",
        "Not",
        "You",
        "All",
        "Can",
        "Had",
        "Her",
        "Was",
        "One",
        "Our",
        "Out",
        "Day",
        "Get",
        "Has",
        "Him",
        "His",
        "How",
        "Its",
        "May",
        "New",
        "Now",
        "Old",
        "See",
        "Two",
        "Way",
        "Who",
        "Did",
        "Let",
        "Put",
        "Say",
        "She",
        "Too",
        "Use",
        "El",
        "La",
        "Los",
        "Las",
        "Una",
        "Unos",
        "Unas",
        "Del",
        "Al",
        "Con",
        "Por",
        "Para",
        "Sin",
        "Sobre",
        "Entre",
        "Hasta",
        "Desde",
        "Durante",
        "Mediante",
        "Según",
        "Contra",
        "Hacia",
        "Ante",
        "Bajo",
        "Tras",
    }
    words = name.split()
    # Al menos una palabra no debe ser una palabra común
    return any(word not in common_words for word in words)


async def _fetch_content(target: str) -> tuple[str, str, str | None]:
    """
    Obtiene contenido de una URL o retorna el texto directamente.

    Retorna: (contenido, url_o_texto, error)
    """
    target = target.strip()
    if not target:
        return "", "", "Target vacío"

    # Si es una URL, descargar
    if target.lower().startswith(("http://", "https://")):
        if ssrf_enforce() and (blocked := check_public_http_url(target)):
            return "", target, f"Bloqueada por NetGuard: {blocked}"
        try:
            resp = await http_get(target, headers=_UA, timeout=_TIMEOUT)
            if resp.status_code >= 400:
                return "", target, f"HTTP {resp.status_code}"
            return resp.text, target, None
        except Exception as exc:
            logger.debug("extractors: error descargando %s: %s", target, exc)
            return "", target, str(exc)

    # Si no es URL, tratar como texto
    return target, target, None


def _create_result(
    collector_name: str,
    target: str,
    entities: list[EntityNode],
    relations: list[RelationEdge],
    metadata: dict[str, Any],
    raw_payload: dict[str, Any] | None = None,
) -> CollectorResult:
    """Helper para crear CollectorResult consistente."""
    return CollectorResult(
        collector_name=collector_name,
        source_target=target,
        entities=entities,
        relations=relations,
        raw_payload=json.dumps(raw_payload or metadata, ensure_ascii=False),
        metadata=metadata,
    )


class EmailExtractorCollector(BaseCollector):
    """Extractor de emails de contenido web o texto."""

    def __init__(self) -> None:
        super().__init__(name="email_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        content, source, error = await _fetch_content(target)
        if error:
            return _create_result(self.name, target, [], [], {"ok": False, "error": error})

        emails = sorted(set(_EMAIL_RE.findall(content)))
        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        for email in emails:
            node = EntityNode.create(
                EntityType.EMAIL,
                email,
                f"Email: {email}",
                attributes={"source": "email_extractor"},
                confidence=0.9,
            )
            entities.append(node)

        return _create_result(
            self.name,
            target,
            entities,
            relations,
            {"ok": True, "emails_found": len(emails)},
            {"emails": emails},
        )


class PhoneExtractorCollector(BaseCollector):
    """Extractor de teléfonos de contenido web o texto."""

    def __init__(self) -> None:
        super().__init__(name="phone_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        content, source, error = await _fetch_content(target)
        if error:
            return _create_result(self.name, target, [], [], {"ok": False, "error": error})

        raw_phones = _PHONE_RE.findall(content)
        phones = sorted({p.strip() for p in raw_phones if _is_valid_phone(p)})

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        for phone in phones:
            node = EntityNode.create(
                EntityType.PHONE,
                phone,
                f"Teléfono: {phone}",
                attributes={"source": "phone_extractor"},
                confidence=0.8,
            )
            entities.append(node)

        return _create_result(
            self.name,
            target,
            entities,
            relations,
            {"ok": True, "phones_found": len(phones)},
            {"phones": phones},
        )


class NameExtractorCollector(BaseCollector):
    """Extractor de nombres humanos de contenido web o texto."""

    def __init__(self) -> None:
        super().__init__(name="name_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        content, source, error = await _fetch_content(target)
        if error:
            return _create_result(self.name, target, [], [], {"ok": False, "error": error})

        raw_names = _NAME_RE.findall(content)
        names = sorted({n.strip() for n in raw_names if _is_valid_name(n)})

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        for name in names:
            node = EntityNode.create(
                EntityType.PERSON,
                name,
                f"Persona: {name}",
                attributes={"source": "name_extractor"},
                confidence=0.6,
            )
            entities.append(node)

        return _create_result(
            self.name,
            target,
            entities,
            relations,
            {"ok": True, "names_found": len(names)},
            {"names": names},
        )


class HashExtractorCollector(BaseCollector):
    """Extractor de hashes MD5/SHA de contenido web o texto."""

    def __init__(self) -> None:
        super().__init__(name="hash_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        content, source, error = await _fetch_content(target)
        if error:
            return _create_result(self.name, target, [], [], {"ok": False, "error": error})

        hashes: dict[str, str] = {}

        for match in _MD5_RE.findall(content):
            hashes[match] = "MD5"
        for match in _SHA1_RE.findall(content):
            hashes[match] = "SHA1"
        for match in _SHA256_RE.findall(content):
            hashes[match] = "SHA256"
        for match in _SHA512_RE.findall(content):
            hashes[match] = "SHA512"

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        for hash_value, hash_type in sorted(hashes.items()):
            node = EntityNode.create(
                EntityType.ALIAS,
                hash_value,
                f"Hash {hash_type}: {hash_value[:16]}...",
                attributes={"source": "hash_extractor", "hash_type": hash_type},
                confidence=0.85,
            )
            entities.append(node)

        return _create_result(
            self.name,
            target,
            entities,
            relations,
            {"ok": True, "hashes_found": len(hashes)},
            {"hashes": [{"value": h, "type": t} for h, t in sorted(hashes.items())]},
        )


class CreditCardExtractorCollector(BaseCollector):
    """Extractor de números de tarjeta de crédito con validación Luhn."""

    def __init__(self) -> None:
        super().__init__(name="creditcard_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        content, source, error = await _fetch_content(target)
        if error:
            return _create_result(self.name, target, [], [], {"ok": False, "error": error})

        raw_cards = _CC_RE.findall(content)
        cards = sorted({c.strip() for c in raw_cards if _luhn_check(c)})

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        for card in cards:
            # Enmascarar para seguridad
            masked = f"****-****-****-{card[-4:]}" if len(card) >= 4 else "****"
            node = EntityNode.create(
                EntityType.ALIAS,
                card,
                f"Tarjeta: {masked}",
                attributes={"source": "creditcard_extractor", "masked": masked},
                confidence=0.95,
            )
            entities.append(node)

        return _create_result(
            self.name,
            target,
            entities,
            relations,
            {"ok": True, "cards_found": len(cards)},
            {"cards": [{"masked": f"****-****-****-{c[-4:]}"} for c in cards]},
        )


class IBANExtractorCollector(BaseCollector):
    """Extractor de IBANs con validación mod-97."""

    def __init__(self) -> None:
        super().__init__(name="iban_extractor")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        content, source, error = await _fetch_content(target)
        if error:
            return _create_result(self.name, target, [], [], {"ok": False, "error": error})

        raw_ibans = _IBAN_RE.findall(content)
        ibans = sorted({i.upper() for i in raw_ibans if _validate_iban(i.upper())})

        entities: list[EntityNode] = []
        relations: list[RelationEdge] = []

        for iban in ibans:
            node = EntityNode.create(
                EntityType.ALIAS,
                iban,
                f"IBAN: {iban[:4]}****{iban[-4:]}",
                attributes={
                    "source": "iban_extractor",
                    "country": iban[:2],
                    "masked": f"{iban[:4]}****{iban[-4:]}",
                },
                confidence=0.9,
            )
            entities.append(node)

        return _create_result(
            self.name,
            target,
            entities,
            relations,
            {"ok": True, "ibans_found": len(ibans)},
            {"ibans": [{"masked": f"{i[:4]}****{i[-4:]}", "country": i[:2]} for i in ibans]},
        )

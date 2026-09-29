"""
SpecterOSINT - Blockchain Collectors
Colectores para investigar direcciones de criptomonedas y reportes de abuso.

Fuentes:
- BitcoinWhoIsWhoCollector: reputación de direcciones Bitcoin (sin key)
- BitcoinAbuseCollector: reportes de abuso de direcciones Bitcoin (sin key)
- BlockchainInfoCollector: datos de Blockchain.info (sin key)
- EtherscanCollector: datos de Ethereum (requiere key)
"""

from __future__ import annotations

import json
import logging
import re
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

logger = logging.getLogger("specter.collectors.blockchain")

_TIMEOUT = 12.0
_UA = {"User-Agent": "SpecterOSINT/0.2 (+blockchain)"}


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


def _is_bitcoin_address(address: str) -> bool:
    """Verifica si la dirección es una dirección Bitcoin válida."""
    return bool(re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", address)) or bool(
        re.match(r"^bc1[a-zA-HJ-NP-Z0-9]{25,39}$", address)
    )


def _is_ethereum_address(address: str) -> bool:
    """Verifica si la dirección es una dirección Ethereum válida."""
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", address))


class BitcoinWhoIsWhoCollector(BaseCollector):
    """Bitcoin Who's Who: verifica si una dirección Bitcoin es conocida como scam."""

    def __init__(self) -> None:
        super().__init__(name="bitcoinwhoswho")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        address = target.strip()
        url = f"https://bitcoinwhoswho.com/api/scam-address/{quote(address)}"

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
                source_target=address,
                raw_payload=json.dumps({"address": address, "error": str(exc)}),
                metadata={"ok": False},
            )

        is_scam = bool(data.get("is_scam", False))
        reports = data.get("reports", [])

        address_node = EntityNode.create(
            EntityType.ALIAS,
            address,
            f"BTC Address: {address[:20]}...",
            attributes={
                "is_scam": is_scam,
                "reports_count": len(reports),
                "source": "bitcoinwhoswho",
            },
            confidence=0.9 if is_scam else 0.5,
        )
        entities.append(address_node)

        # Agregar reportes como entidades
        for report in reports[:10]:
            report_id = str(report.get("id", report.get("report_id", "")))
            report_type = str(report.get("type", report.get("report_type", "")))
            if report_id:
                report_node = EntityNode.create(
                    EntityType.ALIAS,
                    report_id,
                    f"Report: {report_type}",
                    attributes={
                        "report_type": report_type,
                        "source": "bitcoinwhoswho",
                    },
                    confidence=0.8,
                )
                entities.append(report_node)
                relations.append(
                    RelationEdge(
                        source_id=address_node.id,
                        target_id=report_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )

        return CollectorResult(
            collector_name=self.name,
            source_target=address,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"address": address, "is_scam": is_scam, "reports": len(reports)}
            ),
            metadata={"ok": True, "is_scam": is_scam, "reports": len(reports)},
        )


class BitcoinAbuseCollector(BaseCollector):
    """BitcoinAbuse: reportes de abuso de direcciones Bitcoin."""

    def __init__(self) -> None:
        super().__init__(name="bitcoinabuse")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        address = target.strip()
        url = f"https://www.bitcoinabuse.com/api/reports/check?address={quote(address)}"

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
                source_target=address,
                raw_payload=json.dumps({"address": address, "error": str(exc)}),
                metadata={"ok": False},
            )

        abuse_count = int(data.get("count", 0))
        reports = data.get("reports", [])

        address_node = EntityNode.create(
            EntityType.ALIAS,
            address,
            f"BTC Address: {address[:20]}...",
            attributes={
                "abuse_reports": abuse_count,
                "source": "bitcoinabuse",
            },
            confidence=0.9 if abuse_count > 0 else 0.5,
        )
        entities.append(address_node)

        # Agregar reportes como entidades
        for report in reports[:10]:
            report_id = str(report.get("id", ""))
            report_type = str(report.get("abuse_type", report.get("type", "")))
            if report_id:
                report_node = EntityNode.create(
                    EntityType.ALIAS,
                    report_id,
                    f"Abuse Report: {report_type}",
                    attributes={
                        "abuse_type": report_type,
                        "source": "bitcoinabuse",
                    },
                    confidence=0.8,
                )
                entities.append(report_node)
                relations.append(
                    RelationEdge(
                        source_id=address_node.id,
                        target_id=report_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )

        return CollectorResult(
            collector_name=self.name,
            source_target=address,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"address": address, "abuse_reports": abuse_count, "reports": len(reports)}
            ),
            metadata={"ok": True, "abuse_reports": abuse_count},
        )


class BlockchainInfoCollector(BaseCollector):
    """Blockchain.info: datos de direcciones Bitcoin (balance, transacciones)."""

    def __init__(self) -> None:
        super().__init__(name="blockchaininfo")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        address = target.strip()
        url = f"https://blockchain.info/rawaddr/{quote(address)}"

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
                source_target=address,
                raw_payload=json.dumps({"address": address, "error": str(exc)}),
                metadata={"ok": False},
            )

        final_balance = int(data.get("final_balance", 0))
        total_received = int(data.get("total_received", 0))
        total_sent = int(data.get("total_sent", 0))
        n_tx = int(data.get("n_tx", 0))
        transactions = data.get("txs", [])

        address_node = EntityNode.create(
            EntityType.ALIAS,
            address,
            f"BTC Address: {address[:20]}...",
            attributes={
                "balance_satoshis": final_balance,
                "total_received_satoshis": total_received,
                "total_sent_satoshis": total_sent,
                "transactions_count": n_tx,
                "source": "blockchaininfo",
            },
            confidence=0.9,
        )
        entities.append(address_node)

        # Agregar transacciones recientes como entidades
        for tx in transactions[:10]:
            tx_hash = str(tx.get("hash", ""))
            if tx_hash:
                tx_node = EntityNode.create(
                    EntityType.ALIAS,
                    tx_hash,
                    f"TX: {tx_hash[:20]}...",
                    attributes={
                        "value": tx.get("value", 0),
                        "time": tx.get("time", 0),
                        "source": "blockchaininfo",
                    },
                    confidence=0.7,
                )
                entities.append(tx_node)
                relations.append(
                    RelationEdge(
                        source_id=address_node.id,
                        target_id=tx_node.id,
                        relation_type=RelationType.ASSOCIATED_WITH,
                    )
                )

        return CollectorResult(
            collector_name=self.name,
            source_target=address,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {
                    "address": address,
                    "balance": final_balance,
                    "total_received": total_received,
                    "total_sent": total_sent,
                    "transactions": n_tx,
                }
            ),
            metadata={"ok": True, "balance": final_balance, "transactions": n_tx},
        )


class EtherscanCollector(BaseCollector):
    """Etherscan: datos de direcciones Ethereum (requiere API key)."""

    def __init__(self) -> None:
        super().__init__(name="etherscan")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        key = _collector_key("etherscan_api_key")
        address = target.strip()
        if key is None:
            return _missing_key_result(self.name, address, "etherscan_api_key")

        url = (
            f"https://api.etherscan.io/api?module=account&action=balance"
            f"&address={quote(address)}&tag=latest&apikey={quote(key)}"
        )

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
                source_target=address,
                raw_payload=json.dumps({"address": address, "error": str(exc)}),
                metadata={"ok": False},
            )

        # Etherscan retorna balance en wei
        balance_wei = int(data.get("result", 0))
        balance_eth = balance_wei / 1e18

        address_node = EntityNode.create(
            EntityType.ALIAS,
            address,
            f"ETH Address: {address[:20]}...",
            attributes={
                "balance_wei": balance_wei,
                "balance_eth": balance_eth,
                "source": "etherscan",
            },
            confidence=0.9,
        )
        entities.append(address_node)

        return CollectorResult(
            collector_name=self.name,
            source_target=address,
            entities=entities,
            relations=relations,
            raw_payload=json.dumps(
                {"address": address, "balance_wei": balance_wei, "balance_eth": balance_eth}
            ),
            metadata={"ok": True, "balance_eth": balance_eth},
        )

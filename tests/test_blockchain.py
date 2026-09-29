"""
Tests de los colectores de Blockchain (Bitcoin Who's Who, BitcoinAbuse, Blockchain.info, Etherscan).
Red 100% mockeada vía tests/http_mock.py: cero internet.
"""

from __future__ import annotations

import pytest
from http_mock import MockRouter, patch_httpx
from specter.collectors.blockchain import (
    BitcoinAbuseCollector,
    BitcoinWhoIsWhoCollector,
    BlockchainInfoCollector,
    EtherscanCollector,
)

pytestmark = pytest.mark.asyncio

_BTC_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_ETH_ADDRESS = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08"


def _router() -> MockRouter:
    return (
        MockRouter()
        # Bitcoin Who's Who: dirección scam
        .add(
            "GET",
            r"bitcoinwhoswho\.com/api/scam-address",
            json={
                "is_scam": True,
                "reports": [
                    {"id": "report-1", "type": "phishing"},
                    {"id": "report-2", "type": "scam"},
                ],
            },
        )
        # BitcoinAbuse: reportes de abuso
        .add(
            "GET",
            r"bitcoinabuse\.com/api/reports/check",
            json={
                "count": 5,
                "reports": [
                    {"id": "abuse-1", "abuse_type": "ransomware"},
                    {"id": "abuse-2", "abuse_type": "darknet_market"},
                ],
            },
        )
        # Blockchain.info: datos de dirección
        .add(
            "GET",
            r"blockchain\.info/rawaddr",
            json={
                "final_balance": 100000000,
                "total_received": 200000000,
                "total_sent": 100000000,
                "n_tx": 5,
                "txs": [
                    {"hash": "tx-hash-1", "value": 50000000, "time": 1609459200},
                    {"hash": "tx-hash-2", "value": 30000000, "time": 1609545600},
                ],
            },
        )
        # Etherscan: balance de ETH
        .add(
            "GET",
            r"api\.etherscan\.io/api",
            json={
                "status": "1",
                "message": "OK",
                "result": "1000000000000000000",  # 1 ETH en wei
            },
        )
    )


async def test_bitcoinwhoswho_detecta_scam(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await BitcoinWhoIsWhoCollector().collect(_BTC_ADDRESS)
    assert result.metadata["ok"] is True
    assert result.metadata["is_scam"] is True
    assert result.metadata["reports"] == 2


async def test_bitcoinabuse_encuentra_reportes(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await BitcoinAbuseCollector().collect(_BTC_ADDRESS)
    assert result.metadata["ok"] is True
    assert result.metadata["abuse_reports"] == 5


async def test_blockchaininfo_encuentra_balance(monkeypatch) -> None:
    patch_httpx(monkeypatch, _router())
    result = await BlockchainInfoCollector().collect(_BTC_ADDRESS)
    assert result.metadata["ok"] is True
    assert result.metadata["balance"] == 100000000
    assert result.metadata["transactions"] == 5


async def test_etherscan_requiere_key(monkeypatch) -> None:
    """Verifica que Etherscan requiere API key."""
    patch_httpx(monkeypatch, _router())
    result = await EtherscanCollector().collect(_ETH_ADDRESS)
    assert result.metadata["ok"] is False
    assert result.metadata["requires_key"] == "etherscan_api_key"


async def test_bitcoinwhoswho_maneja_error_red(monkeypatch) -> None:
    """Verifica que un error de red no rompe el colector."""
    router = MockRouter()  # Sin rutas = 599
    patch_httpx(monkeypatch, router)
    result = await BitcoinWhoIsWhoCollector().collect(_BTC_ADDRESS)
    assert result.metadata["ok"] is False


async def test_bitcoinabuse_maneja_error_red(monkeypatch) -> None:
    """Verifica que un error de red no rompe el colector."""
    router = MockRouter()  # Sin rutas = 599
    patch_httpx(monkeypatch, router)
    result = await BitcoinAbuseCollector().collect(_BTC_ADDRESS)
    assert result.metadata["ok"] is False


async def test_blockchaininfo_maneja_error_red(monkeypatch) -> None:
    """Verifica que un error de red no rompe el colector."""
    router = MockRouter()  # Sin rutas = 599
    patch_httpx(monkeypatch, router)
    result = await BlockchainInfoCollector().collect(_BTC_ADDRESS)
    assert result.metadata["ok"] is False

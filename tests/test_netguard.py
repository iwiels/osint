"""
Tests de NetGuard (SSRF) y de los límites de file_forensics (LFI/cotas).
Sin red real: DNS stubbeado + SPECTER_SSRF_ENFORCE=1 explícito.
"""

from __future__ import annotations

import socket

import pytest
from specter.netguard import assert_public_http_url, check_public_http_url


@pytest.fixture()
def _enforced(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SPECTER_SSRF_ENFORCE", "1")


def _dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]):
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host in mapping:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in mapping[host]]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_netguard_bloquea_loopback_privada_y_linklocal(_enforced) -> None:
    assert check_public_http_url("http://127.0.0.1:8787/health") is not None
    assert check_public_http_url("http://[::1]/x") is not None
    assert check_public_http_url("http://169.254.169.254/latest/meta-data/") is not None
    assert check_public_http_url("http://10.0.0.5/intranet") is not None
    assert check_public_http_url("http://192.168.1.1/router") is not None
    with pytest.raises(ValueError, match="NetGuard"):
        assert_public_http_url("http://127.0.0.1:8787/health")


def test_netguard_bloquea_dns_a_privada_y_credenciales(_enforced, monkeypatch) -> None:
    _dns(monkeypatch, {"evil.test": ["10.9.9.9"], "ok.test": ["93.184.215.14"]})
    assert check_public_http_url("http://evil.test/x") is not None
    assert check_public_http_url("http://ok.test/x") is None
    assert check_public_http_url("http://user:pass@ok.test/x") is not None
    assert check_public_http_url("ftp://ok.test/x") is not None


def test_netguard_falla_cerrado_sin_dns(_enforced, monkeypatch) -> None:
    def boom(*args, **kwargs):
        raise OSError("sin red")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert check_public_http_url("http://inexistente.invalid/x") is not None


async def test_web_fetch_respeta_netguard(monkeypatch) -> None:
    """URL privada -> error controlado, sin tocar la red."""
    from specter.collectors.web import WebFetchCollector

    monkeypatch.setenv("SPECTER_SSRF_ENFORCE", "1")
    result = await WebFetchCollector().collect("http://127.0.0.1:8787/health")
    assert result.metadata.get("ok") is False
    assert "NetGuard" in result.raw_payload


async def test_file_forensics_rechaza_secretos_propios(engine_env, tmp_path) -> None:
    """Ni siquiera aprobado se sellan bóveda/clave HMAC en el ledger."""
    from specter import config as specter_config
    from specter.collectors.artifacts import FileForensics

    vault = specter_config.secrets_path()
    vault.parent.mkdir(parents=True, exist_ok=True)
    vault.write_text('{"opencode_api_key": "sk-x"}', encoding="utf-8")
    with pytest.raises(ValueError, match="bloqueado"):
        await FileForensics().collect(str(vault))
    decoy = tmp_path / "id_rsa.key"
    decoy.write_text("falsa", encoding="utf-8")
    with pytest.raises(ValueError, match="bloqueado"):
        await FileForensics().collect(str(decoy))

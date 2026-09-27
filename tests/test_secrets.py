"""
Tests de la bóveda local de secretos: guardado con permisos, enmascarado,
lista blanca, endpoints HTTP y precedencia de resolución de claves del agente.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx
import pytest
from conftest import TEST_AUTH_HEADERS
from specter import config, secrets

from engine.agent import PROVIDERS, _resolve_provider

pytestmark = pytest.mark.asyncio


@pytest.fixture()
def vault(engine_env: Path, monkeypatch) -> Path:
    """Bóveda aislada en tmp: ni la del usuario ni variables de entorno reales."""
    monkeypatch.delenv("SPECTER_SECRETS_PATH", raising=False)
    for env_var in ("OPENCODE_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(env_var, raising=False)
    return config.secrets_path()


def test_set_get_delete_roundtrip(vault: Path):
    assert secrets.get_secret("opencode_api_key") is None
    assert secrets.list_secrets()[0]["configured"] is False

    secrets.set_secret("opencode_api_key", "  sk-zen-1234567890  ")

    assert vault.exists()
    assert secrets.get_secret("opencode_api_key") == "sk-zen-1234567890"
    assert json.loads(vault.read_text(encoding="utf-8")) == {
        "opencode_api_key": "sk-zen-1234567890"
    }

    assert secrets.delete_secret("opencode_api_key") is True
    assert secrets.delete_secret("opencode_api_key") is False
    assert secrets.get_secret("opencode_api_key") is None


@pytest.mark.skipif(sys.platform == "win32", reason="Windows no aplica el modo POSIX")
def test_vault_file_is_owner_only(vault: Path):
    secrets.set_secret("openai_api_key", "sk-test-abcdef")

    assert os.stat(vault).st_mode & 0o777 == 0o600


def test_list_secrets_enmascara_y_nunca_expone_el_valor(vault: Path):
    secrets.set_secret("anthropic_api_key", "sk-ant-1234567890abcd")

    entries = {entry["name"]: entry for entry in secrets.list_secrets()}

    assert entries["anthropic_api_key"] == {
        "name": "anthropic_api_key",
        "env_var": "ANTHROPIC_API_KEY",
        "configured": True,
        "masked": "•" * 21,
    }
    assert entries["openai_api_key"]["configured"] is False
    assert entries["openai_api_key"]["masked"] is None
    assert "1234567890" not in json.dumps(secrets.list_secrets())


@pytest.mark.parametrize(
    ("value", "expected"),
    [("12345678", "••••••••"), ("clave-larga-de-prueba", "•" * 21)],
)
def test_mask_nunca_revela_el_cuerpo(value, expected):
    assert secrets.mask(value) == expected
    assert set(secrets.mask(value)) == {"•"}


def test_lista_blanca_de_nombres(vault: Path):
    with pytest.raises(secrets.SecretError, match="no admitido"):
        secrets.set_secret("aws_secret_access_key", "x")
    with pytest.raises(secrets.SecretError, match="no admitido"):
        secrets.delete_secret("cualquiera")
    with pytest.raises(secrets.SecretError, match="vacío"):
        secrets.set_secret("opencode_api_key", "   ")
    assert secrets.get_secret("nombre-invalido") is None


def test_boveda_corrupta_o_con_nombres_desconocidos_no_rompe(vault: Path):
    vault.write_text("{roto", encoding="utf-8")
    assert secrets.get_secret("opencode_api_key") is None
    assert all(entry["configured"] is False for entry in secrets.list_secrets())

    vault.write_text(json.dumps({"opencode_api_key": "ok", "clave_rara": "no"}), encoding="utf-8")
    assert secrets.get_secret("opencode_api_key") == "ok"
    assert [e["name"] for e in secrets.list_secrets()] == sorted(secrets.ALLOWED_SECRETS)


def test_provider_secret_name():
    assert secrets.provider_secret_name("OpenCode") == "opencode_api_key"
    assert secrets.provider_secret_name("anthropic") == "anthropic_api_key"
    assert secrets.provider_secret_name("ollama") is None


# --- Precedencia en el agente ---


def test_boveda_alimenta_al_agente_y_el_entorno_tiene_prioridad(vault: Path, monkeypatch):
    secrets.set_secret("opencode_api_key", "sk-desde-boveda")

    cfg, model = _resolve_provider("opencode", None, None, None)
    assert cfg.api_key == "sk-desde-boveda"
    assert model == PROVIDERS["opencode"].default_model

    monkeypatch.setenv("OPENCODE_API_KEY", "sk-desde-entorno")
    cfg, _ = _resolve_provider("opencode", None, None, None)
    assert cfg.api_key == "sk-desde-entorno"

    cfg, _ = _resolve_provider("opencode", None, "sk-explicita", None)
    assert cfg.api_key == "sk-explicita"


def test_boveda_alimenta_openai_y_anthropic(vault: Path):
    secrets.set_secret("openai_api_key", "sk-oai")
    secrets.set_secret("anthropic_api_key", "sk-ant")

    assert _resolve_provider("openai", None, None, None)[0].api_key == "sk-oai"
    assert _resolve_provider("anthropic", None, None, None)[0].api_key == "sk-ant"


def test_sin_clave_en_ningun_sitio_sigue_fallando(vault: Path, monkeypatch):
    """Modelo de pago sin clave en ningún sitio -> error; free -> permitido."""
    monkeypatch.delenv("OPENCODE_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="Falta API key"):
        _resolve_provider("opencode", "glm-5.3", None, None)

    cfg, _ = _resolve_provider("opencode", "big-pickle", None, None)
    assert cfg.api_key == "public"


# --- Endpoints HTTP ---


async def _client(engine) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=engine.app),
        base_url="http://test",
        headers=TEST_AUTH_HEADERS,
    )


async def test_endpoints_de_boveda(engine, vault: Path):
    async with await _client(engine) as client:
        initial = await client.get("/settings/secrets")
        assert initial.status_code == 200
        assert initial.json()["path"] == str(vault)
        assert all(not entry["configured"] for entry in initial.json()["secrets"])

        stored = await client.put(
            "/settings/secrets/opencode_api_key", json={"value": "sk-zen-9999"}
        )
        assert stored.status_code == 200
        entry = next(e for e in stored.json()["secrets"] if e["name"] == "opencode_api_key")
        assert entry["configured"] is True and set(entry["masked"]) == {"•"}

        invalid = await client.put("/settings/secrets/aws_key", json={"value": "x"})
        assert invalid.status_code == 400
        assert "no admitido" in invalid.json()["detail"]

        empty = await client.put("/settings/secrets/openai_api_key", json={"value": "  "})
        assert empty.status_code == 400

        removed = await client.delete("/settings/secrets/opencode_api_key")
        assert removed.status_code == 200 and removed.json()["removed"] is True

        unknown_delete = await client.delete("/settings/secrets/aws_key")
        assert unknown_delete.status_code == 400

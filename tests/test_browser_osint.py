"""Tests de la capa OSINT del navegador sigiloso (browser_osint).

El navegador se mockea a nivel de módulo; el ledger usa una BD temporal real
para verificar que el sellado produce bloques encadenados.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest
from specter import browser_osint
from specter.browser_osint import (
    _validate_actions,
    osint_browser_status,
    osint_interact,
    osint_rotate_identity,
    osint_screenshot,
    osint_snapshot,
)
from specter.osint_core.database import Database
from specter.osint_core.ledger import ForensicLedger

STEALTH = "specter.browser_osint.get_browser"


class FakeBrowser:
    """Doble del navegador con la interfaz completa que consume browser_osint."""

    fingerprint: dict = {
        "label": "test",
        "ua": "UA",
        "sec_ch_ua": "CH",
        "sec_ch_ua_platform": '"Windows"',
        "locale": "es-ES",
        "tz": "UTC",
        "viewport": {"width": 800, "height": 600},
        "accept_language": "es",
    }
    fingerprint_index = 0
    restart_times: list[float] = []
    is_ready = True

    def __init__(self, snapshot=None, shot=None):
        self.snapshot = snapshot or {"title": "T", "url": "u", "text": "x", "links": []}
        self.shot = shot or {
            "image_base64": "aGVsbG8=",
            "mime": "image/png",
            "title": "T",
            "url": "u",
            "captured_at": "2026-09-26T12:00:00Z",
        }
        self.rotated = False
        self.recycled = False

    async def navigate_and_snapshot(self, url, timeout_s=30.0):
        return dict(self.snapshot)

    async def screenshot(self, url=None, full_page=False, timeout_s=30.0):
        return dict(self.shot)

    async def interact(self, url, actions, timeout_s=30.0):
        return {**self.snapshot, "actions_run": len(actions)}

    def rotate_fingerprint(self):
        self.rotated = True
        return {"locale": "es-MX", "tz": "America/Mexico_City"}

    async def recycle_context(self):
        self.recycled = True


@pytest.fixture()
def tmp_ledger(monkeypatch, tmp_path):
    """Ledger real contra BD temporal: el sellado produce bloques verificables."""
    db = Database(tmp_path / "test.db")
    ledger = ForensicLedger(db)
    monkeypatch.setattr("specter.server.db", db)
    monkeypatch.setattr("specter.server.ledger", ledger)
    return db, ledger


def _fake(monkeypatch, **kwargs):
    fake = FakeBrowser(**{k: v for k, v in kwargs.items() if k != "screenshot"})
    if "screenshot" in kwargs:
        fake.shot = kwargs["screenshot"]
    monkeypatch.setattr(STEALTH, AsyncMock(return_value=fake))
    return fake


# ---------------------------------------------------------------- whitelist


def test_validate_actions_rechaza_verbos_desconocidos():
    with pytest.raises(ValueError, match="no permitida"):
        _validate_actions([{"action": "evaluate", "script": "evil()"}])


def test_validate_actions_exige_selector_y_texto():
    with pytest.raises(ValueError, match="selector"):
        _validate_actions([{"action": "click"}])
    with pytest.raises(ValueError, match="text"):
        _validate_actions([{"action": "fill", "selector": "input"}])
    assert _validate_actions([]) == []
    ok = [{"action": "fill", "selector": "input[name=q]", "text": "x"}]
    assert _validate_actions(ok) == ok


# ------------------------------------------------------------------- sellado


async def test_snapshot_sin_caso_devuelve_sin_sello(monkeypatch):
    _fake(monkeypatch)

    out = json.loads(await osint_snapshot("https://ejemplo.test"))

    assert out["evidence"]["sealed"] is False
    assert out["evidence"]["block_hash"] is None


async def test_snapshot_con_caso_sella_en_ledger(monkeypatch, tmp_ledger):
    db, ledger = tmp_ledger
    from specter.osint_core.models import CaseMetadata

    case = CaseMetadata(case_id="case-test-1", name="Prueba", description="d", investigator="QA")
    db.create_case(case)
    ledger.initialize_case_genesis(case)
    _fake(monkeypatch)

    out = json.loads(await osint_snapshot("https://ejemplo.test", case_id="case-test-1"))

    assert out["evidence"]["sealed"] is True
    assert out["evidence"]["block_hash"]
    blocks = db.get_case_ledger("case-test-1")
    assert len(blocks) == 2  # genesis + evidencia
    assert blocks[1].evidence_hash


async def test_screenshot_sella_meta_sin_base64_en_payload(monkeypatch, tmp_ledger):
    db, ledger = tmp_ledger
    from specter.osint_core.models import CaseMetadata

    case = CaseMetadata(case_id="case-test-2", name="Prueba2", description="d", investigator="QA")
    db.create_case(case)
    ledger.initialize_case_genesis(case)
    _fake(monkeypatch)

    out = json.loads(await osint_screenshot("https://ejemplo.test", case_id="case-test-2"))

    assert out["evidence"]["sealed"] is True
    # El payload sellado es la META, no el base64 (la imagen vive en la respuesta).
    blocks = db.get_case_ledger("case-test-2")
    assert len(blocks) == 2


async def test_interact_ejecuta_acciones_validadas(monkeypatch):
    fake = _fake(monkeypatch)

    actions = [
        {"action": "fill", "selector": "input[name=q]", "text": "consulta"},
        {"action": "press", "key": "Enter"},
        {"action": "wait", "ms": 500},
    ]
    out = json.loads(await osint_interact("https://ejemplo.test", actions))

    assert out["actions_run"] == 3
    assert fake.recycled is False


async def test_interact_rechaza_accion_prohibida_sin_tocar_navegador(monkeypatch):
    _fake(monkeypatch)

    # 'evaluate' no está en la whitelist: la validación falla ANTES de tocar
    # el navegador (no hay flujo completado).
    with pytest.raises(ValueError, match="no permitida"):
        await osint_interact("https://x.test", [{"action": "evaluate"}])
    # Y una acción válida sí llega al navegador:
    out = json.loads(await osint_interact("https://x.test", [{"action": "click", "selector": "a"}]))
    assert out["actions_run"] == 1


# ---------------------------------------------------------------- identidad


async def test_rotate_identity_rota_y_recicla(monkeypatch):
    fake = _fake(monkeypatch)

    out = json.loads(await osint_rotate_identity())

    assert out["status"] == "IDENTITY_ROTATED"
    assert fake.rotated is True
    assert fake.recycled is True
    assert out["next_fingerprint"]["locale"] == "es-MX"


async def test_status_reporta_estado(monkeypatch):
    _fake(monkeypatch)

    out = json.loads(await osint_browser_status())

    assert out["engine"] == "patchright-chromium"
    assert "ready" in out and "fingerprint_index" in out


# --------------------------- sanity: patch del ledger aislado por test


def test_seal_sin_ledger_configurado_no_explota(monkeypatch):
    """Si el import de server falla (contexto raro), el sellado es no-fatal."""
    monkeypatch.setattr(
        browser_osint,
        "_ledger",
        lambda: (_ for _ in ()).throw(RuntimeError("sin kernel")),
    )
    h = browser_osint._seal_evidence("case-x", "c", "a", "u", {})
    assert h is None

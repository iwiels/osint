"""
Tests del catálogo de colectores: registro, plugins externos y las tools
genéricas `list_collectors` / `run_collector`.
"""

from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path
from typing import Any

import pytest
from http_mock import MockRouter, patch_network
from specter.collectors.base import BaseCollector
from specter.collectors.registry import CollectorRegistry
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
)

from engine.registry import call_tool_validated


class FakeCollector(BaseCollector):
    """Colector de prueba: no toca la red, sólo declara una entidad."""

    def __init__(self, name: str = "fake_collector") -> None:
        super().__init__(name=name)

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        node = EntityNode.create(EntityType.DOMAIN, target, label=f"Fake: {target}")
        return CollectorResult(
            collector_name=self.name,
            source_target=target,
            entities=[node],
            raw_payload=json.dumps({"fake": target}),
            metadata={"fake": True},
        )


class ExplodingCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__(name="exploding")

    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        raise RuntimeError("fuente caída")


def _fake_entry(name: str, loaded: Any, error: Exception | None = None) -> Any:
    class _Entry:
        def __init__(self) -> None:
            self.name = name
            self.value = f"paquete.modulo:{name}"

        def load(self) -> Any:
            if error:
                raise error
            return loaded

    return _Entry()


@pytest.fixture()
def registry() -> CollectorRegistry:
    return CollectorRegistry()


def test_register_y_consulta(registry: CollectorRegistry):
    spec = registry.register(FakeCollector())

    assert spec.name == "fake_collector"
    assert spec.origin == "builtin"
    assert "fake_collector" in registry
    assert len(registry) == 1
    assert registry.names() == ["fake_collector"]
    assert isinstance(registry.get("fake_collector"), FakeCollector)
    assert registry.describe() == [
        {
            "name": "fake_collector",
            "origin": "builtin",
            "class": "FakeCollector",
            "kind": "builtin",
        }
    ]


def test_register_acepta_clases_y_usa_el_nombre_de_clase(registry: CollectorRegistry):
    spec = registry.register(ExplodingCollector)

    assert spec.name == "exploding"
    assert registry.unregister("exploding") is True
    assert registry.unregister("exploding") is False


def test_get_desconocido_lanza_keyerror(registry: CollectorRegistry):
    with pytest.raises(KeyError):
        registry.get("no-existe")
    with pytest.raises(KeyError):
        registry.spec("no-existe")


def test_load_entry_points_registra_plugins_y_aisla_rotos(registry: CollectorRegistry, monkeypatch):
    entries = [
        _fake_entry("mi_plugin", FakeCollector("plugin_collector")),
        _fake_entry("roto", None, error=ImportError("dependencia ausente")),
        _fake_entry("sin_collect", object()),
    ]
    monkeypatch.setattr(
        importlib.metadata, "entry_points", lambda group=None: entries if group else []
    )

    loaded = registry.load_entry_points()

    assert loaded == ["mi_plugin"]  # el roto y el que no expone collect() no se registran
    assert registry.names() == ["plugin_collector"]
    plugin = registry.spec("plugin_collector")
    assert plugin.origin == "plugin:mi_plugin"
    assert registry.describe()[0]["kind"] == "plugin"
    assert any("dependencia ausente" in err for err in registry.errors)
    assert any("no expone collect()" in err for err in registry.errors)


# --- Tools genéricas del kernel ---


async def test_list_collectors_expone_el_catalogo(engine_env: Path):
    payload = json.loads(await call_tool_validated("list_collectors", {}))

    names = [c["name"] for c in payload["collectors"]]
    assert {"dns_collector", "github_forensics", "email_investigator"} <= set(names)
    assert payload["total"] == len(names)
    assert all(c["kind"] == "builtin" for c in payload["collectors"])
    assert payload["errors"] == []


async def test_run_collector_ingesta_y_sella_evidencia(engine_env: Path):
    import specter.server as specter_server

    specter_server.collectors.register(FakeCollector("plugin_test"))
    created = json.loads(
        await call_tool_validated("create_case", {"name": "Plugins", "description": "prueba"})
    )
    case_id = created["case_id"]

    try:
        result = json.loads(
            await call_tool_validated(
                "run_collector",
                {"case_id": case_id, "collector": "plugin_test", "target": "plugin.test"},
            )
        )

        assert result["status"] == "COMPLETED"
        assert result["entities_found"] == 1
        assert result["evidence_hash"] != "auto"

        entities = specter_server.db.get_case_entities(case_id)
        assert [e.id for e in entities] == ["domain:plugin.test"]

        blocks = specter_server.db.get_case_ledger(case_id)
        assert blocks[-1].action == "COLLECTOR_RUN: plugin_test -> plugin.test"
        assert blocks[-1].evidence_hash == result["evidence_hash"]

        evidence = specter_server.db.get_evidence(blocks[-1].evidence_id)
        assert evidence is not None
        assert evidence.metadata["collector_origin"] == "builtin"
    finally:
        specter_server.collectors.unregister("plugin_test")


async def test_run_collector_valida_caso_colector_y_fallos(engine_env: Path):
    import specter.server as specter_server

    created = json.loads(
        await call_tool_validated("create_case", {"name": "Errores", "description": "d"})
    )
    case_id = created["case_id"]

    unknown = json.loads(
        await call_tool_validated(
            "run_collector", {"case_id": case_id, "collector": "fantasma", "target": "x.test"}
        )
    )
    assert "no registrado" in unknown["error"]
    assert "dns_collector" in unknown["available"]

    missing_case = json.loads(
        await call_tool_validated(
            "run_collector",
            {"case_id": "case-nada", "collector": "dns_collector", "target": "x.test"},
        )
    )
    assert "no existe" in missing_case["error"]

    specter_server.collectors.register(ExplodingCollector())
    try:
        failed = json.loads(
            await call_tool_validated(
                "run_collector", {"case_id": case_id, "collector": "exploding", "target": "x.test"}
            )
        )
        assert failed == {"error": "Colector 'exploding' falló: fuente caída", "target": "x.test"}
        assert len(specter_server.db.get_case_ledger(case_id)) == 1  # sólo el génesis
    finally:
        specter_server.collectors.unregister("exploding")


async def test_run_collector_usa_un_colector_real_del_kernel(engine_env: Path, monkeypatch):
    """El catálogo no es decorativo: un built-in pasa por la ruta genérica completa."""
    patch_network(
        monkeypatch,
        MockRouter().add("GET", r"crdap|rdap", json={}),
        {"4.3.2.1.in-addr.arpa/ptr": ["host.example.com"]},
    )
    import specter.server as specter_server

    created = json.loads(
        await call_tool_validated("create_case", {"name": "IP", "description": "d"})
    )
    case_id = created["case_id"]

    result = json.loads(
        await call_tool_validated(
            "run_collector", {"case_id": case_id, "collector": "ip_enricher", "target": "1.2.3.4"}
        )
    )

    assert result["collector"] == "ip_enricher"
    assert result["entities_found"] == 2  # IP + PTR
    assert len(specter_server.db.get_case_ledger(case_id)) == 2


async def test_call_tool_validated_deniega_sensible_sin_regla(engine_env: Path):
    """La vía directa falla cerrado: sensible sin allow → ToolPermissionDenied."""
    from engine.registry import ToolPermissionDenied

    with pytest.raises(ToolPermissionDenied, match="PERMISSION_REQUIRED"):
        await call_tool_validated(
            "investigate_domain", {"case_id": "case-x", "target": "x.test"}
        )


async def test_call_tool_validated_segura_pasa(engine_env: Path):
    """La vía directa deja pasar tools SAFE sin regla explícita."""
    payload = json.loads(await call_tool_validated("list_collectors", {}))
    assert "collectors" in payload

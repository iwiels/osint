"""
Tests de specter.config: única fuente de verdad de rutas.
Invariante clave: las funciones leen el entorno en cada llamada (call-time),
lo que permite a tests y a la app empaquetada reconfigurar sin recargar.
"""

from __future__ import annotations

from pathlib import Path

from specter import config


def test_env_overrides_repo_defaults(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("SPECTER_REPORTS_DIR", str(tmp_path / "r"))
    monkeypatch.setenv("SPECTER_DB_PATH", str(tmp_path / "d" / "x.db"))

    assert config.database_path() == tmp_path / "d" / "x.db"
    assert config.data_dir() == tmp_path / "d"
    assert config.reports_dir() == tmp_path / "r"
    assert config.wmn_data_path() == tmp_path / "d" / "wmn-data.json"


def test_dirs_are_created_on_access(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "nuevo" / "data"))
    monkeypatch.setenv("SPECTER_REPORTS_DIR", str(tmp_path / "nuevo" / "reports"))

    assert config.data_dir().exists()
    assert config.reports_dir().exists()


def test_wmn_dataset_cae_al_bundle_en_la_app_empaquetada(tmp_path: Path, monkeypatch) -> None:
    """En la app instalada el data_dir (%APPDATA%) no trae el dataset: se usa el embebido."""
    data_dir = tmp_path / "appdata"
    monkeypatch.setenv("SPECTER_DATA_DIR", str(data_dir))
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.setattr(config.sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)

    # Sin dataset en el bundle, se devuelve igualmente la ruta del data_dir.
    assert config.wmn_data_path() == data_dir / "wmn-data.json"

    bundled = tmp_path / "bundle" / "data" / "wmn-data.json"
    bundled.parent.mkdir(parents=True)
    bundled.write_text('{"sites": []}', encoding="utf-8")
    assert config.wmn_data_path() == bundled

    # El dataset del usuario (si existe) tiene prioridad sobre el embebido.
    local = data_dir / "wmn-data.json"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text('{"sites": []}', encoding="utf-8")
    assert config.wmn_data_path() == local
    assert config.bundle_dir() == tmp_path / "bundle"


def test_ledger_key_resolution_order(tmp_path: Path, monkeypatch) -> None:
    """La clave de firma sale del entorno (hex o texto) o del archivo local."""
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.delenv("SPECTER_LEDGER_KEY_PATH", raising=False)

    monkeypatch.delenv("SPECTER_LEDGER_KEY", raising=False)
    assert config.ledger_signing_key() is None  # todavía no existe archivo

    monkeypatch.setenv("SPECTER_LEDGER_KEY", "abcdef01")
    assert config.ledger_signing_key() == b"\xab\xcd\xef\x01"

    monkeypatch.setenv("SPECTER_LEDGER_KEY", "clave-secreta")
    assert config.ledger_signing_key() == b"clave-secreta"


def test_ensure_ledger_key_generates_once(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.delenv("SPECTER_LEDGER_KEY", raising=False)
    monkeypatch.delenv("SPECTER_LEDGER_KEY_PATH", raising=False)

    generated = config.ensure_ledger_key()

    assert len(generated) == 32
    assert config.ledger_key_path() == tmp_path / "d" / "ledger.key"
    assert config.ledger_key_path().read_text(encoding="utf-8") == generated.hex()
    assert config.ledger_signing_key() == generated
    assert config.ensure_ledger_key() == generated  # idempotente: no rota la clave


def test_ledger_key_path_override_and_corrupt_file(tmp_path: Path, monkeypatch) -> None:
    custom = tmp_path / "custom.key"
    monkeypatch.setenv("SPECTER_LEDGER_KEY_PATH", str(custom))
    assert config.ledger_key_path() == custom

    monkeypatch.delenv("SPECTER_LEDGER_KEY", raising=False)
    custom.write_text("no-es-hexadecimal", encoding="utf-8")
    assert config.ledger_signing_key() is None  # archivo ilegible → ledger sin firmar


def test_call_time_resolution(tmp_path: Path, monkeypatch) -> None:
    """Cambiar el entorno entre llamadas cambia el resultado (sin recargar módulo)."""
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "a"))
    first = config.database_path()
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "b"))
    second = config.database_path()

    assert first != second

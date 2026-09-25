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


def test_call_time_resolution(tmp_path: Path, monkeypatch) -> None:
    """Cambiar el entorno entre llamadas cambia el resultado (sin recargar módulo)."""
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "a"))
    first = config.database_path()
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "b"))
    second = config.database_path()

    assert first != second

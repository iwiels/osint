"""
SpecterOSINT - Runtime Configuration
Única fuente de verdad para rutas de filesystem del motor.

Prioridad de resolución:
  1. Variables de entorno (SPECTER_DATA_DIR, SPECTER_REPORTS_DIR) — app
     empaquetada y tests.
  2. Raíz del repo, calculada desde este archivo (dev).

Las funciones leen el entorno *en cada llamada* (no en import-time) para que
tests y la app empaquetada puedan reconfigurar rutas sin recargar módulos.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _repo_root() -> Path:
    if getattr(sys, "frozen", False):  # PyInstaller onefile
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    """Directorio de datos (SQLite, datasets). Se crea si no existe."""
    env = os.environ.get("SPECTER_DATA_DIR")
    d = Path(env) if env else _repo_root() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def reports_dir() -> Path:
    """Directorio de dossiers generados. Se crea si no existe."""
    env = os.environ.get("SPECTER_REPORTS_DIR")
    d = Path(env) if env else _repo_root() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def database_path() -> Path:
    """Ruta de la base de datos forense."""
    env = os.environ.get("SPECTER_DB_PATH")
    return Path(env) if env else data_dir() / "specter_osint.db"


def wmn_data_path() -> Path:
    """Ruta del dataset WhatsMyName. Devuelve la ruta aunque no exista."""
    env = os.environ.get("SPECTER_DATA_DIR")
    base = Path(env) if env else _repo_root() / "data"
    return base / "wmn-data.json"

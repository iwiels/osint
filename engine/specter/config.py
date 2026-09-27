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


def bundle_dir() -> Path:
    """Directorio de recursos embebidos de la app empaquetada (PyInstaller onefile)."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    return Path(__file__).resolve().parents[2]


def wmn_data_path() -> Path:
    """Ruta del dataset WhatsMyName. Devuelve la ruta aunque no exista.

    Prioridad: data_dir (env o repo) → dataset embebido en el ejecutable. En la
    app instalada el data_dir apunta a %APPDATA% y no lleva el dataset, así que
    sin este fallback el app empaquetada se quedaría sin el barrido WhatsMyName.
    """
    env = os.environ.get("SPECTER_DATA_DIR")
    base = Path(env) if env else _repo_root() / "data"
    candidate = base / "wmn-data.json"
    if candidate.exists() or not getattr(sys, "frozen", False):
        return candidate
    bundled = bundle_dir() / "data" / "wmn-data.json"
    return bundled if bundled.exists() else candidate


def secrets_path() -> Path:
    """Ruta de la bóveda local de secretos (creada en el primer guardado)."""
    env = os.environ.get("SPECTER_SECRETS_PATH")
    return Path(env) if env else data_dir() / "secrets.json"


def ledger_key_path() -> Path:
    """Ruta de la clave HMAC que firma la cadena de custodia (no se versiona)."""
    env = os.environ.get("SPECTER_LEDGER_KEY_PATH")
    return Path(env) if env else data_dir() / "ledger.key"


def ledger_signing_key() -> bytes | None:
    """Clave HMAC del ledger: variable de entorno → archivo local → None.

    Sin clave el ledger sigue funcionando (modo sin firmar): la integridad
    SHA-256 se verifica igual, pero el dossier no puede sellarse ante terceros.
    Leer la clave *nunca* la genera: eso lo hace ensure_ledger_key() en el
    arranque de la app, para que importar el kernel no escriba en disco.
    """
    raw = os.environ.get("SPECTER_LEDGER_KEY")
    if raw:
        try:
            return bytes.fromhex(raw.strip())
        except ValueError:
            return raw.encode("utf-8")
    path = ledger_key_path()
    if not path.exists():
        return None
    try:
        return bytes.fromhex(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def ensure_ledger_key() -> bytes:
    """Devuelve la clave de firma generándola la primera vez (permisos 0600).

    En Windows el modo POSIX es informativo (el ACL del perfil ya restringe el
    acceso); en Linux/macOS el archivo queda legible sólo por el usuario.
    """
    import secrets

    existing = ledger_signing_key()
    if existing:
        return existing
    key = secrets.token_bytes(32)
    path = ledger_key_path()
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(key.hex())
    return key


def browser_url() -> str | None:
    """Obsoleto: el navegador sigiloso vive ahora en el engine (specter.stealth_browser).

    Se conserva porque tests/documentación antigua pueden referenciarlo; siempre
    devuelve None, de modo que cualquier ruta legada que lo compruebe caiga a su
    fallback HTTP sin intentar hablar con un puente que ya no existe.
    """
    return None

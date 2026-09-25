"""
Fixtures compartidas de la suite.

Patrón clave: el fixture `engine` redirige el almacenamiento del kernel a un
tmp_path vía variables de entorno + reset_services() (seam de testabilidad de
specter.server). Cada test arranca con una BD forense limpia y aislada,
sin tocar el disco del repo ni los datos reales.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ENGINE_DIR = REPO_ROOT / "engine"
for p in (str(REPO_ROOT), str(ENGINE_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture()
def engine_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Aísla data/reports/BD del test en tmp_path y reconstruye los servicios."""
    data_dir = tmp_path / "data"
    reports_dir = tmp_path / "reports"
    db_path = data_dir / "test.db"
    monkeypatch.setenv("SPECTER_DATA_DIR", str(data_dir))
    monkeypatch.setenv("SPECTER_REPORTS_DIR", str(reports_dir))
    monkeypatch.setenv("SPECTER_DB_PATH", str(db_path))

    from specter import server as specter_server

    specter_server.reset_services(db_path)
    yield db_path
    specter_server.reset_services()  # restaura estado global por defecto


@pytest.fixture()
def engine(engine_env: Path):
    """App FastAPI del engine lista para tests ASGI (sin sockets)."""
    import http_server  # noqa: import perezoso tras configurar el entorno

    http_server.db = specter_server_db(engine_env)
    return http_server


def specter_server_db(db_path: Path):
    """Expone la BD activa del kernel (tras reset_services)."""
    from specter import server as specter_server

    return specter_server.db

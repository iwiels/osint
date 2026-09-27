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
TESTS_DIR = Path(__file__).resolve().parent
for p in (str(REPO_ROOT), str(ENGINE_DIR), str(TESTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# Token Bearer que engine_env inyecta (ver fixture): los tests HTTP lo mandan
# en cada cliente httpx. Mantener en un solo lugar, no hardcodear por archivo.
TEST_ENGINE_TOKEN = "test-token"
TEST_AUTH_HEADERS = {"Authorization": f"Bearer {TEST_ENGINE_TOKEN}"}


@pytest.fixture(autouse=True)
def _ssrf_relaxed_in_tests(monkeypatch: pytest.MonkeyPatch):
    """NetGuard desactivado por defecto en tests (red mockeada, DNS falso).

    Los tests dedicados de SSRF reactivan la protección con
    SPECTER_SSRF_ENFORCE=1 y DNS stubbeado. Producción: siempre "1".
    """
    monkeypatch.setenv("SPECTER_SSRF_ENFORCE", "0")


@pytest.fixture()
def engine_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Aísla data/reports/BD del test en tmp_path y reconstruye los servicios."""
    data_dir = tmp_path / "data"
    reports_dir = tmp_path / "reports"
    db_path = data_dir / "test.db"
    monkeypatch.setenv("SPECTER_DATA_DIR", str(data_dir))
    monkeypatch.setenv("SPECTER_REPORTS_DIR", str(reports_dir))
    monkeypatch.setenv("SPECTER_DB_PATH", str(db_path))
    # C1: el middleware de auth exige Bearer en todo salvo /health; los tests
    # HTTP mandan este token en cada cliente ASGI.
    monkeypatch.setenv("SPECTER_ENGINE_TOKEN", TEST_ENGINE_TOKEN)

    from specter import server as specter_server

    specter_server.reset_services(db_path)
    yield db_path
    specter_server.reset_services()  # restaura estado global por defecto


@pytest.fixture()
def engine(engine_env: Path):
    """App FastAPI del engine lista para tests ASGI (sin sockets)."""
    import http_server  # noqa: E402

    http_server.db = specter_server_db(engine_env)
    return http_server


def specter_server_db(db_path: Path):
    """Expone la BD activa del kernel (tras reset_services)."""
    from specter import server as specter_server

    return specter_server.db

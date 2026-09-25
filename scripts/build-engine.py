"""
Empaqueta el motor Specter como ejecutable Windows onefile (PyInstaller).

Uso:
    .venv/Scripts/python.exe scripts/build-engine.py

Salida: dist-engine/specter-engine.exe
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist-engine"
BUILD = ROOT / "build-engine"


def main() -> None:
    DIST.mkdir(exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--name",
        "specter-engine",
        "--distpath",
        str(DIST),
        "--workpath",
        str(BUILD),
        "--specpath",
        str(BUILD),
        # data files embebidos (el exe los resuelve via SPECTER_DATA_DIR/sys._MEIPASS)
        "--add-data",
        f"{ROOT / 'data' / 'wmn-data.json'};data",
        "--hidden-import",
        "uvicorn.logging",
        "--hidden-import",
        "uvicorn.loops.auto",
        "--hidden-import",
        "uvicorn.protocols.http.auto",
        "--hidden-import",
        "uvicorn.protocols.websockets.auto",
        "--hidden-import",
        "uvicorn.lifespan.on",
        str(ROOT / "engine" / "http_server.py"),
    ]
    print("[specter] Empaquetando engine:", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=ROOT)
    print(f"[specter] OK -> {DIST / 'specter-engine.exe'}")


if __name__ == "__main__":
    main()

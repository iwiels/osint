"""
Empaqueta el motor Wraith como ejecutable onefile (PyInstaller).

Uso:
    .venv/Scripts/python.exe scripts/build-engine.py            # build real
    .venv/Scripts/python.exe scripts/build-engine.py --dry-run  # sólo preflight + comando
    .venv/Scripts/python.exe scripts/build-engine.py --clean    # limpia y construye

Salida: dist-engine/wraith-engine.exe (lo copia el instalador vía extraResources)

El ejecutable resuelve datos/reportes por variables de entorno (SPECTER_DATA_DIR,
SPECTER_REPORTS_DIR) y firma su cadena de custodia con `data/ledger.key` del
directorio de datos del usuario: los secretos y la clave del analista viven
fuera del bundle, así que sobreviven a las actualizaciones de la app.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist-engine"
BUILD = ROOT / "build-engine"
BINARY_NAME = "wraith-engine"
WMN_DATA = ROOT / "data" / "wmn-data.json"
ENTRY = ROOT / "engine" / "http_server.py"
TEMPLATES = ROOT / "engine" / "specter" / "visualizer" / "templates"
SKILLS = ROOT / "skills"
BUILD_INFO = ROOT / "engine" / "_build_info.py"

SEP = ";" if sys.platform == "win32" else ":"

# Uvicorn carga estos módulos por import dinámico: PyInstaller no los ve solo.
HIDDEN_IMPORTS = (
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
)


def preflight() -> list[str]:
    """Comprueba lo imprescindible antes de gastar minutos de build."""
    problems: list[str] = []
    if not ENTRY.exists():
        problems.append(f"falta el entrypoint: {ENTRY}")
    if not WMN_DATA.exists():
        problems.append(
            f"falta el dataset WhatsMyName: {WMN_DATA} "
            "(descárgalo o el barrido de usernames quedará vacío en la app instalada)"
        )
    if not TEMPLATES.is_dir():
        problems.append(
            f"faltan las plantillas del dossier: {TEMPLATES} "
            "(sin ellas export_case_dossier falla en la app instalada)"
        )
    if not SKILLS.is_dir() or not any(SKILLS.glob("*.md")):
        problems.append(
            f"faltan los playbooks de skills: {SKILLS} "
            "(sin ellos load_skill falla en la app instalada)"
        )
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        problems.append(
            "PyInstaller no está instalado en este intérprete: "
            "uv pip install '.[build]' (o pip install pyinstaller>=6.10)"
        )
    return problems


def build_command() -> list[str]:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--onefile",
        "--noconfirm",
        "--name",
        BINARY_NAME,
        "--distpath",
        str(DIST),
        "--workpath",
        str(BUILD),
        "--specpath",
        str(BUILD),
        # El kernel `specter` y `engine` NO están instalados como paquetes en el
        # venv (viven en el repo), así que PyInstaller necesita que se le digan
        # explícitamente dónde buscarlos y que recoja todos sus submódulos.
        "--paths",
        str(ROOT),
        "--paths",
        str(ROOT / "engine"),
        "--collect-submodules",
        "specter",
        "--collect-submodules",
        "engine",
        # curl_cffi lleva DLL nativa (libcurl-BoringSSL) + metadatos: sin esto
        # el exe falla en runtime al importar el transporte con impersonación.
        "--collect-all",
        "curl_cffi",
        # Datos embebidos: `specter.config.bundle_dir()` los resuelve en runtime.
        "--add-data",
        f"{WMN_DATA}{SEP}data",
        # El exportador resuelve sus plantillas con Path(__file__).parent/templates.
        "--add-data",
        f"{TEMPLATES}{SEP}specter/visualizer/templates",
        # Los playbooks se resuelven con specter.config.bundle_dir()/skills.
        "--add-data",
        f"{SKILLS}{SEP}skills",
    ]
    for module in HIDDEN_IMPORTS:
        cmd += ["--hidden-import", module]
    cmd.append(str(ENTRY))
    return cmd


def stamp_build_info() -> str:
    """Escribe engine/_build_info.py con el hash del código empaquetado.

    El /health del ejecutable lo reporta como build_hash: la UI puede
    mostrar exactamente qué código sirve cada binario. El fichero está en
    .gitignore (artefacto de build, no fuente).
    """
    import datetime

    try:
        commit = (
            subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=ROOT,
            ).stdout.strip()
            or "unknown"
        )
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=ROOT,
        ).stdout.strip()
        if dirty:
            commit += "-dirty"
    except (OSError, ValueError, subprocess.SubprocessError):
        commit = "unknown"
    BUILD_INFO.write_text(
        f'"""Artefacto de build (generado, no editar)."""\n\n'
        f"BUILD_HASH = {commit!r}\n"
        f"BUILD_TIME = {datetime.datetime.now(datetime.UTC).isoformat()!r}\n",
        encoding="utf-8",
    )
    return commit


def main() -> int:
    parser = argparse.ArgumentParser(description="Empaqueta el motor Wraith (PyInstaller)")
    parser.add_argument(
        "--dry-run", action="store_true", help="Sólo valida el entorno e imprime el comando"
    )
    parser.add_argument(
        "--clean", action="store_true", help="Borra dist-engine/ y build-engine/ antes de construir"
    )
    args = parser.parse_args()

    problems = preflight()
    if problems:
        for problem in problems:
            print(f"[wraith] ✗ {problem}", file=sys.stderr)
        return 1

    if args.clean:
        for path in (DIST, BUILD):
            if path.exists():
                shutil.rmtree(path)
                print(f"[wraith] limpiado {path}")

    DIST.mkdir(exist_ok=True)
    build_hash = stamp_build_info()
    print(f"[wraith] build_hash sellado: {build_hash}")
    cmd = build_command()
    print(f"[wraith] python: {sys.version.split()[0]} ({sys.executable})")
    print("[wraith] comando:", " ".join(cmd))

    if args.dry_run:
        print(f"[wraith] dry-run OK -> produciría {DIST / BINARY_NAME}")
        return 0

    subprocess.run(cmd, check=True, cwd=ROOT)
    binary = DIST / (BINARY_NAME + ".exe" if sys.platform == "win32" else BINARY_NAME)
    if not binary.exists():
        print(f"[wraith] ✗ el build terminó sin producir {binary}", file=sys.stderr)
        return 1
    print(f"[wraith] OK -> {binary} ({binary.stat().st_size // (1024 * 1024)} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

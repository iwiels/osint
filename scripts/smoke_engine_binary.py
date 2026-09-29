"""
Smoke test del binario del motor empaquetado (el artefacto que viaja en los instaladores).

Arranca el ejecutable con datos aislados y un token desechable, espera a /health,
comprueba que la autenticación se exige y crea un caso real (SQLite + ledger firmado),
y lo detiene. Lo ejecuta release.yml justo después de PyInstaller: un motor roto no
debe llegar nunca a un instalador.

Uso:
    python scripts/smoke_engine_binary.py [ruta/al/binario]

Sin argumentos usa dist-engine/wraith-engine(.exe). Solo depende de la biblioteca estándar.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = (
    ROOT / "dist-engine" / ("wraith-engine.exe" if sys.platform == "win32" else "wraith-engine")
)
STARTUP_TIMEOUT = 90  # el onefile se extrae al arrancar: en Windows con antivirus tarda


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(
    base: str, path: str, token: str | None = None, body: dict | None = None
) -> tuple[int, dict]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def stop(proc: subprocess.Popen) -> None:
    """Detiene el árbol de procesos: el onefile es un bootloader que lanza al motor."""
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def fail(message: str, log: Path | None = None) -> int:
    print(f"[wraith] ✗ {message}", file=sys.stderr)
    if log is not None and log.exists():
        tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-25:]
        print("[wraith] --- últimas líneas del motor ---\n" + "\n".join(tail), file=sys.stderr)
    return 1


def main() -> int:
    binary = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BINARY
    if not binary.is_file():
        return fail(f"no existe el binario: {binary}")

    port, token = free_port(), secrets.token_hex(16)
    base = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        log = work / "engine.log"
        # Mismo entorno con el que la app lanza el sidecar (desktop/src/main/sidecar.ts).
        env = {
            **os.environ,
            "SPECTER_ENGINE_TOKEN": token,
            "SPECTER_DATA_DIR": str(work / "data"),
            "SPECTER_REPORTS_DIR": str(work / "reports"),
        }
        with log.open("wb") as sink:
            proc = subprocess.Popen(
                [str(binary), "--port", str(port)], cwd=work, env=env, stdout=sink, stderr=sink
            )
        try:
            deadline = time.monotonic() + STARTUP_TIMEOUT
            health = None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    return fail(f"el motor terminó al arrancar (código {proc.returncode})", log)
                try:
                    status, body = request(base, "/health")
                    if status == 200:
                        health = body
                        break
                except OSError:
                    pass
                time.sleep(1)
            if health is None:
                return fail(f"el motor no respondió a /health en {STARTUP_TIMEOUT}s", log)
            if health.get("status") != "ok" or not health.get("mcp_tools"):
                return fail(f"/health inesperado: {health}", log)
            print(
                f"[wraith] health OK: v{health.get('version')} | tools MCP: {health['mcp_tools']}"
            )

            if request(base, "/cases")[0] != 401:
                return fail("/cases respondió sin token: la autenticación no se exige", log)
            print("[wraith] auth OK: sin token se rechaza (401)")

            status, created = request(
                base,
                "/cases",
                token,
                {"name": "Smoke binario", "description": "verificación del release"},
            )
            if status != 200 or created.get("status") != "CASE_CREATED":
                return fail(f"no se pudo crear un caso ({status}): {created}", log)
            status, ledger = request(base, f"/cases/{created['case_id']}/ledger", token)
            if status != 200:
                return fail(f"no se pudo leer el ledger del caso ({status})", log)
            print(f"[wraith] caso OK: {created['case_id']} (SQLite + ledger firmado)")
        finally:
            stop(proc)
    print("[wraith] smoke del binario OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

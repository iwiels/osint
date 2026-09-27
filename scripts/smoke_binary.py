"""
Smoke test del motor EMPAQUETADO (dist-engine/specter-engine.exe).

Arranca el ejecutable con un directorio de datos temporal y recorre el contrato
que consume Electron: salud, catálogo, caso, custodia sellada, atestación,
timeline, correlaciones, bóveda y **exportación de dossier** (que sólo funciona
si las plantillas Jinja viajaron dentro del bundle). Si algo falla, imprime el
log del proceso y sale con código 1.

Uso:
    .venv/Scripts/python.exe scripts/smoke_binary.py
    .venv/Scripts/python.exe scripts/smoke_binary.py --binary dist-engine/specter-engine.exe
    .venv/Scripts/python.exe scripts/smoke_binary.py --keep-data   # no borra el dir temporal
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = (
    ROOT / "dist-engine" / ("specter-engine.exe" if sys.platform == "win32" else "specter-engine")
)
START_TIMEOUT_SECONDS = 60.0


def wait_for_health(base_url: str, process: subprocess.Popen, deadline: float) -> dict:
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"el motor terminó con código {process.returncode}")
        try:
            response = httpx.get(f"{base_url}/health", timeout=3.0)
            if response.status_code == 200:
                return response.json()
            last_error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = str(exc)
        time.sleep(0.7)
    raise RuntimeError(f"/health no respondió a tiempo ({last_error})")


def stop(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            # Mata el árbol: el bootloader onefile lanza el proceso real.
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            process.terminate()
        process.wait(timeout=10)
    except (OSError, subprocess.SubprocessError):
        # El proceso ya no existe o no se pudo matar: no enmascarar el fallo real.
        process.kill()


def run_checks(client: httpx.Client, data_dir: Path) -> None:
    health = client.get("/health").json()
    print(f"health OK: {health['version']} | tools MCP: {health['mcp_tools']}")

    names = {tool["name"] for tool in client.get("/tools").json()["tools"]}
    for expected in (
        "create_case",
        "correlate_cases",
        "case_timeline",
        "attest_case_ledger",
        "list_collectors",
        "run_collector",
        "export_case_dossier",
    ):
        assert expected in names, f"tool ausente en el binario: {expected}"
    print(f"registry OK: {len(names)} tools")

    catalog = client.post("/tools/list_collectors/call", json={"arguments": {}}).json()
    assert catalog["result"]["total"] >= 9, catalog
    print(f"collectors OK: {catalog['result']['total']} en el catálogo")

    created = client.post(
        "/cases", json={"name": "Smoke binario", "description": "verificacion de release"}
    ).json()
    assert created["status"] == "CASE_CREATED", created
    case_id = created["case_id"]
    print(f"case OK: {case_id}")

    linked = client.post(
        "/tools/link_entities/call",
        json={
            "arguments": {
                "case_id": case_id,
                "source_id": "alias:smoke",
                "target_id": "domain:smoke.test",
                "relation_type": "CORRELATED_WITH",
            }
        },
    ).json()
    assert linked["result"]["status"] == "LINK_CREATED", linked

    ledger = client.get(f"/cases/{case_id}/ledger").json()
    assert ledger["valid"] is True and len(ledger["blocks"]) >= 2, ledger
    # En producción el motor genera su clave al arrancar: la cadena nace sellada.
    assert ledger["signature_status"] == "SEALED", ledger
    assert all(block["signature"] for block in ledger["blocks"]), ledger
    print(f"custodia OK: {len(ledger['blocks'])} bloques SEALED (key_id {ledger['key_id']})")

    attestation = client.get(f"/cases/{case_id}/attestation").json()
    assert attestation["sealed"] is True and attestation["attestation"]["signature"], attestation
    sig = attestation["attestation"]["signature"]
    print(f"atestación OK: {attestation['algorithm']} · {sig[:16]}…")

    timeline = client.get(f"/cases/{case_id}/timeline").json()
    assert timeline["total_events"] >= 3, timeline
    print(f"timeline OK: {timeline['total_events']} eventos")

    correlations = client.get(f"/cases/{case_id}/correlations").json()
    assert "cross_case" in correlations and "identity_candidates" in correlations
    print("correlaciones OK")

    vault = client.get("/settings/secrets").json()
    assert len(vault["secrets"]) == 3, vault
    print(f"bóveda OK: {vault['path']}")

    # La exportación del dossier prueba que las plantillas Jinja están embebidas.
    for fmt in ("html", "md"):
        exported = client.post(
            "/tools/export_case_dossier/call",
            json={"arguments": {"case_id": case_id, "format": fmt}},
        ).json()["result"]
        assert exported["status"] == "DOSSIER_EXPORTED", exported
        dossier = Path(exported["file_path"])
        assert dossier.exists() and dossier.stat().st_size > 0, dossier
        print(f"dossier {fmt} OK: {dossier.name} ({dossier.stat().st_size} bytes)")

    assert (data_dir / "ledger.key").exists(), "el binario no generó su clave de custodia"
    assert (data_dir / "specter_osint.db").exists(), "el binario no creó la base forense"
    print(f"datos OK: {data_dir} (ledger.key + base forense)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test del motor empaquetado")
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--port", type=int, default=8796)
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        print(
            f"[smoke] ✗ binario no encontrado: {binary}\n"
            "        constrúyelo primero: python scripts/build-engine.py",
            file=sys.stderr,
        )
        return 1

    base_url = f"http://127.0.0.1:{args.port}"
    workspace = Path(tempfile.mkdtemp(prefix="specter-smoke-"))
    data_dir = workspace / "data"
    reports_dir = workspace / "reports"
    data_dir.mkdir()
    reports_dir.mkdir()
    log_path = workspace / "engine.log"
    print(f"[smoke] binario: {binary} ({binary.stat().st_size // (1024 * 1024)} MB)")
    print(f"[smoke] datos:   {workspace}")

    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(binary), "--port", str(args.port)],
            env={
                **_minimal_env(),
                "SPECTER_DATA_DIR": str(data_dir),
                "SPECTER_REPORTS_DIR": str(reports_dir),
                "PYTHONUNBUFFERED": "1",
            },
            stdout=log,
            stderr=subprocess.STDOUT,
        )

    try:
        health = wait_for_health(base_url, process, time.monotonic() + START_TIMEOUT_SECONDS)
        print(f"[smoke] motor arriba en {base_url} (data_dir reportado: {health['data_dir']})")
        with httpx.Client(base_url=base_url, timeout=60) as client:
            run_checks(client, Path(health["data_dir"]))
    except Exception as exc:
        tail = log_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-15:]
        print(f"\n[smoke] ✗ FALLO: {exc}", file=sys.stderr)
        print("[smoke] --- últimas líneas del motor ---", file=sys.stderr)
        for line in tail:
            print(f"    {line}", file=sys.stderr)
        return 1
    finally:
        stop(process)
        if not args.keep_data:
            shutil.rmtree(workspace, ignore_errors=True)

    print("\nSMOKE DEL BINARIO COMPLETO: el motor empaquetado opera y sella su custodia\n")
    return 0


def _minimal_env() -> dict[str, str]:
    """Entorno mínimo: sin credenciales ni rutas del shell del desarrollador."""
    import os

    keep = (
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "PATHEXT",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
    )
    return {key: os.environ[key] for key in keep if key in os.environ}


if __name__ == "__main__":
    raise SystemExit(main())

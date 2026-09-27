"""
Genera packages/sdk/src/generated.ts desde el /openapi.json del engine.

Es la mitad ejecutable del contrato motor <-> UI: los response_model de
FastAPI describen las formas reales, este script las convierte en tipos
TypeScript y `npm run gen:sdk:check` (parte de `npm run verify`) falla si
el fichero generado no coincide — la deriva se vuelve ruidosa en CI en
vez de silenciosa en el canvas.

Uso:
    .venv/Scripts/python.exe scripts/gen_sdk_types.py            # regenera
    .venv/Scripts/python.exe scripts/gen_sdk_types.py --check    # solo verifica

El script levanta su propio engine efímero (puerto 8799, datos temporales)
para no depender del :8787 de desarrollo ni tocar la BD real.
"""

from __future__ import annotations

import argparse
import difflib
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "packages" / "sdk" / "src" / "generated.ts"
PORT = 8799

HEADER = """/**
 * GENERADO por scripts/gen_sdk_types.py — no editar a mano.
 * Fuente de verdad: response_model de FastAPI en engine/http_server.py
 * (modelos en engine/specter/osint_core/models.py).
 * Regenerar con: npm run gen:sdk
 */
"""

IDENT = "  "


def _ts_type(schema: dict, defs: dict) -> str:
    """Convierte un schema OpenAPI 3.1 (pydantic v2) a tipo TypeScript."""
    if not isinstance(schema, dict):
        return "unknown"
    if "$ref" in schema:
        return str(schema["$ref"]).rsplit("/", 1)[-1]
    if "enum" in schema:
        return " | ".join(json.dumps(v) for v in schema["enum"]) or "never"
    if "anyOf" in schema:
        return " | ".join(_ts_type(s, defs) for s in schema["anyOf"])
    if "allOf" in schema and len(schema["allOf"]) == 1:
        return _ts_type(schema["allOf"][0], defs)
    kind = schema.get("type")
    if kind == "array":
        return f"{_ts_type(schema.get('items', {}), defs)}[]"
    if kind == "object":
        props = schema.get("properties", {})
        if not props:
            values = schema.get("additionalProperties")
            if isinstance(values, dict):
                return f"Record<string, {_ts_type(values, defs)}>"
            return "Record<string, unknown>"
        required = set(schema.get("required", []))
        parts = []
        for name, sub in props.items():
            key = name if name.isidentifier() else json.dumps(name)
            mark = "" if name in required else "?"
            parts.append(f"{key}{mark}: {_ts_type(sub, defs)};")
        return "{ " + " ".join(parts) + " }"
    if kind == "integer" or kind == "number":
        return "number"
    if kind == "boolean":
        return "boolean"
    if kind == "string":
        return "string"
    if kind == "null":
        return "null"
    return "unknown"


def _emit(name: str, schema: dict, defs: dict) -> str:
    if "enum" in schema:
        return f"export type {name} = {_ts_type(schema, defs)};\n"
    if schema.get("type") == "object" or "properties" in schema:
        lines = [f"export interface {name} {{"]
        required = set(schema.get("required", []))
        for prop, sub in schema.get("properties", {}).items():
            key = prop if prop.isidentifier() else json.dumps(prop)
            mark = "" if prop in required else "?"
            lines.append(f"{IDENT}{key}{mark}: {_ts_type(sub, defs)};")
        lines.append("}\n")
        return "\n".join(lines)
    return f"export type {name} = {_ts_type(schema, defs)};\n"


def generate(spec: dict) -> str:
    defs = spec.get("components", {}).get("schemas", {})
    chunks = [HEADER.strip(), ""]
    for name in sorted(defs):
        chunks.append(_emit(name, defs[name], defs).rstrip())
        chunks.append("")
    return "\n".join(chunks).rstrip() + "\n"


class _EphemeralEngine:
    """Engine efímero para leer el contrato sin tocar el dev ni la BD real."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="specter-gen-")
        self.proc: subprocess.Popen | None = None

    def __enter__(self) -> str:
        import os

        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        env["SPECTER_DATA_DIR"] = str(Path(self.tmp.name) / "data")
        env["SPECTER_REPORTS_DIR"] = str(Path(self.tmp.name) / "reports")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "engine.http_server", "--port", str(PORT)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{PORT}"
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"{base}/health", timeout=3) as res:
                    if res.status == 200:
                        return base
            except OSError:
                pass
            if self.proc.poll() is not None:
                raise RuntimeError("el engine efímero murió al arrancar")
            time.sleep(1)
        raise RuntimeError("el engine efímero no respondió /health en 60s")

    def __exit__(self, *exc: object) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.tmp.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="Genera los tipos TS del SDK")
    parser.add_argument("--check", action="store_true", help="Falla si hay deriva")
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args()

    with (
        _EphemeralEngine() as base,
        urllib.request.urlopen(f"{base}/openapi.json", timeout=15) as res,
    ):
        spec = json.load(res)
    rendered = generate(spec)

    out = Path(args.out)
    if args.check:
        if not out.is_file():
            print(f"[specter] ✗ falta {out}: ejecuta npm run gen:sdk", file=sys.stderr)
            return 1
        current = out.read_text(encoding="utf-8")
        if current != rendered:
            diff = difflib.unified_diff(
                current.splitlines(),
                rendered.splitlines(),
                "generated.ts (repo)",
                "generated.ts (engine)",
                lineterm="",
            )
            print("[specter] ✗ deriva motor<->SDK detectada:", file=sys.stderr)
            print("\n".join(list(diff)[:40]), file=sys.stderr)
            print("[specter] ejecuta npm run gen:sdk y revisa el diff", file=sys.stderr)
            return 1
        print("[specter] contrato motor<->SDK sin deriva")
        return 0

    out.write_text(rendered, encoding="utf-8")
    print(f"[specter] OK -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

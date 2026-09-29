"""Every place that declares the project version must agree.

Releases are cut from a `vX.Y.Z` tag and the installers are named after
`desktop/package.json`, so a stale constant ships silently unless something
compares them: the engine reported 0.2.0 in /health for a 0.3.0 build.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from engine import ENGINE_VERSION

REPO_ROOT = Path(__file__).resolve().parents[1]
RENDERER_SRC = REPO_ROOT / "desktop" / "src" / "renderer"
_VERSION_LITERAL = re.compile(r"\bv\d+\.\d+\.\d+\b")


def _package_json_version(relative: str) -> str:
    return json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))["version"]


def test_all_version_declarations_agree() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        "pyproject.toml": pyproject["project"]["version"],
        "engine/__init__.py": ENGINE_VERSION,
        "package.json": _package_json_version("package.json"),
        "desktop/package.json": _package_json_version("desktop/package.json"),
        "packages/sdk/package.json": _package_json_version("packages/sdk/package.json"),
    }
    assert len(set(declared.values())) == 1, f"version declarations disagree: {declared}"


def test_renderer_does_not_hardcode_the_app_version() -> None:
    """The UI shows the packaged version (`__APP_VERSION__`), never a literal that goes stale."""
    offenders = [
        f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}"
        for path in sorted(RENDERER_SRC.rglob("*.ts*"))
        if path.suffix in {".ts", ".tsx"} and ".test." not in path.name
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if _VERSION_LITERAL.search(line)
    ]
    assert not offenders, f"hard-coded version literals, use __APP_VERSION__: {offenders}"

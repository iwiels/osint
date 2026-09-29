"""Presupuestos de tiempo de la búsqueda web.

REGRESIÓN: `parallel_search` envolvía cada consulta en un `wait_for(25s)`
mientras que un solo motor podía consumir ~28s (goto 25s + settle + parse), y
el fallback HTTP de DDG añadía hasta 25s más en serie. El presupuesto externo
era MENOR que el peor caso interno, así que cualquier motor lento expiraba la
consulta entera y se perdían también los resultados de los motores que sí
funcionaban. El agente lo leía como "motores saturados" y repetía la búsqueda.

Estos tests fijan la RELACIÓN entre los presupuestos: el externo tiene que
poder contener al peor caso interno, o el trabajo se tira a la basura.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from specter.collectors import web as web_mod
from specter.stealth_browser import SEARCH_TIMEOUT_MS, SETTLE_DELAY_S

ENGINE_SRC = Path(__file__).resolve().parents[1] / "engine" / "specter" / "server.py"


def _parallel_search_defaults() -> tuple[float, float]:
    """Extrae el timeout por defecto de la firma de `parallel_search`."""
    tree = ast.parse(ENGINE_SRC.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "parallel_search":
            names = [a.arg for a in node.args.args]
            assert "timeout_s" in names, "parallel_search debe exponer timeout_s"
            # `args.defaults` se alinea a la DERECHA con los argumentos que
            # tienen valor por defecto: son los últimos N de `names`.
            with_default = names[len(names) - len(node.args.defaults) :]
            offset = with_default.index("timeout_s")
            default = node.args.defaults[offset]
            assert isinstance(default, ast.Constant), "timeout_s debe ser un literal"
            return float(default.value), 120.0
    pytest.fail("no se encontró parallel_search en server.py")


def test_timeout_externo_cubre_el_peor_caso_interno() -> None:
    """El presupuesto de `parallel_search` debe contener el peor caso real.

    Peor caso = motores en paralelo (navegación + settle + parse) + el
    fallback HTML de DDG, que corre en serie después.
    """
    outer, _cap = _parallel_search_defaults()

    # Por motor: navegación + settle + un margen para parse/bloqueo.
    per_engine = (SEARCH_TIMEOUT_MS / 1000) + SETTLE_DELAY_S + 3.0
    worst_case = per_engine + web_mod.DDG_HTML_TIMEOUT

    assert outer >= worst_case, (
        f"presupuesto externo ({outer}s) < peor caso interno ({worst_case:.1f}s): "
        "la consulta se expiraría aunque los motores dieran resultados"
    )


def test_timeout_de_serp_es_snappy() -> None:
    """Navegar una SERP debe tener un presupuesto corto.

    Una página de resultados carga rápido o no carga. Con 25s por motor, un
    solo motor lento consumía el presupuesto entero del llamante.
    """
    assert SEARCH_TIMEOUT_MS <= 15_000, (
        f"SEARCH_TIMEOUT_MS={SEARCH_TIMEOUT_MS} es demasiado holgado para una SERP"
    )


def test_fallback_ddg_no_come_el_presupuesto_entero() -> None:
    """El fallback HTML es una red de seguridad, no la vía principal."""
    assert web_mod.DDG_HTML_TIMEOUT <= 10.0
    assert web_mod.DDG_HTML_TIMEOUT < web_mod.SEARCH_TIMEOUT


def test_timeout_error_reporta_mensaje_util() -> None:
    """`str(TimeoutError())` es vacío: el error debe explicar el presupuesto.

    Sin esto el agente veía "TimeoutError: " y no distinguía saturación de red
    de un fallo real, así que repetía la misma búsqueda sin cambiar nada.
    """
    source = inspect.getsource(_parallel_search_fn())
    assert "except TimeoutError" in source
    # El mensaje debe mentioning el presupuesto, no ser un error vacío.
    assert "presupuesto" in source


def _parallel_search_fn():  # type: ignore[no-untyped-def]
    from specter.server import parallel_search

    return parallel_search

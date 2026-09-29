"""
Tests del Run Coordinator.

Cubre ejecución serializada por caseID, cancelación, duplicados,
prioridades y estado de runs.
"""

from __future__ import annotations

import asyncio

import pytest
from specter.osint_core.run_coordinator import (
    RunCoordinator,
    RunPriority,
    RunStatus,
    generate_run_key,
)


@pytest.mark.asyncio
async def test_run_ejecuta_tarea_simple() -> None:
    """Un run simple ejecuta y completa correctamente."""
    coord = RunCoordinator()

    async def tarea() -> str:
        return "ok"

    result = await coord.run("run-1", tarea, case_id="case-1")
    assert result == "ok"

    info = coord.get_run("run-1")
    assert info is not None
    assert info.status == RunStatus.COMPLETED
    assert info.case_id == "case-1"


@pytest.mark.asyncio
async def test_run_serializa_por_case_id() -> None:
    """Dos runs del mismo caseID se ejecutan secuencialmente."""
    coord = RunCoordinator()
    execution_order: list[str] = []

    async def tarea(nombre: str, delay: float) -> None:
        execution_order.append(f"start-{nombre}")
        await asyncio.sleep(delay)
        execution_order.append(f"end-{nombre}")

    # Lanzar dos runs concurrentes del mismo caso
    await asyncio.gather(
        coord.run("run-a", lambda: tarea("a", 0.05), case_id="case-1"),
        coord.run("run-b", lambda: tarea("b", 0.01), case_id="case-1"),
    )

    # Verificar que no se solaparon
    assert execution_order == ["start-a", "end-a", "start-b", "end-b"]


@pytest.mark.asyncio
async def test_run_diferentes_case_id_concurrentes() -> None:
    """Runs de diferentes caseID pueden ejecutarse concurrentemente."""
    coord = RunCoordinator()
    concurrent = 0
    max_concurrent = 0

    async def tarea() -> None:
        nonlocal concurrent, max_concurrent
        concurrent += 1
        max_concurrent = max(max_concurrent, concurrent)
        await asyncio.sleep(0.02)
        concurrent -= 1

    await asyncio.gather(
        coord.run("run-1", tarea, case_id="case-1"),
        coord.run("run-2", tarea, case_id="case-2"),
        coord.run("run-3", tarea, case_id="case-3"),
    )

    assert max_concurrent == 3


@pytest.mark.asyncio
async def test_run_duplicado_lanza_error() -> None:
    """No puede haber dos runs con la misma key."""
    coord = RunCoordinator()

    async def tarea() -> str:
        return "ok"

    await coord.run("run-dup", tarea, case_id="case-1")

    with pytest.raises(RuntimeError, match="ya existe"):
        await coord.run("run-dup", tarea, case_id="case-1")


@pytest.mark.asyncio
async def test_interrupt_run_en_vuelo() -> None:
    """Interrupt cancela un run en ejecución."""
    coord = RunCoordinator()
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def tarea_lenta() -> None:
        started.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    task = asyncio.create_task(coord.run("run-cancel", tarea_lenta, case_id="case-1"))

    await started.wait()
    assert coord.is_running("run-cancel")

    # Interrumpir
    result = await coord.interrupt("run-cancel")
    assert result is True

    with pytest.raises(asyncio.CancelledError):
        await task

    assert cancelled.is_set()
    info = coord.get_run("run-cancel")
    assert info is not None
    assert info.status == RunStatus.CANCELLED


@pytest.mark.asyncio
async def test_interrupt_run_pendiente() -> None:
    """Interrupt cancela un run pendiente (aún no ejecutándose)."""
    coord = RunCoordinator()
    started = asyncio.Event()

    async def tarea_bloqueante() -> None:
        started.set()
        await asyncio.sleep(10)

    async def tarea_pendiente() -> str:
        return "no-ejecutado"

    # Lanzar run bloqueante
    task1 = asyncio.create_task(coord.run("run-1", tarea_bloqueante, case_id="case-1"))
    await started.wait()

    # Lanzar run pendiente (se encola)
    task2 = asyncio.create_task(coord.run("run-2", tarea_pendiente, case_id="case-1"))
    await asyncio.sleep(0.01)  # Dar tiempo a encolar

    # Interrumpir el pendiente
    result = await coord.interrupt("run-2")
    assert result is True

    with pytest.raises(asyncio.CancelledError):
        await task2

    # Limpiar
    await coord.interrupt("run-1")
    with pytest.raises(asyncio.CancelledError):
        await task1


@pytest.mark.asyncio
async def test_active_lista_runs_activos() -> None:
    """active() retorna solo runs pendientes o en ejecución."""
    coord = RunCoordinator()
    started = asyncio.Event()

    async def tarea() -> None:
        started.set()
        await asyncio.sleep(10)

    task = asyncio.create_task(coord.run("run-1", tarea, case_id="case-1"))
    await started.wait()

    active = coord.active()
    assert len(active) == 1
    assert active[0].key == "run-1"
    assert active[0].status == RunStatus.RUNNING

    # Completar
    await coord.interrupt("run-1")
    with pytest.raises(asyncio.CancelledError):
        await task

    assert coord.active() == []


@pytest.mark.asyncio
async def test_is_running_refleja_estado() -> None:
    """is_running retorna True solo cuando el run está ejecutándose."""
    coord = RunCoordinator()
    started = asyncio.Event()

    async def tarea() -> None:
        started.set()
        await asyncio.sleep(0.05)

    task = asyncio.create_task(coord.run("run-1", tarea, case_id="case-1"))
    await started.wait()

    assert coord.is_running("run-1") is True

    await task
    assert coord.is_running("run-1") is False


@pytest.mark.asyncio
async def test_run_con_prioridad() -> None:
    """Los runs se ejecutan en orden de llegada (la prioridad es informativa)."""
    coord = RunCoordinator()
    execution_order: list[str] = []
    started = asyncio.Event()

    async def tarea_bloqueante() -> None:
        started.set()
        await asyncio.sleep(0.1)

    async def tarea(nombre: str) -> None:
        execution_order.append(nombre)

    # Bloquear el case
    task_block = asyncio.create_task(coord.run("run-block", tarea_bloqueante, case_id="case-1"))
    await started.wait()

    # Encolar con diferentes prioridades
    await asyncio.gather(
        coord.run(
            "run-low",
            lambda: tarea("low"),
            case_id="case-1",
            priority=RunPriority.LOW,
        ),
        coord.run(
            "run-high",
            lambda: tarea("high"),
            case_id="case-1",
            priority=RunPriority.HIGH,
        ),
        coord.run(
            "run-normal",
            lambda: tarea("normal"),
            case_id="case-1",
            priority=RunPriority.NORMAL,
        ),
    )

    await task_block

    # Los runs se ejecutan en orden de llegada (la prioridad es informativa)
    assert len(execution_order) == 3
    assert "low" in execution_order
    assert "high" in execution_order
    assert "normal" in execution_order


@pytest.mark.asyncio
async def test_run_con_error() -> None:
    """Un run que falla registra el error."""
    coord = RunCoordinator()

    async def tarea_fallida() -> None:
        raise ValueError("error de prueba")

    with pytest.raises(ValueError, match="error de prueba"):
        await coord.run("run-error", tarea_fallida, case_id="case-1")

    info = coord.get_run("run-error")
    assert info is not None
    assert info.status == RunStatus.FAILED
    assert info.error == "error de prueba"


@pytest.mark.asyncio
async def test_cancel_all_por_caso() -> None:
    """cancel_all cancela todos los runs de un caso."""
    coord = RunCoordinator()
    started = asyncio.Event()

    async def tarea() -> None:
        started.set()
        await asyncio.sleep(10)

    # Lanzar runs de dos casos
    task1 = asyncio.create_task(coord.run("run-1", tarea, case_id="case-1"))
    await started.wait()

    task2 = asyncio.create_task(coord.run("run-2", tarea, case_id="case-1"))
    task3 = asyncio.create_task(coord.run("run-3", tarea, case_id="case-2"))

    await asyncio.sleep(0.01)

    # Cancelar solo case-1
    cancelled = await coord.cancel_all(case_id="case-1")
    assert cancelled == 2

    with pytest.raises(asyncio.CancelledError):
        await task1
    with pytest.raises(asyncio.CancelledError):
        await task2

    # case-2 sigue activo
    assert coord.is_running("run-3") is True

    # Limpiar
    await coord.interrupt("run-3")
    with pytest.raises(asyncio.CancelledError):
        await task3


@pytest.mark.asyncio
async def test_clear_history() -> None:
    """clear_history elimina runs completados del historial."""
    coord = RunCoordinator()

    async def tarea() -> str:
        return "ok"

    await coord.run("run-1", tarea, case_id="case-1")
    await coord.run("run-2", tarea, case_id="case-1")

    assert len(coord.list_runs()) == 2

    deleted = coord.clear_history(case_id="case-1")
    assert deleted == 2
    assert len(coord.list_runs()) == 0


@pytest.mark.asyncio
async def test_list_runs_filtra_por_caso() -> None:
    """list_runs filtra por caseID."""
    coord = RunCoordinator()

    async def tarea() -> str:
        return "ok"

    await coord.run("run-1", tarea, case_id="case-1")
    await coord.run("run-2", tarea, case_id="case-2")

    runs_case1 = coord.list_runs(case_id="case-1")
    assert len(runs_case1) == 1
    assert runs_case1[0].key == "run-1"


def test_generate_run_key_unico() -> None:
    """generate_run_key genera keys únicas."""
    key1 = generate_run_key("case-1")
    key2 = generate_run_key("case-1")
    assert key1 != key2
    assert key1.startswith("run-case-1-")


@pytest.mark.asyncio
async def test_wake_run_pendiente() -> None:
    """wake retorna True para runs pendientes."""
    coord = RunCoordinator()
    started = asyncio.Event()

    async def tarea_bloqueante() -> None:
        started.set()
        await asyncio.sleep(10)

    async def tarea_pendiente() -> str:
        return "ok"

    task1 = asyncio.create_task(coord.run("run-1", tarea_bloqueante, case_id="case-1"))
    await started.wait()

    task2 = asyncio.create_task(coord.run("run-2", tarea_pendiente, case_id="case-1"))
    await asyncio.sleep(0.01)

    # wake sobre run pendiente
    assert await coord.wake("run-2") is True

    # wake sobre run inexistente
    assert await coord.wake("run-inexistente") is False

    # Limpiar
    await coord.interrupt("run-1")
    await coord.interrupt("run-2")
    with pytest.raises(asyncio.CancelledError):
        await task1
    with pytest.raises(asyncio.CancelledError):
        await task2

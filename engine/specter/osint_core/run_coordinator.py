"""
WraithOSINT - Run Coordinator
Coordinador de ejecución por sesión inspirado en OpenCode.

Serializa la ejecución por caseID, evita duplicados, permite cancelar
runs en vuelo y reporta el estado de cada run.
"""

from __future__ import annotations

import asyncio
import enum
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


class RunStatus(enum.StrEnum):
    """Estados posibles de un run coordinado."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunPriority(int, enum.Enum):
    """Prioridades declarativas de ejecución.

    El valor es informativo: el coordinador serializa por caseID y el orden
    real es el de llegada. Se conserva para que el agente pueda etiquetar la
    urgencia y el registro de runs la muestre.
    """

    LOW = 3
    NORMAL = 2
    HIGH = 1
    CRITICAL = 0


@dataclass
class RunInfo:
    """Información de un run coordinado."""

    key: str
    case_id: str
    status: RunStatus
    priority: RunPriority
    created_at: str
    started_at: str | None = None
    ended_at: str | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class RunCoordinator:
    """Coordinador de ejecución por sesión.

    Serializa la ejecución por caseID con un lock por caso: solo un run
    activo a la vez. Los runs adicionales esperan su turno y se ejecutan
    cuando el activo termina. Un run cancelado lanza CancelledError.
    """

    def __init__(self) -> None:
        self._runs: dict[str, RunInfo] = {}
        self._cancel_flags: dict[str, asyncio.Event] = {}
        self._tasks: dict[str, asyncio.Task[Any]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, case_id: str) -> asyncio.Lock:
        """Lock por caseID (lazy init)."""
        if case_id not in self._locks:
            self._locks[case_id] = asyncio.Lock()
        return self._locks[case_id]

    async def run(
        self,
        key: str,
        drain: Callable[[], Awaitable[Any]],
        *,
        case_id: str = "",
        priority: RunPriority = RunPriority.NORMAL,
        metadata: dict[str, Any] | None = None,
    ) -> Any:
        """Ejecuta una tarea con coordinación.

        Args:
            key: Identificador único del run.
            drain: Callable async que ejecuta la tarea real.
            case_id: ID del caso (serialización por caso).
            priority: Prioridad declarativa del run.
            metadata: Metadatos adicionales del run.

        Returns:
            El resultado de drain().

        Raises:
            asyncio.CancelledError: Si el run es cancelado.
            RuntimeError: Si el key ya existe.
        """
        if key in self._runs:
            raise RuntimeError(f"Run {key} ya existe")

        info = RunInfo(
            key=key,
            case_id=case_id,
            status=RunStatus.PENDING,
            priority=priority,
            created_at=datetime.now(UTC).isoformat(),
            metadata=metadata or {},
        )
        self._runs[key] = info
        cancel_flag = asyncio.Event()
        self._cancel_flags[key] = cancel_flag
        lock = self._get_lock(case_id)

        async def _execute() -> Any:
            async with lock:
                # Comprobamos la cancelación al adquirir el lock: si el run se
                # canceló mientras esperaba turno, no ejecuta nada.
                if cancel_flag.is_set():
                    info.status = RunStatus.CANCELLED
                    info.ended_at = datetime.now(UTC).isoformat()
                    raise asyncio.CancelledError(f"Run {key} cancelado antes de ejecutar")

                info.status = RunStatus.RUNNING
                info.started_at = datetime.now(UTC).isoformat()

                try:
                    result = await drain()
                    info.status = RunStatus.COMPLETED
                    return result
                except asyncio.CancelledError:
                    info.status = RunStatus.CANCELLED
                    raise
                except Exception as exc:
                    info.status = RunStatus.FAILED
                    info.error = str(exc)
                    raise
                finally:
                    info.ended_at = datetime.now(UTC).isoformat()

        task = asyncio.create_task(_execute())
        self._tasks[key] = task

        try:
            return await task
        finally:
            self._tasks.pop(key, None)
            self._cancel_flags.pop(key, None)

    async def wake(self, key: str) -> bool:
        """Indica si el run existe y sigue pendiente de ejecutar."""
        info = self._runs.get(key)
        return info is not None and info.status == RunStatus.PENDING

    async def interrupt(self, key: str) -> bool:
        """Interrumpe un run en vuelo o pendiente.

        Returns:
            True si el run existía y fue marcado para cancelación.
        """
        info = self._runs.get(key)
        if not info:
            return False

        cancel_flag = self._cancel_flags.get(key)
        if cancel_flag:
            cancel_flag.set()

        task = self._tasks.get(key)
        if task and not task.done():
            task.cancel()

        if info.status in (RunStatus.RUNNING, RunStatus.PENDING):
            info.status = RunStatus.CANCELLED
            info.ended_at = datetime.now(UTC).isoformat()
            return True
        return False

    def active(self) -> list[RunInfo]:
        """Lista runs activos (pendientes o en ejecución)."""
        return [
            info
            for info in self._runs.values()
            if info.status in (RunStatus.PENDING, RunStatus.RUNNING)
        ]

    def is_running(self, key: str) -> bool:
        """Verifica si un run está en ejecución."""
        info = self._runs.get(key)
        return info is not None and info.status == RunStatus.RUNNING

    def get_run(self, key: str) -> RunInfo | None:
        """Obtiene la información de un run."""
        return self._runs.get(key)

    def list_runs(self, case_id: str | None = None) -> list[RunInfo]:
        """Lista runs, opcionalmente filtrados por caseID."""
        runs = list(self._runs.values())
        if case_id:
            runs = [r for r in runs if r.case_id == case_id]
        return sorted(runs, key=lambda r: r.created_at, reverse=True)

    def is_cancelled(self, key: str) -> bool:
        """Verifica si un run fue cancelado (para chequeo cooperativo)."""
        flag = self._cancel_flags.get(key)
        return flag is not None and flag.is_set()

    async def cancel_all(self, case_id: str | None = None) -> int:
        """Cancela todos los runs activos (opcionalmente de un caso).

        Returns:
            Número de runs cancelados.
        """
        cancelled = 0
        for key, info in list(self._runs.items()):
            if case_id and info.case_id != case_id:
                continue
            if info.status in (RunStatus.PENDING, RunStatus.RUNNING) and await self.interrupt(key):
                cancelled += 1
        return cancelled

    def clear_history(self, case_id: str | None = None) -> int:
        """Limpia el historial de runs ya terminados.

        Returns:
            Número de runs eliminados del historial.
        """
        to_remove = [
            key
            for key, info in self._runs.items()
            if (not case_id or info.case_id == case_id)
            and info.status in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED)
        ]
        for key in to_remove:
            del self._runs[key]
        return len(to_remove)


# Instancia global del coordinador
coordinator = RunCoordinator()


def generate_run_key(case_id: str, prefix: str = "run") -> str:
    """Genera una key única para un run."""
    return f"{prefix}-{case_id}-{uuid.uuid4().hex[:8]}"

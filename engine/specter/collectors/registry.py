"""
SpecterOSINT - Collector Registry
Catálogo de colectores: los built-ins del kernel + plugins de terceros.

Un plugin se declara en el `pyproject.toml` de su paquete:

    [project.entry-points."specter.collectors"]
    mi_fuente = "mi_paquete.colectores:MiColector"

El kernel descubre esos entry-points al arrancar y los expone con las tools
genéricas `list_collectors` / `run_collector`, sin tocar el código del kernel:
ingesta en el grafo y sello en la cadena de custodia son responsabilidad del
kernel, no del plugin.

Un plugin roto **no** impide arrancar: el error se registra en `errors` y el
resto del catálogo sigue operativo.
"""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass, field
from typing import Any

from specter.collectors.base import BaseCollector
from specter.collectors.threatintel_enhanced import (
    CensysCollector,
    HaveIBeenPwnedCollector,
    ShodanCollector,
    VirusTotalCollector,
)

ENTRY_POINT_GROUP = "specter.collectors"
BUILTIN_ORIGIN = "builtin"

ENHANCED_COLLECTORS = (
    ShodanCollector,
    CensysCollector,
    VirusTotalCollector,
    HaveIBeenPwnedCollector,
)


@dataclass(frozen=True)
class CollectorSpec:
    name: str
    instance: Any
    origin: str


@dataclass
class CollectorRegistry:
    _collectors: dict[str, CollectorSpec] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def register(self, instance: Any, origin: str = BUILTIN_ORIGIN) -> CollectorSpec:
        """Registra un colector (instancia o clase) bajo su `name`."""
        if isinstance(instance, type):
            instance = instance()
        name = getattr(instance, "name", None) or type(instance).__name__
        spec = CollectorSpec(name=str(name), instance=instance, origin=origin)
        self._collectors[spec.name] = spec
        return spec

    def register_enhanced_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores avanzados (Shodan, Censys, VirusTotal, HIBP)."""
        return [self.register(cls(), origin=origin) for cls in ENHANCED_COLLECTORS]

    def unregister(self, name: str) -> bool:
        return self._collectors.pop(name, None) is not None

    def spec(self, name: str) -> CollectorSpec:
        spec = self._collectors.get(name)
        if spec is None:
            raise KeyError(name)
        return spec

    def get(self, name: str) -> Any:
        return self.spec(name).instance

    def __contains__(self, name: object) -> bool:
        return name in self._collectors

    def __len__(self) -> int:
        return len(self._collectors)

    def names(self) -> list[str]:
        return sorted(self._collectors)

    def describe(self) -> list[dict[str, Any]]:
        """Catálogo serializable para la UI y el agente."""
        return [
            {
                "name": spec.name,
                "origin": spec.origin,
                "class": type(spec.instance).__name__,
                "kind": "plugin" if spec.origin.startswith("plugin:") else "builtin",
            }
            for spec in sorted(self._collectors.values(), key=lambda s: s.name)
        ]

    def load_entry_points(self, group: str = ENTRY_POINT_GROUP) -> list[str]:
        """Descubre y registra colectores externos. Devuelve los nombres cargados."""
        loaded: list[str] = []
        for entry in importlib.metadata.entry_points(group=group):
            try:
                target = entry.load()
                instance = target() if isinstance(target, type) else target
                if not isinstance(instance, BaseCollector) and not hasattr(instance, "collect"):
                    raise TypeError(f"{entry.value} no expone collect()")  # noqa: TRY301
            except Exception as exc:  # un plugin roto no debe tumbar el kernel
                self.errors.append(f"{entry.name}: {exc}")
                continue
            self.register(instance, origin=f"plugin:{entry.name}")
            loaded.append(str(entry.name))
        return loaded


def create_default_registry() -> CollectorRegistry:
    """Crea una instancia de CollectorRegistry con los colectores base registrados."""
    from specter.collectors.attack_surface import AttackSurfaceCollector

    reg = CollectorRegistry()
    reg.register(AttackSurfaceCollector())
    return reg


default_registry = create_default_registry()

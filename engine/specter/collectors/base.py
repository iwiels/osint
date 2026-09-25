"""
SpecterOSINT - Base Collector
Interfaz abstracta para todos los módulos de recolección de inteligencia.
"""

from abc import ABC, abstractmethod
from typing import Any

from specter.osint_core.models import CollectorResult


class BaseCollector(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def collect(self, target: str, **kwargs: Any) -> CollectorResult:
        """
        Ejecuta la recolección contra el objetivo y retorna un CollectorResult
        con entidades, relaciones y el payload crudo para la cadena de custodia.
        """
        pass

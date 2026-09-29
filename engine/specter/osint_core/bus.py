"""
SpecterOSINT - Command/Query Buses (CQRS)
Buses que despachan comandos y queries a sus respectivos handlers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from specter.osint_core.commands import Command, CommandResult
from specter.osint_core.queries import Query, QueryResult

# Type variables para handlers
CommandHandler = Callable[[Command], Any]
QueryHandler = Callable[[Query], Any]


class CommandBus:
    """
    Bus de comandos: despacha comandos a sus handlers registrados.

    Patrón CQRS: los comandos mutan estado y pasan por este bus.
    """

    def __init__(self):
        self._handlers: dict[type[Command], CommandHandler] = {}
        self._middleware: list[Callable[[Command], None]] = []

    def register_handler(self, command_type: type[Command], handler: CommandHandler) -> None:
        """Registra un handler para un tipo de comando."""
        self._handlers[command_type] = handler

    def add_middleware(self, middleware: Callable[[Command], None]) -> None:
        """Añade middleware que se ejecuta antes de cada comando."""
        self._middleware.append(middleware)

    async def dispatch(self, command: Command) -> CommandResult:
        """
        Despacha un comando a su handler registrado.

        Args:
            command: Comando a ejecutar

        Returns:
            CommandResult con el resultado de la ejecución

        Raises:
            ValueError: Si no hay handler registrado para el tipo de comando
        """
        command_type = type(command)

        # Ejecutar middleware
        for mw in self._middleware:
            mw(command)

        # Buscar handler
        handler = self._handlers.get(command_type)
        if not handler:
            raise ValueError(f"No hay handler registrado para {command_type.__name__}")

        # Ejecutar handler
        result = handler(command)
        if hasattr(result, "__await__"):
            result = await result

        return result

    def has_handler(self, command_type: type[Command]) -> bool:
        """Verifica si hay un handler registrado para un tipo de comando."""
        return command_type in self._handlers

    def unregister_handler(self, command_type: type[Command]) -> None:
        """Elimina el handler registrado para un tipo de comando."""
        self._handlers.pop(command_type, None)


class QueryBus:
    """
    Bus de queries: despacha queries a sus handlers registrados.

    Patrón CQRS: las queries leen estado sin mutar nada.
    """

    def __init__(self):
        self._handlers: dict[type[Query], QueryHandler] = {}
        self._middleware: list[Callable[[Query], None]] = []

    def register_handler(self, query_type: type[Query], handler: QueryHandler) -> None:
        """Registra un handler para un tipo de query."""
        self._handlers[query_type] = handler

    def add_middleware(self, middleware: Callable[[Query], None]) -> None:
        """Añade middleware que se ejecuta antes de cada query."""
        self._middleware.append(middleware)

    async def dispatch(self, query: Query) -> QueryResult:
        """
        Despacha una query a su handler registrado.

        Args:
            query: Query a ejecutar

        Returns:
            QueryResult con el resultado de la ejecución

        Raises:
            ValueError: Si no hay handler registrado para el tipo de query
        """
        query_type = type(query)

        # Ejecutar middleware
        for mw in self._middleware:
            mw(query)

        # Buscar handler
        handler = self._handlers.get(query_type)
        if not handler:
            raise ValueError(f"No hay handler registrado para {query_type.__name__}")

        # Ejecutar handler
        result = handler(query)
        if hasattr(result, "__await__"):
            result = await result

        return result

    def has_handler(self, query_type: type[Query]) -> bool:
        """Verifica si hay un handler registrado para un tipo de query."""
        return query_type in self._handlers

    def unregister_handler(self, query_type: type[Query]) -> None:
        """Elimina el handler registrado para un tipo de query."""
        self._handlers.pop(query_type, None)


class BusRegistry:
    """
    Registro central de buses: gestiona CommandBus y QueryBus juntos.

    Proporciona un punto único de configuración para todos los handlers.
    """

    def __init__(self):
        self.command_bus = CommandBus()
        self.query_bus = QueryBus()

    def register_command_handler(
        self, command_type: type[Command], handler: CommandHandler
    ) -> None:
        """Registra un handler de comando."""
        self.command_bus.register_handler(command_type, handler)

    def register_query_handler(self, query_type: type[Query], handler: QueryHandler) -> None:
        """Registra un handler de query."""
        self.query_bus.register_handler(query_type, handler)

    async def dispatch_command(self, command: Command) -> CommandResult:
        """Despacha un comando."""
        return await self.command_bus.dispatch(command)

    async def dispatch_query(self, query: Query) -> QueryResult:
        """Despacha una query."""
        return await self.query_bus.dispatch(query)

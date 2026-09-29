"""
Tests para los buses CQRS de SpecterOSINT.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from specter.osint_core.bus import BusRegistry, CommandBus, QueryBus
from specter.osint_core.commands import Command, CommandResult
from specter.osint_core.database import Database
from specter.osint_core.queries import Query, QueryResult


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_bus.db"
        yield Database(db_path)


class MockCommand(Command):
    """Comando mock para tests."""

    def __init__(self, value: str = "test"):
        self.value = value

    async def execute(self) -> CommandResult:
        return CommandResult(
            success=True,
            message=f"MockCommand ejecutado con valor: {self.value}",
            data={"value": self.value},
        )

    def validate(self) -> list[str]:
        return []


class MockQuery(Query):
    """Query mock para tests."""

    def __init__(self, value: str = "test"):
        self.value = value

    async def execute(self) -> QueryResult:
        return QueryResult(
            success=True,
            message=f"MockQuery ejecutado con valor: {self.value}",
            data={"value": self.value},
        )

    def validate(self) -> list[str]:
        return []


class TestCommandBus:
    """Tests para CommandBus."""

    @pytest.mark.asyncio
    async def test_register_and_dispatch(self):
        """Test registrar y despachar un comando."""
        bus = CommandBus()

        async def handler(cmd: MockCommand) -> CommandResult:
            return await cmd.execute()

        bus.register_handler(MockCommand, handler)

        cmd = MockCommand(value="test_value")
        result = await bus.dispatch(cmd)

        assert result.success is True
        assert result.data["value"] == "test_value"

    @pytest.mark.asyncio
    async def test_dispatch_without_handler(self):
        """Test despachar un comando sin handler registrado."""
        bus = CommandBus()

        cmd = MockCommand()

        with pytest.raises(ValueError, match="No hay handler registrado"):
            await bus.dispatch(cmd)

    @pytest.mark.asyncio
    async def test_has_handler(self):
        """Test verificar si existe un handler."""
        bus = CommandBus()

        async def handler(cmd: MockCommand) -> CommandResult:
            return await cmd.execute()

        assert bus.has_handler(MockCommand) is False

        bus.register_handler(MockCommand, handler)

        assert bus.has_handler(MockCommand) is True

    @pytest.mark.asyncio
    async def test_unregister_handler(self):
        """Test eliminar un handler registrado."""
        bus = CommandBus()

        async def handler(cmd: MockCommand) -> CommandResult:
            return await cmd.execute()

        bus.register_handler(MockCommand, handler)
        assert bus.has_handler(MockCommand) is True

        bus.unregister_handler(MockCommand)
        assert bus.has_handler(MockCommand) is False

    @pytest.mark.asyncio
    async def test_middleware(self):
        """Test middleware de comandos."""
        bus = CommandBus()
        middleware_calls: list[str] = []

        def middleware(cmd: Command) -> None:
            middleware_calls.append("called")

        bus.add_middleware(middleware)

        async def handler(cmd: MockCommand) -> CommandResult:
            return await cmd.execute()

        bus.register_handler(MockCommand, handler)

        cmd = MockCommand()
        await bus.dispatch(cmd)

        assert len(middleware_calls) == 1


class TestQueryBus:
    """Tests para QueryBus."""

    @pytest.mark.asyncio
    async def test_register_and_dispatch(self):
        """Test registrar y despachar una query."""
        bus = QueryBus()

        async def handler(query: MockQuery) -> QueryResult:
            return await query.execute()

        bus.register_handler(MockQuery, handler)

        query = MockQuery(value="test_value")
        result = await bus.dispatch(query)

        assert result.success is True
        assert result.data["value"] == "test_value"

    @pytest.mark.asyncio
    async def test_dispatch_without_handler(self):
        """Test despachar una query sin handler registrado."""
        bus = QueryBus()

        query = MockQuery()

        with pytest.raises(ValueError, match="No hay handler registrado"):
            await bus.dispatch(query)

    @pytest.mark.asyncio
    async def test_has_handler(self):
        """Test verificar si existe un handler."""
        bus = QueryBus()

        async def handler(query: MockQuery) -> QueryResult:
            return await query.execute()

        assert bus.has_handler(MockQuery) is False

        bus.register_handler(MockQuery, handler)

        assert bus.has_handler(MockQuery) is True

    @pytest.mark.asyncio
    async def test_middleware(self):
        """Test middleware de queries."""
        bus = QueryBus()
        middleware_calls: list[str] = []

        def middleware(query: Query) -> None:
            middleware_calls.append("called")

        bus.add_middleware(middleware)

        async def handler(query: MockQuery) -> QueryResult:
            return await query.execute()

        bus.register_handler(MockQuery, handler)

        query = MockQuery()
        await bus.dispatch(query)

        assert len(middleware_calls) == 1


class TestBusRegistry:
    """Tests para BusRegistry."""

    @pytest.mark.asyncio
    async def test_register_command_handler(self):
        """Test registrar handler de comando en el registry."""
        registry = BusRegistry()

        async def handler(cmd: MockCommand) -> CommandResult:
            return await cmd.execute()

        registry.register_command_handler(MockCommand, handler)

        assert registry.command_bus.has_handler(MockCommand) is True

    @pytest.mark.asyncio
    async def test_register_query_handler(self):
        """Test registrar handler de query en el registry."""
        registry = BusRegistry()

        async def handler(query: MockQuery) -> QueryResult:
            return await query.execute()

        registry.register_query_handler(MockQuery, handler)

        assert registry.query_bus.has_handler(MockQuery) is True

    @pytest.mark.asyncio
    async def test_dispatch_command(self):
        """Test despachar comando a través del registry."""
        registry = BusRegistry()

        async def handler(cmd: MockCommand) -> CommandResult:
            return await cmd.execute()

        registry.register_command_handler(MockCommand, handler)

        cmd = MockCommand(value="registry_test")
        result = await registry.dispatch_command(cmd)

        assert result.success is True
        assert result.data["value"] == "registry_test"

    @pytest.mark.asyncio
    async def test_dispatch_query(self):
        """Test despachar query a través del registry."""
        registry = BusRegistry()

        async def handler(query: MockQuery) -> QueryResult:
            return await query.execute()

        registry.register_query_handler(MockQuery, handler)

        query = MockQuery(value="registry_test")
        result = await registry.dispatch_query(query)

        assert result.success is True
        assert result.data["value"] == "registry_test"

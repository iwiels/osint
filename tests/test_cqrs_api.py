"""
Tests para la API HTTP de CQRS de SpecterOSINT.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_cqrs_api.db"
        yield db_path


@pytest.fixture
async def client(temp_db):
    """Cliente HTTP asíncrono para la API CQRS."""
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

    from specter import server as specter_server

    specter_server.reset_services(temp_db)

    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    # Crear app de test
    app = FastAPI()
    app.mount("/cqrs", specter_server.cqrs_app)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    specter_server.reset_services()


class TestCommandsEndpoint:
    """Tests para el endpoint POST /commands."""

    @pytest.mark.asyncio
    async def test_create_case(self, client):
        """Test crear un caso vía API."""
        response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso API Test",
                    "description": "Descripción del caso de API",
                    "investigator": "Analista_API",
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "case_id" in data["data"]
        assert data["data"]["name"] == "Caso API Test"

    @pytest.mark.asyncio
    async def test_create_case_validation_error(self, client):
        """Test error de validación al crear caso."""
        response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "",  # Nombre vacío
                    "description": "Descripción",
                },
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False

    @pytest.mark.asyncio
    async def test_delete_case(self, client):
        """Test eliminar un caso vía API."""
        # Primero crear el caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso a Eliminar",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Luego eliminarlo
        response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "delete_case",
                "payload": {"case_id": case_id},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["case_id"] == case_id

    @pytest.mark.asyncio
    async def test_invalid_command_type(self, client):
        """Test tipo de comando inválido."""
        response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "invalid_command",
                "payload": {},
            },
        )

        assert response.status_code == 400


class TestQueriesEndpoint:
    """Tests para el endpoint POST /queries."""

    @pytest.mark.asyncio
    async def test_get_case(self, client):
        """Test obtener un caso vía API."""
        # Crear caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso Query Test",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Obtener caso
        response = await client.post(
            "/cqrs/queries",
            json={
                "query_type": "get_case",
                "payload": {"case_id": case_id},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["case"]["case_id"] == case_id

    @pytest.mark.asyncio
    async def test_get_case_not_found(self, client):
        """Test obtener un caso que no existe."""
        response = await client.post(
            "/cqrs/queries",
            json={
                "query_type": "get_case",
                "payload": {"case_id": "case-inexistente"},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False

    @pytest.mark.asyncio
    async def test_get_entities(self, client):
        """Test obtener entidades vía API."""
        # Crear caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso Entities Test",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Obtener entidades
        response = await client.post(
            "/cqrs/queries",
            json={
                "query_type": "get_entities",
                "payload": {"case_id": case_id},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "entities" in data["data"]

    @pytest.mark.asyncio
    async def test_get_graph(self, client):
        """Test obtener grafo vía API."""
        # Crear caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso Graph Test",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Obtener grafo
        response = await client.post(
            "/cqrs/queries",
            json={
                "query_type": "get_graph",
                "payload": {"case_id": case_id},
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "graph" in data["data"]

    @pytest.mark.asyncio
    async def test_invalid_query_type(self, client):
        """Test tipo de query inválido."""
        response = await client.post(
            "/cqrs/queries",
            json={
                "query_type": "invalid_query",
                "payload": {},
            },
        )

        assert response.status_code == 400


class TestProjectionsEndpoint:
    """Tests para el endpoint GET /projections/{name}."""

    @pytest.mark.asyncio
    async def test_get_graph_projection(self, client):
        """Test obtener proyección de grafo."""
        # Crear caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso Projection Test",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Obtener proyección
        response = await client.get(f"/cqrs/projections/graph?case_id={case_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "graph"
        assert data["case_id"] == case_id

    @pytest.mark.asyncio
    async def test_get_timeline_projection(self, client):
        """Test obtener proyección de timeline."""
        # Crear caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso Timeline Test",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Obtener proyección
        response = await client.get(f"/cqrs/projections/timeline?case_id={case_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "timeline"
        assert data["case_id"] == case_id

    @pytest.mark.asyncio
    async def test_get_correlations_projection(self, client):
        """Test obtener proyección de correlaciones."""
        # Crear caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso Correlations Test",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Obtener proyección
        response = await client.get(f"/cqrs/projections/correlations?case_id={case_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "correlations"
        assert data["case_id"] == case_id

    @pytest.mark.asyncio
    async def test_invalid_projection_name(self, client):
        """Test nombre de proyección inválido."""
        # Crear caso
        create_response = await client.post(
            "/cqrs/commands",
            json={
                "command_type": "create_case",
                "payload": {
                    "name": "Caso Invalid Projection",
                    "description": "Descripción",
                },
            },
        )
        case_id = create_response.json()["data"]["case_id"]

        # Obtener proyección inválida
        response = await client.get(f"/cqrs/projections/invalid?case_id={case_id}")

        assert response.status_code == 404

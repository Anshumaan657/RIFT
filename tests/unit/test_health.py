from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from rift.api import app as app_module


@asynccontextmanager
async def isolated_lifespan(_app: object) -> AsyncIterator[None]:
    app_module.app.state.db_engine = object()
    yield


def test_live_endpoint() -> None:
    app_module.app.router.lifespan_context = isolated_lifespan
    with TestClient(app_module.app) as client:
        response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ready_reports_database_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    app_module.app.router.lifespan_context = isolated_lifespan
    readiness = AsyncMock(return_value=False)
    monkeypatch.setattr(app_module, "database_is_ready", readiness)
    with TestClient(app_module.app) as client:
        response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "code": "DATABASE_UNAVAILABLE"}


def test_ready_reports_database_success(monkeypatch: pytest.MonkeyPatch) -> None:
    app_module.app.router.lifespan_context = isolated_lifespan
    readiness = AsyncMock(return_value=True)
    monkeypatch.setattr(app_module, "database_is_ready", readiness)
    with TestClient(app_module.app) as client:
        response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}

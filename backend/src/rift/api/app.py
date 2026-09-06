"""FastAPI application entrypoint."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncEngine

from rift import __version__
from rift.api.routes import router
from rift.db.session import create_engine, database_is_ready
from rift.logging import configure_logging
from rift.settings import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    app.state.db_engine = create_engine(settings)
    yield
    await app.state.db_engine.dispose()


app = FastAPI(title="RIFT Operator API", version=__version__, lifespan=lifespan)
app.include_router(router)


@app.get("/api/v1/health/live", tags=["health"])
async def live() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/v1/health/ready", tags=["health"])
async def ready(request: Request) -> JSONResponse:
    engine: AsyncEngine = request.app.state.db_engine
    if await database_is_ready(engine):
        return JSONResponse({"status": "ready"})
    return JSONResponse(
        {"status": "not_ready", "code": "DATABASE_UNAVAILABLE"},
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
    )

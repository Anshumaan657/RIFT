"""FastAPI application entrypoint."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncEngine

from rift import __version__
from rift.api.report_routes import router as report_router
from rift.api.routes import router
from rift.api.ui_routes import router as ui_router
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
app.include_router(report_router)
app.include_router(ui_router)


@app.exception_handler(HTTPException)
async def http_error(_request: Request, exc: HTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "request failed"
    details = None if isinstance(exc.detail, str) else exc.detail
    payload: dict[str, object] = {
        "code": f"HTTP_{exc.status_code}",
        "message": message,
    }
    if details is not None:
        payload["details"] = details
    return JSONResponse(payload, status_code=exc.status_code, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        {
            "code": "VALIDATION_ERROR",
            "message": "request validation failed",
            "details": [
                {
                    key: value
                    for key, value in error.items()
                    if key not in {"input", "ctx"}
                }
                for error in exc.errors()
            ],
        },
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )


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

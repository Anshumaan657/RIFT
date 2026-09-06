"""Synthetic target with vulnerable and fixed modes."""

import asyncio
import os
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from lab_app.fixtures import load_fixtures

LabMode = Literal["vulnerable", "fixed"]


class Identity(BaseModel):
    id: str
    label: str


def create_app(mode: LabMode) -> FastAPI:
    app = FastAPI(title="RIFT synthetic security lab", version="1.0.0")
    fixtures = load_fixtures()

    def authenticate(authorization: str | None = Header(default=None)) -> Identity:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Valid bearer token required"
            )
        token = authorization.removeprefix("Bearer ")
        for user in fixtures["users"]:
            if token == user["token"]:
                if user["expired"]:
                    raise HTTPException(
                        status.HTTP_401_UNAUTHORIZED, "Bearer token expired"
                    )
                return Identity.model_validate(user)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid bearer token")

    def optional_identity(
        authorization: str | None = Header(default=None),
    ) -> Identity | None:
        if authorization is None:
            return None
        return authenticate(authorization)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "mode": mode}

    @app.get("/api/status")
    async def api_status() -> dict[str, str]:
        return {"status": "ok", "mode": mode}

    @app.get("/api/public/{resource_id}")
    async def public_resource(resource_id: str) -> dict[str, str]:
        resource = fixtures["public_records"].get(resource_id)
        if resource is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "Synthetic resource not found"
            )
        return resource

    @app.get("/api/records/{resource_id}")
    async def private_resource(
        resource_id: str,
        identity: Identity | None = Depends(optional_identity),
    ) -> dict[str, str]:
        resource = fixtures["private_records"].get(resource_id)
        if resource is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "Synthetic resource not found"
            )
        if mode == "fixed":
            if identity is None:
                raise HTTPException(
                    status.HTTP_401_UNAUTHORIZED, "Valid bearer token required"
                )
            if identity.id != resource["owner_id"]:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    "Synthetic resource belongs to another user",
                )
        return resource

    @app.get("/api/auth-required")
    async def auth_required(
        identity: Identity = Depends(authenticate),
    ) -> dict[str, str]:
        return {"identity_id": identity.id, "status": "authenticated"}

    @app.get("/api/denied")
    async def denied(_identity: Identity = Depends(authenticate)) -> None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "This synthetic operation is denied"
        )

    @app.get("/api/missing")
    async def missing() -> None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Synthetic resource not found")

    @app.get("/api/redirect")
    async def redirect() -> RedirectResponse:
        return RedirectResponse(
            "/api/status", status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )

    @app.get("/api/slow")
    async def slow(
        delay_seconds: float = Query(default=3, ge=0, le=10),
    ) -> dict[str, float]:
        await asyncio.sleep(delay_seconds)
        return {"delay_seconds": delay_seconds}

    @app.get("/api/oversized")
    async def oversized() -> dict[str, str]:
        return {"synthetic_payload": "X" * 1_100_000}

    @app.get("/api/error")
    async def error() -> JSONResponse:
        return JSONResponse({"detail": "Synthetic server error"}, status_code=500)

    @app.api_route("/api/config", methods=["GET", "HEAD"])
    async def configuration(response: Response) -> dict[str, str]:
        if mode == "fixed":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.set_cookie(
                "rift_lab_session",
                "synthetic",
                secure=True,
                httponly=True,
                samesite="strict",
            )
        else:
            response.set_cookie("rift_lab_session", "synthetic")
        return {"mode": mode}

    return app


configured_mode = os.getenv("RIFT_LAB_MODE", "fixed")
if configured_mode not in {"vulnerable", "fixed"}:
    raise RuntimeError("RIFT_LAB_MODE must be 'vulnerable' or 'fixed'")
app = create_app(configured_mode)

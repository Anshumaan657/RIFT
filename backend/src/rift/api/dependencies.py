"""Authentication and CSRF dependencies shared by operator routes."""

from functools import lru_cache

from fastapi import Depends, HTTPException, Request, status

from rift.api.auth import SESSION_COOKIE, AuthenticationError, AuthService
from rift.settings import get_settings


@lru_cache
def get_auth_service() -> AuthService:
    settings = get_settings()
    return AuthService(
        settings.session_secret.get_secret_value(),
        session_ttl_seconds=settings.session_ttl_seconds,
    )


def current_operator(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
) -> str:
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    try:
        return auth.validate_session(cookie).operator_id
    except AuthenticationError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired session") from exc


def require_csrf(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
    _operator: str = Depends(current_operator),
) -> None:
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    session = auth.validate_session(cookie)
    if not auth.validate_csrf(session, request.headers.get("X-CSRF-Token")):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid CSRF token")

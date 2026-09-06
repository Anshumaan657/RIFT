"""Single-operator authentication, sessions, CSRF, and login throttling."""

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Final

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

SESSION_COOKIE: Final = "rift_session"


class AuthenticationError(ValueError):
    pass


class SessionExpiredError(AuthenticationError):
    pass


class RateLimitedError(AuthenticationError):
    pass


@dataclass(frozen=True)
class SessionData:
    operator_id: str
    csrf_token: str
    expires_at: int


class LoginThrottle:
    def __init__(self, attempts: int = 5, window_seconds: int = 900) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, key: str, now: float | None = None) -> bool:
        timestamp = time.monotonic() if now is None else now
        failures = self._failures[key]
        while failures and timestamp - failures[0] >= self.window_seconds:
            failures.popleft()
        return len(failures) < self.attempts

    def record_failure(self, key: str, now: float | None = None) -> None:
        if not self.is_allowed(key, now):
            raise RateLimitedError("too many login attempts")
        self._failures[key].append(time.monotonic() if now is None else now)

    def clear(self, key: str) -> None:
        self._failures.pop(key, None)


class AuthService:
    def __init__(
        self,
        session_secret: str,
        *,
        session_ttl_seconds: int = 3600,
        throttle: LoginThrottle | None = None,
    ) -> None:
        if len(session_secret) < 32:
            raise ValueError("session secret must contain at least 32 characters")
        self._secret = session_secret.encode()
        self.session_ttl_seconds = session_ttl_seconds
        self.throttle = throttle or LoginThrottle()
        self._password_hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65_536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    def hash_password(self, password: str) -> str:
        if len(password) < 12:
            raise ValueError("operator password must contain at least 12 characters")
        return self._password_hasher.hash(password)

    def verify_password(self, password: str, password_hash: str) -> bool:
        try:
            return self._password_hasher.verify(password_hash, password)
        except (VerificationError, InvalidHashError):
            return False

    def authenticate(
        self, username: str, password: str, *, expected_username: str, password_hash: str, key: str
    ) -> bool:
        if not self.throttle.is_allowed(key):
            raise RateLimitedError("too many login attempts")
        username_matches = hmac.compare_digest(username, expected_username)
        password_matches = self.verify_password(password, password_hash)
        valid = username_matches and password_matches
        if not valid:
            self.throttle.record_failure(key)
            return False
        self.throttle.clear(key)
        return True

    def create_session(self, operator_id: str, now: int | None = None) -> tuple[str, str]:
        issued = int(time.time()) if now is None else now
        csrf = secrets.token_urlsafe(32)
        payload = {
            "operator_id": operator_id,
            "csrf_token": csrf,
            "expires_at": issued + self.session_ttl_seconds,
        }
        encoded = self._encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = self._sign(encoded)
        return f"{encoded}.{signature}", csrf

    def validate_session(self, cookie: str, now: int | None = None) -> SessionData:
        try:
            encoded, supplied_signature = cookie.split(".", 1)
            if not hmac.compare_digest(self._sign(encoded), supplied_signature):
                raise AuthenticationError("invalid session")
            payload = json.loads(self._decode(encoded))
            session = SessionData(
                operator_id=str(payload["operator_id"]),
                csrf_token=str(payload["csrf_token"]),
                expires_at=int(payload["expires_at"]),
            )
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError("invalid session") from exc
        timestamp = int(time.time()) if now is None else now
        if timestamp >= session.expires_at:
            raise SessionExpiredError("session expired")
        return session

    @staticmethod
    def validate_csrf(session: SessionData, submitted: str | None) -> bool:
        return submitted is not None and hmac.compare_digest(session.csrf_token, submitted)

    def _sign(self, encoded: str) -> str:
        return self._encode(hmac.new(self._secret, encoded.encode(), hashlib.sha256).digest())

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

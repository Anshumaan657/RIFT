"""The only network boundary available to security checks."""

import asyncio
import hashlib
import ipaddress
import ssl
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urljoin, urlsplit

from rift.safety.audit import AuditChain
from rift.safety.policy import SafetyPolicy
from rift.safety.redaction import redact_headers, redact_text
from rift.safety.scope import NormalizedTarget, ScopeViolation, resolve_hostname

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[frozenset[IPAddress]]]
CancellationCheck = Callable[[], bool]
ALLOWED_METHODS = frozenset({"GET", "HEAD"})
FORBIDDEN_HEADERS = frozenset(
    {
        "host",
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "content-length",
    }
)
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class SafeHttpClientError(RuntimeError):
    pass


class PolicyError(SafeHttpClientError):
    pass


class DnsChangeError(PolicyError):
    pass


class BudgetExceededError(PolicyError):
    pass


class CancellationError(PolicyError):
    pass


class RuntimeExceededError(PolicyError):
    pass


class RedirectLimitError(PolicyError):
    pass


class ResponseTooLargeError(PolicyError):
    pass


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class PinnedTransport(Protocol):
    async def request(
        self,
        *,
        scheme: str,
        hostname: str,
        ip: IPAddress,
        port: int,
        method: str,
        path: str,
        headers: Mapping[str, str],
        connect_timeout: float,
        response_limit: int,
    ) -> TransportResponse: ...


class DirectTransport:
    """Minimal HTTP/1.1 transport that pins the peer IP and preserves TLS SNI."""

    async def request(
        self,
        *,
        scheme: str,
        hostname: str,
        ip: IPAddress,
        port: int,
        method: str,
        path: str,
        headers: Mapping[str, str],
        connect_timeout: float,
        response_limit: int,
    ) -> TransportResponse:
        ssl_context = ssl.create_default_context() if scheme == "https" else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    str(ip),
                    port,
                    ssl=ssl_context,
                    server_hostname=hostname if ssl_context else None,
                ),
                timeout=connect_timeout,
            )
            request_headers = "\r\n".join(f"{key}: {value}" for key, value in headers.items())
            writer.write(f"{method} {path} HTTP/1.1\r\n{request_headers}\r\n\r\n".encode())
            await writer.drain()
            header_block = await reader.readuntil(b"\r\n\r\n")
            if len(header_block) > 65_536:
                raise PolicyError("response headers exceed 64 KiB")
            status_line, *header_lines = header_block[:-4].decode("iso-8859-1").split("\r\n")
            parts = status_line.split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                raise PolicyError("upstream returned a malformed status line")
            response_headers: dict[str, str] = {}
            for line in header_lines:
                key, separator, value = line.partition(":")
                if not separator:
                    raise PolicyError("upstream returned a malformed header")
                response_headers[key.strip().lower()] = value.strip()
            declared = response_headers.get("content-length")
            try:
                declared_size = int(declared) if declared is not None else None
            except ValueError as exc:
                raise PolicyError("upstream returned an invalid Content-Length") from exc
            if declared_size is not None and declared_size > response_limit:
                raise ResponseTooLargeError("response exceeds configured body limit")
            body = b""
            while len(body) <= response_limit:
                chunk = await reader.read(min(65_536, response_limit + 1 - len(body)))
                if not chunk:
                    break
                body += chunk
            if len(body) > response_limit:
                raise ResponseTooLargeError("response exceeds configured body limit")
            return TransportResponse(int(parts[1]), response_headers, body)
        finally:
            if "writer" in locals():
                writer.close()
                await writer.wait_closed()


@dataclass(frozen=True)
class SafeResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    body_digest: str
    path: str


class SafeHttpClient:
    def __init__(
        self,
        *,
        assessment_id: str,
        target: NormalizedTarget,
        policy: SafetyPolicy,
        cancellation_check: CancellationCheck,
        audit: AuditChain,
        resolver: Resolver = resolve_hostname,
        transport: PinnedTransport | None = None,
        configured_redactions: tuple[str, ...] = (),
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if target.scheme == "http" and not policy.local_lab_mode:
            raise ScopeViolation("plain HTTP is permitted only in local lab mode")
        self.assessment_id = assessment_id
        self.target = target
        self.policy = policy
        self._cancelled = cancellation_check
        self._audit = audit
        self._resolver = resolver
        self._transport = transport or DirectTransport()
        self._patterns = configured_redactions
        self._clock = clock
        self._sleep = sleep
        self._started = clock()
        self._request_count = 0
        self._semaphore = asyncio.Semaphore(policy.concurrency)
        self._rate_lock = asyncio.Lock()
        self._last_request_at: float | None = None

    @property
    def request_count(self) -> int:
        return self._request_count

    async def request(
        self,
        method: str,
        relative_path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> SafeResponse:
        self._check_cancelled()
        if body is not None:
            raise PolicyError("request bodies are prohibited")
        normalized_method = method.upper()
        if normalized_method not in ALLOWED_METHODS:
            raise PolicyError("only GET and HEAD are permitted")
        path = self.target.normalize_relative_path(relative_path)
        safe_headers = self._prepare_headers(headers or {})
        async with self._semaphore:
            self._check_cancelled()
            return await asyncio.wait_for(
                self._request_chain(normalized_method, path, safe_headers),
                timeout=self.policy.total_timeout_seconds,
            )

    async def _request_chain(
        self, method: str, initial_path: str, headers: Mapping[str, str]
    ) -> SafeResponse:
        path = initial_path
        for redirect_count in range(3):
            self._check_cancelled()
            self._check_runtime_and_budget()
            current_ips = await self._resolver(self.target.hostname, self.target.port)
            self._validate_resolved_ips(current_ips)
            await self._rate_limit()
            self._check_cancelled()
            self._check_runtime_and_budget()
            self._request_count += 1
            self._audit.append(
                self.assessment_id,
                "http_request_intent",
                "system",
                {"method": method, "path": path, "headers": redact_headers(headers)},
                configured_patterns=self._patterns,
            )
            response = await self._transport.request(
                scheme=self.target.scheme,
                hostname=self.target.hostname,
                ip=sorted(current_ips, key=str)[0],
                port=self.target.port,
                method=method,
                path=path,
                headers=headers,
                connect_timeout=self.policy.connect_timeout_seconds,
                response_limit=self.policy.response_body_bytes,
            )
            if len(response.body) > self.policy.response_body_bytes:
                raise ResponseTooLargeError("response exceeds configured body limit")
            self._audit.append(
                self.assessment_id,
                "http_request_outcome",
                "system",
                {
                    "method": method,
                    "path": path,
                    "status_code": response.status_code,
                    "response_bytes": len(response.body),
                },
            )
            if response.status_code not in REDIRECT_STATUSES:
                safe_body = redact_text(
                    response.body.decode("utf-8", errors="replace"), self._patterns
                ).encode()
                return SafeResponse(
                    response.status_code,
                    redact_headers(response.headers),
                    safe_body,
                    hashlib.sha256(response.body).hexdigest(),
                    path,
                )
            if redirect_count == 2:
                raise RedirectLimitError("redirect limit exceeded")
            location = response.headers.get("location")
            if not location:
                raise ScopeViolation("redirect response has no Location header")
            path = self._validate_redirect(path, location)
        raise RedirectLimitError("redirect limit exceeded")

    def _prepare_headers(self, supplied: Mapping[str, str]) -> dict[str, str]:
        result = {
            "Host": self.target.authority,
            "User-Agent": self.policy.user_agent,
            "Accept": "*/*",
            "Connection": "close",
        }
        for key, value in supplied.items():
            if key.lower() in FORBIDDEN_HEADERS:
                raise PolicyError(f"caller-supplied {key} header is prohibited")
            if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                raise PolicyError("header contains a newline")
            result[key] = value
        return result

    def _validate_resolved_ips(self, current: frozenset[IPAddress]) -> None:
        if not current or current != self.target.validated_ips:
            raise DnsChangeError("DNS result differs from the immutable verified IP set")
        for address in current:
            if self.policy.local_lab_mode:
                if not address.is_loopback:
                    raise PolicyError("local lab mode permits loopback destinations only")
            elif (
                not address.is_global
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
                or address.is_link_local
                or address.is_loopback
                or address.is_private
            ):
                raise PolicyError("destination IP is not globally routable")

    def _validate_redirect(self, current_path: str, location: str) -> str:
        absolute = urljoin(
            f"{self.target.scheme}://{self.target.authority}{current_path}",
            location,
        )
        parsed = urlsplit(absolute)
        effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            parsed.scheme != self.target.scheme
            or parsed.hostname != self.target.hostname
            or effective_port != self.target.port
        ):
            raise ScopeViolation("redirect leaves the exact authorized target")
        combined = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return self.target.normalize_relative_path(combined)

    async def _rate_limit(self) -> None:
        async with self._rate_lock:
            minimum_interval = 1.0 / self.policy.requests_per_second
            now = self._clock()
            if self._last_request_at is not None:
                delay = minimum_interval - (now - self._last_request_at)
                if delay > 0:
                    await self._sleep(delay)
            self._last_request_at = self._clock()

    def _check_cancelled(self) -> None:
        if self._cancelled():
            self._audit.append(
                self.assessment_id, "cancellation_observed", "system", {"cancelled": True}
            )
            raise CancellationError("assessment cancellation requested")

    def _check_runtime_and_budget(self) -> None:
        if self._clock() - self._started >= self.policy.runtime_seconds:
            raise RuntimeExceededError("assessment runtime limit exceeded")
        if self._request_count >= self.policy.max_requests:
            raise BudgetExceededError("assessment request budget exhausted")

"""Normalization and validation for immutable assessment target scope."""

import ipaddress
import posixpath
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


class ScopeViolation(ValueError):
    pass


@dataclass(frozen=True)
class NormalizedTarget:
    scheme: str
    hostname: str
    port: int
    base_path: str
    validated_ips: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]

    @classmethod
    def create(
        cls, scheme: str, hostname: str, port: int, base_path: str, validated_ips: list[str]
    ) -> "NormalizedTarget":
        normalized_scheme = scheme.lower()
        if normalized_scheme not in {"http", "https"}:
            raise ScopeViolation("only HTTP and HTTPS targets are permitted")
        if not 1 <= port <= 65_535:
            raise ScopeViolation("target port is invalid")
        host = normalize_hostname(hostname)
        path = normalize_base_path(base_path)
        addresses = frozenset(parse_address(value) for value in validated_ips)
        if not addresses:
            raise ScopeViolation("target has no validated IP addresses")
        return cls(normalized_scheme, host, port, path, addresses)

    @property
    def authority(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        return self.hostname if self.port == default_port else f"{self.hostname}:{self.port}"

    def normalize_relative_path(self, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme or parsed.netloc or parsed.username or parsed.password or parsed.fragment:
            raise ScopeViolation(
                "request path must be relative and contain no fragment or authority"
            )
        path = repeatedly_unquote(parsed.path)
        if not path.startswith("/") or path.startswith("//") or "\\" in path:
            raise ScopeViolation("request path is malformed")
        normalized = posixpath.normpath(path)
        if path.endswith("/") and normalized != "/":
            normalized += "/"
        base = self.base_path.rstrip("/") or "/"
        if base != "/" and normalized != base and not normalized.startswith(base + "/"):
            raise ScopeViolation("request path escapes the authorized base path")
        return normalized + (f"?{parsed.query}" if parsed.query else "")


def normalize_hostname(value: str) -> str:
    if any(character in value for character in "@#%*[]/\\") or not value:
        raise ScopeViolation("hostname is malformed")
    candidate = value.rstrip(".").lower()
    if candidate.isdigit() or candidate.startswith("0x"):
        raise ScopeViolation("alternate numeric host forms are prohibited")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeViolation("hostname is invalid") from exc
        if any(not label or len(label) > 63 for label in candidate.split(".")):
            raise ScopeViolation("hostname is invalid") from None
        return candidate
    return address.compressed


def normalize_base_path(value: str) -> str:
    if "?" in value or "#" in value:
        raise ScopeViolation("base path cannot contain a query or fragment")
    decoded = repeatedly_unquote(value)
    if not decoded.startswith("/") or decoded.startswith("//") or "\\" in decoded:
        raise ScopeViolation("base path is malformed")
    normalized = posixpath.normpath(decoded)
    return normalized if normalized == "/" else normalized.rstrip("/") + "/"


def repeatedly_unquote(value: str) -> str:
    current = value
    for _ in range(3):
        decoded = unquote(current)
        if decoded == current:
            return decoded
        current = decoded
    if "%" in current:
        raise ScopeViolation("path contains excessive encoding")
    return current


def parse_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ScopeViolation("validated IP address is invalid") from exc


async def resolve_hostname(
    hostname: str, port: int
) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    loop = __import__("asyncio").get_running_loop()
    records = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return frozenset(ipaddress.ip_address(record[4][0]) for record in records)

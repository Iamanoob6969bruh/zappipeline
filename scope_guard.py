"""Resolve ALL addresses, reject mixed/public DNS, and pin scan connections."""

from __future__ import annotations

import ipaddress
import socket
import sys
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class ScopeViolationError(ValueError):
    pass


@dataclass(frozen=True)
class ScopedTarget:
    url: str
    hostname: str
    ip: str
    port: int
    scheme: str


def resolve_target(target_url: str) -> ScopedTarget:
    try:
        if not target_url or any(ord(c) <= 32 for c in target_url) or "\\" in target_url:
            raise ValueError("whitespace, control characters or backslashes in URL")
        parsed = urlsplit(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("a complete http:// or https:// URL is required")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("credentials and fragments are not permitted")
        host = parsed.hostname
        if "%" in host:
            raise ValueError("zone identifiers are not permitted")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = {ipaddress.ip_address(item[4][0]) for item in infos}
        if not ips or not all(ip.is_loopback for ip in ips):
            raise ValueError("every resolved address must be loopback (127.0.0.0/8 or ::1)")
        # Prefer IPv4 for localhost apps; preserve explicit IPv6 addresses.
        ip = str(sorted(ips, key=lambda value: (value.version, int(value)))[0])
        return ScopedTarget(urlunsplit(parsed), host, ip, port, parsed.scheme)
    except (ValueError, OSError) as exc:
        raise ScopeViolationError(f"REFUSED: local test targets only: {exc}") from exc


def validate_target_scope(target_url: str) -> bool:
    resolve_target(target_url)
    return True


def enforce_or_exit(target_url: str) -> bool:
    try:
        return validate_target_scope(target_url)
    except ScopeViolationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(3) from exc

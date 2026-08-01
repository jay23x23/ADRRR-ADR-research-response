"""Central security controls for the local SIEM administration service."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import threading
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SENSITIVE_FRAGMENTS = ("password", "passwd", "secret", "token", "authorization", "cookie", "api_key", "apikey", "credential", "connection_string")
MAX_TEXT_LENGTH = 100_000
AUDIT_LOCK = threading.Lock()


def redact(value: Any, depth: int = 0) -> Any:
    """Redact common secret fields and cap deeply nested/unbounded display data."""
    if depth > 12: return "[DEPTH LIMIT]"
    if isinstance(value, dict):
        return {str(key)[:200]: ("[REDACTED]" if any(fragment in str(key).lower() for fragment in SENSITIVE_FRAGMENTS) else redact(item, depth + 1)) for key, item in list(value.items())[:2000]}
    if isinstance(value, list): return [redact(item, depth + 1) for item in value[:2000]]
    if isinstance(value, str) and len(value) > MAX_TEXT_LENGTH: return value[:MAX_TEXT_LENGTH] + "…[TRUNCATED]"
    return value


def public_error(error: Exception) -> str:
    """Return useful error classes without vendor bodies, secrets, or local paths."""
    message = str(error).replace("\r", " ").replace("\n", " ")[:400]
    for fragment in SENSITIVE_FRAGMENTS:
        if fragment in message.lower(): return f"{type(error).__name__}: sensitive connector operation failed; inspect the local audit log"
    return f"ValueError: {message}" if isinstance(error, ValueError) else f"{type(error).__name__}: operation failed; inspect the local audit log"


def validate_https_url(value: str, *, allow_private_env: str = "ALLOW_PRIVATE_EDR_URLS") -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Connector URL must be HTTPS with a hostname and no embedded credentials or fragment")
    if os.environ.get(allow_private_env) == "1": return value.rstrip("/")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise ValueError("Connector hostname could not be resolved") from error
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Private/local connector targets are blocked by default; set ALLOW_PRIVATE_EDR_URLS=1 only for an approved on-premises console")
    return value.rstrip("/")


def append_audit(path: Path, action: str, outcome: str, details: dict[str, Any] | None = None) -> None:
    """Append a hash-chained, secret-redacted administrative audit entry."""
    with AUDIT_LOCK:
        previous_hash = "0" * 64
        if path.exists():
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                try: previous_hash = json.loads(lines[-1])["entry_hash"]
                except (json.JSONDecodeError, KeyError): previous_hash = "INVALID_PREVIOUS_ENTRY"
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action[:100], "outcome": outcome[:30], "details": redact(details or {}), "previous_hash": previous_hash}
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        entry["entry_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with path.open("a", encoding="utf-8") as handle: handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

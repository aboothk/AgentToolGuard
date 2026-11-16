"""Destination parsing and allowlists (§6.6).

AgentGuard never opens a connection, so this is a check on *parameters* only. It cannot
stop DNS rebinding or redirects; pair it with an egress proxy for that.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>]+")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")


@dataclass(frozen=True)
class Destination:
    kind: str  # "url" or "email"
    host: str  # normalized host name or dotted IP
    raw: str  # what was found in the argument; for emails the whole address


# --- IP forms -----------------------------------------------------------------------------


def parse_ipv4_loose(host: str) -> ipaddress.IPv4Address | None:
    """Parse dotted, hex, octal, integer and short IPv4 forms (e.g. 0x7f.1, 2130706433).

    Implemented by hand because socket.inet_aton behaves differently across platforms and
    `ipaddress` rejects these forms.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(part == "" for part in parts):
        return None
    numbers = []
    for part in parts:
        number = _parse_ip_part(part)
        if number is None:
            return None
        numbers.append(number)
    *leading, last = numbers
    if any(number > 255 for number in leading):
        return None
    if last >= 256 ** (5 - len(numbers)):
        return None
    value = last
    for position, number in enumerate(leading):
        value += number << (8 * (3 - position))
    return ipaddress.IPv4Address(value)


def _parse_ip_part(part: str) -> int | None:
    try:
        if part.lower().startswith("0x"):
            return int(part[2:] or "0", 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part, 8)
        if part.isdigit():
            return int(part, 10)
    except ValueError:
        return None
    return None


def normalize_host(host: str) -> str:
    """Lowercase, drop brackets and trailing dot, rewrite any IPv4 form as dotted decimal."""
    host = host.strip().strip("[]").rstrip(".").lower()
    if ":" in host:  # IPv6
        try:
            return str(ipaddress.IPv6Address(host.split("%")[0]))
        except ValueError:
            return host
    ipv4 = parse_ipv4_loose(host)
    if ipv4 is not None:
        return str(ipv4)
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def is_blocked_address(host: str) -> bool:
    """True for literal private, loopback, link-local, metadata and unspecified addresses."""
    try:
        address = ipaddress.ip_address(normalize_host(host))
    except ValueError:
        return host in ("localhost",) or host.endswith(".localhost")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_reserved
    )


# --- extraction ---------------------------------------------------------------------------


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple):
        return [text for item in value for text in _flatten_strings(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _flatten_strings(item)]
    return []


def extract_destinations(value: Any, kind: str) -> list[Destination]:
    """Pull URLs (network tools) or email addresses (message tools) out of an argument value."""
    found: list[Destination] = []
    for text in _flatten_strings(value):
        if kind == "network":
            found.extend(_urls_in(text))
        else:
            found.extend(_emails_in(text))
    return found


def find_urls_in_text(text: str) -> list[Destination]:
    """Used for tools without a declared egress (§6.6, `undeclared_destination`)."""
    return _urls_in(text)


def _urls_in(text: str) -> list[Destination]:
    candidates = _URL_RE.findall(text)
    if not candidates and "." in text and " " not in text.strip():
        candidates = ["//" + text.strip()]  # a bare "host/path" value
    found = []
    for candidate in candidates:
        host = _host_of_url(candidate)
        if host:
            found.append(Destination("url", host, candidate))
    return found


def _host_of_url(url: str) -> str | None:
    try:
        # Browsers treat a backslash like a slash, so `http://evil.com\@corp.example` is evil.com.
        host = urlsplit(url.replace("\\", "/")).hostname
    except ValueError:
        return None
    return normalize_host(host) if host else None


def _emails_in(text: str) -> list[Destination]:
    return [
        Destination("email", match.split("@")[1].lower(), match.lower()) for match in _EMAIL_RE.findall(text)
    ]


# --- allowlists ---------------------------------------------------------------------------


def matches_allowlist(destination: Destination, patterns: list[str]) -> bool:
    """Emails match on the whole address, URLs on the host name."""
    subject = destination.raw if destination.kind == "email" else destination.host
    return any(fnmatch.fnmatchcase(subject, pattern.lower()) for pattern in patterns)

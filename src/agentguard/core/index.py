"""Value index: remember protected values as hashes, find them again in arguments (§6.5).

Only hashes are stored, never the original text.

How matching works:
  * Values of 8..31 characters are stored whole, per length. A request is searched by
    sliding each stored length over the request text (E1: the value appears verbatim).
  * Longer values are stored as 32-character windows taken every 8 characters.
    A request is searched by sliding a 32-character window over every position, so a
    fragment at any offset still lines up with at least one stored window.
    All windows of a value found, plus a matching full hash -> E1.
    Enough windows found -> E2 (a verbatim fragment).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

MIN_VALUE_CHARS = 8
WINDOW_CHARS = 32
WINDOW_STEP = 8
MAX_DECODE_DEPTH = 2

_ZERO_WIDTH = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
_WHITESPACE = re.compile(r"\s+")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def normalize_text(text: str) -> str:
    """NFKC, strip zero-width characters, collapse whitespace, lowercase."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return _WHITESPACE.sub(" ", text).strip().lower()


def _hash(text: str) -> bytes:
    return hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest()


def iter_string_leaves(value: Any) -> Iterator[str]:
    """Yield every string inside nested lists and dicts."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list | tuple):
            stack.extend(node)


# --- decoding -----------------------------------------------------------------------------


def decode_candidates(text: str, budget_chars: int) -> tuple[list[str], bool]:
    """Decode base64 / base64url / hex / percent-encoding, up to two layers.

    Returns the decoded texts and whether the budget ran out (the caller then falls back
    to the session-level evidence E3).
    """
    results: list[str] = []
    seen = {text}
    spent = 0
    frontier = [text]
    for _ in range(MAX_DECODE_DEPTH):
        next_frontier: list[str] = []
        for current in frontier:
            for decoded in _decode_once(current):
                if decoded in seen:
                    continue
                spent += len(decoded)
                if spent > budget_chars:
                    return results, True
                seen.add(decoded)
                results.append(decoded)
                next_frontier.append(decoded)
        frontier = next_frontier
    return results, False


def _decode_once(text: str) -> Iterator[str]:
    if _PERCENT.search(text):
        yield urllib.parse.unquote(text, errors="replace")
    for run in _BASE64_RUN.findall(text):
        decoded = _try_base64(run)
        if decoded:
            yield decoded
    for run in _HEX_RUN.findall(text):
        decoded = _bytes_to_text(bytes.fromhex(run))
        if decoded:
            yield decoded


def _try_base64(run: str) -> str | None:
    cleaned = run.rstrip("=").replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        return _bytes_to_text(base64.b64decode(cleaned, validate=True))
    except (binascii.Error, ValueError):
        return None


def _bytes_to_text(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return decoded if len(decoded) >= MIN_VALUE_CHARS else None


# --- the index ----------------------------------------------------------------------------


@dataclass
class ProtectedValue:
    labels: set[str]
    source_call: str
    length: int
    window_total: int  # 0 for values shorter than one window
    full_hash: bytes


@dataclass(frozen=True)
class IndexHit:
    level: str  # "E1" or "E2"
    label: str
    source_call: str
    overlap: float


@dataclass
class ValueIndex:
    max_windows: int
    saturated: bool = False
    _values: list[ProtectedValue] = field(default_factory=list)
    _by_full_hash: dict[bytes, int] = field(default_factory=dict)
    _short: dict[int, dict[bytes, int]] = field(default_factory=dict)
    _windows: dict[bytes, list[tuple[int, int]]] = field(default_factory=dict)
    _window_count: int = 0

    def add(self, value: str, labels: set[str], source_call: str) -> None:
        """Index one protected value. Values shorter than 8 characters are ignored."""
        text = normalize_text(value)
        if len(text) < MIN_VALUE_CHARS:
            return
        full_hash = _hash(text)
        existing = self._by_full_hash.get(full_hash)
        if existing is not None:
            self._values[existing].labels |= labels
            return

        position = len(self._values)
        windows = self._window_hashes(text)
        record = ProtectedValue(set(labels), source_call, len(text), len(windows), full_hash)
        self._values.append(record)
        self._by_full_hash[full_hash] = position

        if not windows:
            self._short.setdefault(len(text), {})[full_hash] = position
        elif self._window_count + len(windows) > self.max_windows:
            self.saturated = True  # the value stays known by its full hash only
        else:
            for number, window_hash in enumerate(windows):
                self._windows.setdefault(window_hash, []).append((position, number))
            self._window_count += len(windows)

    @staticmethod
    def _window_hashes(text: str) -> list[bytes]:
        last_start = len(text) - WINDOW_CHARS
        return [_hash(text[start : start + WINDOW_CHARS]) for start in range(0, last_start + 1, WINDOW_STEP)]

    @property
    def window_count(self) -> int:
        return self._window_count

    def find(self, text: str, wanted_labels: set[str], min_windows: int) -> list[IndexHit]:
        """Search `text` for protected values carrying any of `wanted_labels`."""
        text = normalize_text(text)
        exact: set[int] = set()
        exact.update(self._find_short(text))
        whole = self._by_full_hash.get(_hash(text))  # works even when the index is saturated
        if whole is not None:
            exact.add(whole)
        partial, full_matches = self._find_windows(text)
        exact.update(full_matches)

        hits: list[IndexHit] = []
        for position in sorted(exact | set(partial)):
            record = self._values[position]
            shared = sorted(record.labels & wanted_labels)
            if not shared:
                continue
            if position in exact:
                hits.append(IndexHit("E1", shared[0], record.source_call, 1.0))
            elif len(partial[position]) >= min_windows:
                overlap = len(partial[position]) / max(record.window_total, 1)
                hits.append(IndexHit("E2", shared[0], record.source_call, round(overlap, 3)))
        return hits

    def _find_short(self, text: str) -> Iterator[int]:
        for length, by_hash in self._short.items():
            for start in range(len(text) - length + 1):
                position = by_hash.get(_hash(text[start : start + length]))
                if position is not None:
                    yield position

    def _find_windows(self, text: str) -> tuple[dict[int, set[int]], set[int]]:
        """Slide a window over `text`; return matched window numbers per value and full matches."""
        matched: dict[int, set[int]] = {}
        full_matches: set[int] = set()
        if not self._windows:
            return matched, full_matches
        for start in range(len(text) - WINDOW_CHARS + 1):
            entries = self._windows.get(_hash(text[start : start + WINDOW_CHARS]))
            for position, number in entries or ():
                matched.setdefault(position, set()).add(number)
                if number == 0 and self._is_full_value_at(text, start, position):
                    full_matches.add(position)
        return matched, full_matches

    def _is_full_value_at(self, text: str, start: int, position: int) -> bool:
        record = self._values[position]
        return _hash(text[start : start + record.length]) == record.full_hash

"""Audit log: redaction and hash chain (§9).

One JSON object per line. Each entry carries the hash of the previous one, so editing or
deleting a line in the middle is detected by `agentguard audit verify`. Deleting the whole
file is not detected (documented in limitations.md).
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentguard.core.canonical import canonical_dumps, to_plain
from agentguard.core.destinations import extract_destinations
from agentguard.core.lock import Egress

GENESIS_HASH = "0" * 64
TAIL_BYTES = 1 << 20


class AuditError(Exception):
    """The audit log could not be written or is corrupt."""


def _entry_hash(entry_without_hash: dict[str, Any]) -> str:
    text = entry_without_hash["prev_hash"] + canonical_dumps(entry_without_hash)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditError(f"cannot create audit directory: {exc}") from exc
        last = self._read_last_entry()
        self._seq = last["seq"] if last else 0
        self._prev_hash = last["hash"] if last else GENESIS_HASH

    def _read_last_entry(self) -> dict[str, Any] | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        with self.path.open("rb") as handle:
            handle.seek(max(0, self.path.stat().st_size - TAIL_BYTES))
            lines = [line for line in handle.read().splitlines() if line.strip()]
        try:
            entry = json.loads(lines[-1])
            return {"seq": int(entry["seq"]), "hash": str(entry["hash"])}
        except (ValueError, KeyError, IndexError) as exc:
            raise AuditError(f"audit log {self.path} is corrupt; run `agentguard audit verify`") from exc

    def write(self, event: str, **fields: Any) -> dict[str, Any]:
        """Append one entry. Raises AuditError if it cannot be written."""
        with self._lock:
            entry: dict[str, Any] = {
                "v": 1,
                "seq": self._seq + 1,
                "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "event": event,
                **{key: value for key, value in fields.items() if value is not None},
                "prev_hash": self._prev_hash,
            }
            entry["hash"] = _entry_hash(entry)
            line = canonical_dumps(entry, sort_keys=False) + "\n"
            try:
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(line)
                    handle.flush()
            except OSError as exc:
                raise AuditError(f"cannot write audit log: {exc}") from exc
            self._seq = entry["seq"]
            self._prev_hash = entry["hash"]
            return entry


def read_entries(path: Path) -> list[dict[str, Any]]:
    entries = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except ValueError as exc:
            raise AuditError(f"line {number} is not valid JSON") from exc
    return entries


def verify_chain(path: Path) -> list[str]:
    """Return a list of problems; an empty list means the chain is intact."""
    problems: list[str] = []
    previous_hash = GENESIS_HASH
    expected_seq = 1
    try:
        entries = read_entries(path)
    except AuditError as exc:
        return [str(exc)]
    for entry in entries:
        seq = entry.get("seq")
        if seq != expected_seq:
            problems.append(f"seq {seq}: expected {expected_seq} (entry removed or reordered?)")
            expected_seq = seq if isinstance(seq, int) else expected_seq
        if entry.get("prev_hash") != previous_hash:
            problems.append(f"seq {seq}: prev_hash does not match the previous entry")
        claimed = entry.get("hash")
        body = {key: value for key, value in entry.items() if key != "hash"}
        try:
            recomputed = _entry_hash(body)
        except (KeyError, TypeError, ValueError):
            recomputed = None
        if claimed != recomputed:
            problems.append(f"seq {seq}: entry content does not match its hash")
        previous_hash = claimed if isinstance(claimed, str) else previous_hash
        expected_seq += 1
    return problems


# --- redaction ----------------------------------------------------------------------------


def redact_args(args: dict[str, Any], egress: Egress | None) -> dict[str, Any]:
    """Record only name, length and a short digest per argument (§9.1).

    Destination arguments also keep their host names, which the reviewer needs to see.
    Used on every path, including the allow path.
    """
    destination_args = set(egress.destination_args) if egress else set()
    redacted: dict[str, Any] = {}
    for name, value in args.items():
        text = value if isinstance(value, str) else canonical_dumps(to_plain(value))
        summary: dict[str, Any] = {
            "len": len(text),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
        }
        if name in destination_args and egress:
            hosts = sorted({dest.host for dest in extract_destinations(value, egress.kind)})
            if hosts:
                summary["domain"] = ",".join(hosts)
        redacted[name] = summary
    return redacted

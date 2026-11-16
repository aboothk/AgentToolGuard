"""Approvals bound to a call fingerprint (§8).

Flow: the gateway records a pending approval and tells the agent to retry. A human runs
`agentguard approve <id>` in another terminal. The retried call has the same fingerprint, so
it consumes the approval exactly once.

State lives in directories under `approval.dir`, one JSON file per approval:
    pending/ -> approved/ -> used/        (also denied/, expired/)
Moving a file with os.replace is atomic, so a timeout and a late approval cannot both win and
a used approval cannot be replayed (S18, S19). This also works across processes.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agentguard.core.canonical import canonical_dumps, to_plain
from agentguard.core.models import Model

STATES = ("pending", "approved", "used", "denied", "denial_reported", "expired")


class ApprovalError(Exception):
    """The approval does not exist, is no longer pending, or has expired."""


def fingerprint(principal: str, session_id: str, tool_id: str, args: dict[str, Any]) -> str:
    """SHA-256 over principal, session, tool and canonical arguments (§8.1)."""
    payload = canonical_dumps([principal, session_id, tool_id, to_plain(args)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ApprovalRecord(Model):
    approval_id: str
    fingerprint: str
    session_id: str
    principal: str
    tool_id: str
    summary: dict[str, Any]  # redacted arguments, shown to the approver
    rule_ids: list[str]
    reason_code: str
    evidence: list[str]  # short human-readable lines
    created_at: float
    expires_at: float
    decided_by: str | None = None
    decided_at: float | None = None


def escape_for_terminal(text: str) -> str:
    """Make control characters visible so they cannot forge the approval prompt (§8.2)."""
    out = []
    for char in text:
        if unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co"):
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return "".join(out)


class ApprovalStore:
    def __init__(self, root: Path, timeout_seconds: float, clock: Callable[[], float] = time.time):
        self.root = root
        self.timeout_seconds = timeout_seconds
        self.clock = clock
        for state in STATES:
            (root / state).mkdir(parents=True, exist_ok=True)

    # --- file helpers ---------------------------------------------------------------------

    def _path(self, state: str, approval_id: str) -> Path:
        return self.root / state / f"{approval_id}.json"

    def _read(self, path: Path) -> ApprovalRecord | None:
        try:
            return ApprovalRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError):
            return None

    def _write(self, path: Path, record: ApprovalRecord) -> None:
        path.write_text(record.model_dump_json(indent=2), encoding="utf-8")

    def _claim(self, approval_id: str, source: str, target: str) -> Path | None:
        """Atomically move an approval between states. Only one caller can succeed."""
        destination = self._path(target, approval_id)
        try:
            os.replace(self._path(source, approval_id), destination)
        except FileNotFoundError:
            return None
        return destination

    def _records(self, state: str) -> list[ApprovalRecord]:
        records = (self._read(path) for path in sorted((self.root / state).glob("*.json")))
        return [record for record in records if record is not None]

    # --- gateway side ---------------------------------------------------------------------

    def request(
        self,
        *,
        fingerprint_value: str,
        session_id: str,
        principal: str,
        tool_id: str,
        summary: dict[str, Any],
        rule_ids: list[str],
        reason_code: str,
        evidence: list[str],
        max_pending: int,
    ) -> tuple[ApprovalRecord, bool]:
        """Register a pending approval. Returns (record, created); identical calls share one.

        Raises ApprovalError when the session already has `max_pending` open approvals,
        which stops an agent from flooding the approver."""
        for existing in self._records("pending"):
            if existing.fingerprint == fingerprint_value:
                return existing, False
        if self.pending_count(session_id) >= max_pending:
            raise ApprovalError("too many pending approvals for this session")
        now = self.clock()
        record = ApprovalRecord(
            approval_id="ap_" + secrets.token_hex(4),
            fingerprint=fingerprint_value,
            session_id=session_id,
            principal=principal,
            tool_id=tool_id,
            summary=summary,
            rule_ids=rule_ids,
            reason_code=reason_code,
            evidence=evidence,
            created_at=now,
            expires_at=now + self.timeout_seconds,
        )
        self._write(self._path("pending", record.approval_id), record)
        return record, True

    def pending_count(self, session_id: str) -> int:
        return sum(1 for record in self._records("pending") if record.session_id == session_id)

    def consume(self, fingerprint_value: str) -> ApprovalRecord | None:
        """Use up an approved, unexpired approval for this exact call, if there is one."""
        for record in self._records("approved"):
            if record.fingerprint != fingerprint_value:
                continue
            target = "used" if record.expires_at > self.clock() else "expired"
            if self._claim(record.approval_id, "approved", target) and target == "used":
                return record
        return None

    def consume_denial(self, fingerprint_value: str) -> ApprovalRecord | None:
        """Report (once) that a human denied this exact call, so the gateway can audit it."""
        for record in self._records("denied"):
            if record.fingerprint == fingerprint_value and self._claim(
                record.approval_id, "denied", "denial_reported"
            ):
                return record
        return None

    def sweep_expired(self) -> list[ApprovalRecord]:
        """Move timed-out pending/approved entries to expired/; return those this call expired."""
        expired = []
        now = self.clock()
        for state in ("pending", "approved"):
            for record in self._records(state):
                if record.expires_at <= now and self._claim(record.approval_id, state, "expired"):
                    expired.append(record)
        return expired

    # --- human side (CLI) -----------------------------------------------------------------

    def get_pending(self, approval_id: str) -> ApprovalRecord | None:
        record = self._read(self._path("pending", approval_id))
        return record if record and record.expires_at > self.clock() else None

    def list_pending(self) -> list[ApprovalRecord]:
        now = self.clock()
        return [record for record in self._records("pending") if record.expires_at > now]

    def decide(self, approval_id: str, approve: bool, decided_by: str) -> ApprovalRecord:
        """Approve or deny a pending approval. An approved call may be retried for the same
        timeout window, counted from the decision."""
        record = self.get_pending(approval_id)
        if record is None:  # expired entries are moved (and audited) by the gateway's sweep
            raise ApprovalError(f"{approval_id} is not pending (unknown, decided, or expired)")
        target = "approved" if approve else "denied"
        destination = self._claim(approval_id, "pending", target)
        if destination is None:
            raise ApprovalError(f"{approval_id} was decided or expired just now")
        now = self.clock()
        decided = record.model_copy(
            update={
                "decided_by": decided_by,
                "decided_at": now,
                "expires_at": now + self.timeout_seconds if approve else record.expires_at,
            }
        )
        self._write(destination, decided)
        return decided

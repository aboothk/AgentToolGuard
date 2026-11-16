"""Approval scenarios S16-S19 and the approval store (§8)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.core.approval import ApprovalError, ApprovalStore, escape_for_terminal, fingerprint
from agentguard.core.models import Decision, Reason
from tests.helpers import FakeClock, audit_events, build_guard, call

RULE = {"rules": [{"id": "TR-001", "tools": ["files__delete_*"], "effect": "require_approval"}]}


def approve_pending(guard, approval_id: str, approve: bool = True) -> None:  # type: ignore[no-untyped-def]
    guard.approvals.decide(approval_id, approve=approve, decided_by="tester")


def test_s16_approved_call_is_allowed_once_on_retry(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, RULE)
    session = guard.open_session()
    first, _ = call(guard, session, "files__delete_file", path="/a")
    assert first.decision is Decision.REQUIRE_APPROVAL and first.approval_id
    approve_pending(guard, first.approval_id)

    retry, _ = call(guard, session, "files__delete_file", path="/a")
    assert retry.decision is Decision.ALLOW and retry.reason_code == Reason.APPROVED
    assert audit_events(tmp_path, "approval.decided")[0]["decided_by"] == "tester"


def test_s17_changed_arguments_need_a_new_approval(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, RULE)
    session = guard.open_session()
    first, _ = call(guard, session, "files__delete_file", path="/a")
    approve_pending(guard, first.approval_id)  # type: ignore[arg-type]
    other, _ = call(guard, session, "files__delete_file", path="/b")
    assert other.decision is Decision.REQUIRE_APPROVAL
    assert other.approval_id != first.approval_id


def test_s18_an_approval_cannot_be_replayed(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, RULE)
    session = guard.open_session()
    first, _ = call(guard, session, "files__delete_file", path="/a")
    approve_pending(guard, first.approval_id)  # type: ignore[arg-type]
    assert call(guard, session, "files__delete_file", path="/a")[0].decision is Decision.ALLOW
    replay, _ = call(guard, session, "files__delete_file", path="/a")
    assert replay.decision is Decision.REQUIRE_APPROVAL


def test_approval_does_not_carry_over_to_another_session(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, RULE)
    first_session, second_session = guard.open_session(), guard.open_session()
    first, _ = call(guard, first_session, "files__delete_file", path="/a")
    approve_pending(guard, first.approval_id)  # type: ignore[arg-type]
    elsewhere, _ = call(guard, second_session, "files__delete_file", path="/a")
    assert elsewhere.decision is Decision.REQUIRE_APPROVAL


def test_s19_timeout_voids_the_approval_and_a_retry_asks_again(tmp_path: Path) -> None:
    clock = FakeClock()
    guard = build_guard(tmp_path, {**RULE, "approval": {"timeout_seconds": 60}}, clock=clock)
    session = guard.open_session()
    first, _ = call(guard, session, "files__delete_file", path="/a")
    clock.advance(61)
    with pytest.raises(ApprovalError):
        approve_pending(guard, first.approval_id)  # type: ignore[arg-type]
    again, _ = call(guard, session, "files__delete_file", path="/a")
    assert again.decision is Decision.REQUIRE_APPROVAL
    assert again.approval_id != first.approval_id
    assert audit_events(tmp_path, "approval.expired")


def test_an_approval_that_is_not_used_in_time_expires(tmp_path: Path) -> None:
    clock = FakeClock()
    guard = build_guard(tmp_path, {**RULE, "approval": {"timeout_seconds": 60}}, clock=clock)
    session = guard.open_session()
    first, _ = call(guard, session, "files__delete_file", path="/a")
    approve_pending(guard, first.approval_id)  # type: ignore[arg-type]
    clock.advance(61)
    late, _ = call(guard, session, "files__delete_file", path="/a")
    assert late.decision is Decision.REQUIRE_APPROVAL


def test_denied_approval_does_not_allow_the_call(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, RULE)
    session = guard.open_session()
    first, _ = call(guard, session, "files__delete_file", path="/a")
    approve_pending(guard, first.approval_id, approve=False)  # type: ignore[arg-type]
    retry, _ = call(guard, session, "files__delete_file", path="/a")
    assert retry.decision is Decision.REQUIRE_APPROVAL


def test_identical_retries_share_one_pending_approval(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, RULE)
    session = guard.open_session()
    ids = {call(guard, session, "files__delete_file", path="/a")[0].approval_id for _ in range(3)}
    assert len(ids) == 1
    assert len(audit_events(tmp_path, "approval.requested")) == 1


def test_pending_limit_blocks_approval_flooding(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, {**RULE, "approval": {"max_pending_per_session": 2}})
    session = guard.open_session()
    decisions = [call(guard, session, "files__delete_file", path=f"/{n}")[0] for n in range(3)]
    assert [d.decision for d in decisions[:2]] == [Decision.REQUIRE_APPROVAL] * 2
    assert decisions[2].decision is Decision.DENY
    assert decisions[2].reason_code == Reason.APPROVAL_LIMIT


def test_observe_mode_never_creates_approvals(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, {**RULE, "mode": "observe"})
    session = guard.open_session()
    verdict, _ = call(guard, session, "files__delete_file", path="/a")
    assert verdict.decision is Decision.ALLOW and verdict.would_decide is Decision.REQUIRE_APPROVAL
    assert guard.approvals.list_pending() == []


def test_approval_dir_setting_is_used(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "somewhere", 60)
    assert (tmp_path / "somewhere" / "pending").is_dir()
    assert store.list_pending() == []


def test_fingerprint_depends_on_every_component() -> None:
    base = fingerprint("u", "s1", "t", {"a": 1})
    assert fingerprint("u", "s1", "t", {"a": 1}) == base
    assert len({base, fingerprint("v", "s1", "t", {"a": 1}), fingerprint("u", "s2", "t", {"a": 1}),
                fingerprint("u", "s1", "x", {"a": 1}), fingerprint("u", "s1", "t", {"a": 2})}) == 5  # fmt: skip
    assert fingerprint("u", "s1", "t", {"a": 1, "b": 2}) == fingerprint("u", "s1", "t", {"b": 2, "a": 1})


def test_terminal_escaping_makes_control_characters_visible() -> None:
    assert escape_for_terminal("ok\x1b[2J\r\nline") == "ok\\u001b[2J\\u000d\\u000aline"
    assert escape_for_terminal("plain text") == "plain text"

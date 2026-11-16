"""Config fields that need an end-to-end check: loading from files and non-default decisions (§7.4)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentguard.core.guard import Guard
from agentguard.core.lock import save_lock
from agentguard.core.models import Decision
from agentguard.core.policy import ConfigError, parse_config
from tests.helpers import (
    DEFAULT_DECLARATIONS,
    DEFAULT_TOOLS,
    FLOW_CONFIG,
    SECRET_DOC,
    build_guard,
    build_lock,
    call,
    read_data,
)


def test_guard_from_files_honours_lock_audit_and_approval_paths(tmp_path: Path) -> None:
    config = {
        "lock": "locks/tools.lock",
        "audit": {"path": "logs/audit.jsonl"},
        "approval": {"dir": "pending-approvals"},
        "rules": [{"id": "TR-1", "tools": ["files__delete_*"], "effect": "require_approval"}],
        "flow": FLOW_CONFIG,
    }
    (tmp_path / "locks").mkdir()
    (tmp_path / "agentguard.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    save_lock(build_lock(DEFAULT_TOOLS, DEFAULT_DECLARATIONS), tmp_path / "locks" / "tools.lock")

    guard = Guard.from_files(tmp_path / "agentguard.yaml")
    for server, tools in DEFAULT_TOOLS.items():
        guard.filter_tools(server, tools)
    session = guard.open_session()
    verdict, _ = call(guard, session, "files__delete_file", path="/x")

    assert verdict.decision is Decision.REQUIRE_APPROVAL  # the lockfile at the custom path was used
    assert (tmp_path / "logs" / "audit.jsonl").exists()
    assert list((tmp_path / "pending-approvals" / "pending").glob("ap_*.json"))


def test_version_other_than_1_is_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_config("version: 2\n")


def _flow(on_value_match: str, on_session_exposure: str) -> dict[str, object]:
    rule = {
        **FLOW_CONFIG["rules"][0],
        "on_value_match": on_value_match,
        "on_session_exposure": on_session_exposure,
    }  # type: ignore[index]
    return {**FLOW_CONFIG, "rules": [rule]}


@pytest.mark.parametrize(
    ("on_value_match", "on_session_exposure", "leak_decision", "exposure_decision"),
    [
        ("warn", "deny", Decision.WARN, Decision.DENY),
        ("require_approval", "warn", Decision.REQUIRE_APPROVAL, Decision.WARN),
        ("deny", "allow", Decision.DENY, Decision.ALLOW),
    ],
)
def test_flow_rule_decisions_are_configurable(
    tmp_path: Path,
    on_value_match: str,
    on_session_exposure: str,
    leak_decision: Decision,
    exposure_decision: Decision,
) -> None:
    guard = build_guard(tmp_path, {"flow": _flow(on_value_match, on_session_exposure)})
    session = guard.open_session()
    read_data(guard, session, "files__read_document", SECRET_DOC, path="p")
    leak, _ = call(guard, session, "web__search", query=SECRET_DOC[3:60])
    exposure, _ = call(guard, session, "web__search", query="harmless words")
    assert (leak.decision, exposure.decision) == (leak_decision, exposure_decision)


@pytest.mark.parametrize("default", [Decision.DENY, Decision.REQUIRE_APPROVAL, Decision.WARN])
def test_no_rule_matched_values(tmp_path: Path, default: Decision) -> None:
    guard = build_guard(tmp_path, {"defaults": {"no_rule_matched": default.value}})
    verdict, _ = call(guard, guard.open_session(), "web__search", query="q")
    assert verdict.decision is default


def test_denial_is_audited_when_the_agent_retries(tmp_path: Path) -> None:
    from tests.helpers import audit_events

    rules = [{"id": "TR-1", "tools": ["files__delete_*"], "effect": "require_approval"}]
    guard = build_guard(tmp_path, {"rules": rules})
    session = guard.open_session()
    first, _ = call(guard, session, "files__delete_file", path="/a")
    guard.approvals.decide(first.approval_id, approve=False, decided_by="reviewer")  # type: ignore[arg-type]
    call(guard, session, "files__delete_file", path="/a")
    decided = audit_events(tmp_path, "approval.decided")
    assert [(e["outcome"], e["decided_by"]) for e in decided] == [("denied", "reviewer")]
    call(guard, session, "files__delete_file", path="/a")
    assert len(audit_events(tmp_path, "approval.decided")) == 1  # reported once

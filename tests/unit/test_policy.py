"""Policy: strict config (S24, S25), grants, argument rules, defaults, rate limit, stop file (§7)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
import yaml

from agentguard.core.audit import AuditLog
from agentguard.core.models import Decision, Reason
from agentguard.core.policy import ConfigError, glob_regex, parse_config
from tests.helpers import FLOW_CONFIG, FakeClock, audit_events, build_guard, call, read_data


def test_s24_unknown_fields_are_rejected_at_every_level() -> None:
    for text in [
        "mode: enforce\nbogus: 1\n",
        "defaults: {unlisted_tool: deny, surprise: 1}\n",
        "approval: {timeout_seconds: 5, colour: blue}\n",
        "rules: [{id: a, tools: ['*'], effect: deny, extra: 1}]\n",
        "flow: {rules: [{id: f, from: [x], to: {kind: [network]}, typo: 1}]}\n",
    ]:
        with pytest.raises(ConfigError):
            parse_config(text)


def test_duplicate_yaml_keys_and_bad_values_are_rejected() -> None:
    with pytest.raises(ConfigError, match="duplicate"):
        parse_config("mode: enforce\nmode: observe\n")
    with pytest.raises(ConfigError):
        parse_config("mode: loud\n")
    with pytest.raises(ConfigError):
        parse_config("defaults: {unlisted_tool: allow}\n")  # unlisted tools never run
    with pytest.raises(ConfigError):
        parse_config("approval: {channel: web}\n")  # not implemented -> not accepted


def test_server_validation() -> None:
    with pytest.raises(ConfigError):
        parse_config("servers: {a__b: {command: [x]}}\n")
    with pytest.raises(ConfigError):
        parse_config("servers: {a: {command: [x], url: 'http://x'}}\n")
    with pytest.raises(ConfigError):
        parse_config("servers: {a: {}}\n")
    for name in ("PYTHONPATH", "NODE_OPTIONS", "LD_PRELOAD", "https_proxy"):
        with pytest.raises(ConfigError):
            parse_config(f"servers: {{a: {{command: [x], env: {{{name}: v}}}}}}\n")
    assert parse_config("servers: {a: {command: [x], env: {TOKEN: v}}}\n").servers["a"].env == {"TOKEN": "v"}


def test_flow_references_and_rule_ids_are_checked() -> None:
    with pytest.raises(ConfigError, match="unknown destination"):
        parse_config(
            "flow: {rules: [{id: f, from: [x], to: {kind: [network]}, allow_destinations: [nope]}]}\n"
        )
    with pytest.raises(ConfigError, match="duplicate rule ids"):
        parse_config(
            "rules: [{id: a, tools: ['*'], effect: warn}]\n"
            "flow: {rules: [{id: a, from: [x], to: {kind: [network]}}]}\n"
        )


def test_s25_invalid_hot_reload_keeps_the_old_config(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text("mode: enforce\nlock: tool.lock\naudit: {path: audit.jsonl}\n", encoding="utf-8")
    guard = build_guard(tmp_path)
    (tmp_path / "tool.lock").write_text("lock_version: 1\nservers: {}\n", encoding="utf-8")
    assert guard.reload(config_path) is True
    assert guard.config.lock == "tool.lock"

    config_path.write_text("mode: enforce\nbogus: true\n", encoding="utf-8")
    assert guard.reload(config_path) is False
    assert guard.config.lock == "tool.lock"  # unchanged
    assert audit_events(tmp_path, "config.reload_rejected")
    assert audit_events(tmp_path, "config.reloaded")


def test_unexposed_tool_is_denied(tmp_path: Path) -> None:
    guard = build_guard(tmp_path)
    session = guard.open_session()
    verdict, _ = call(guard, session, "web__upload", file="x")
    assert (verdict.decision, verdict.reason_code) == (Decision.DENY, Reason.TOOL_UNAPPROVED)
    assert call(guard, session, "no-namespace")[0].reason_code == Reason.TOOL_UNAPPROVED


def test_grants_limit_what_a_principal_can_call(tmp_path: Path) -> None:
    config = {"principal": "bob", "grants": {"bob": {"tools": ["files__*"]}}}
    guard = build_guard(tmp_path, config)
    session = guard.open_session()
    assert call(guard, session, "files__read_document", path="p")[0].decision is Decision.ALLOW
    verdict, _ = call(guard, session, "web__search", query="q")
    assert (verdict.decision, verdict.reason_code) == (Decision.DENY, Reason.NOT_GRANTED)
    stranger = guard.open_session(principal="mallory")
    assert call(guard, stranger, "files__read_document", path="p")[0].reason_code == Reason.NOT_GRANTED


def test_principal_setting_is_the_session_principal(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, {"principal": "ci-bot"})
    assert guard.open_session().principal == "ci-bot"
    assert audit_events(tmp_path, "session.start")[0]["principal"] == "ci-bot"


def test_argument_rules_first_match_wins(tmp_path: Path) -> None:
    rules = [
        {"id": "TR-1", "tools": ["files__read_document"], "args": {"path": {"glob": ["**/.env"]}}, "effect": "deny"},
        {"id": "TR-2", "tools": ["files__*"], "args": {"path": {"glob": ["/tmp/**"]}}, "effect": "allow"},
        {"id": "TR-3", "tools": ["files__*"], "effect": "warn"},
    ]  # fmt: skip
    guard = build_guard(tmp_path, {"rules": rules})
    session = guard.open_session()
    denied, _ = call(guard, session, "files__read_document", path="/home/me/app/.env")
    assert (denied.decision, denied.rule_ids) == (Decision.DENY, ["TR-1"])
    assert call(guard, session, "files__read_document", path=".env")[0].decision is Decision.DENY
    assert call(guard, session, "files__read_document", path="/tmp/a/b.txt")[0].decision is Decision.ALLOW
    warned, _ = call(guard, session, "files__read_document", path="/etc/hosts")
    assert (warned.decision, warned.rule_ids) == (Decision.WARN, ["TR-3"])


def test_matchers_and_their_semantics() -> None:
    def hit(matcher: dict, value: object, key: str = "x") -> Decision | None:  # type: ignore[type-arg]
        from agentguard.core.policy import first_matching_rule

        config = parse_config(
            yaml.safe_dump({"rules": [{"id": "r", "tools": ["t"], "args": {key: matcher}, "effect": "deny"}]})
        )
        rule = first_matching_rule(config, "t", {key: value})
        return rule.effect if rule else None

    assert hit({"equals": "a"}, "a") and not hit({"equals": "a"}, "b")
    assert hit({"equals": 5}, 5) and not hit({"equals": 5}, 6)
    assert hit({"in": ["a", "b"]}, "b") and not hit({"in": ["a"]}, "c")
    assert hit({"regex": "^rm "}, "rm -rf /") and not hit({"regex": "^rm "}, "ls")
    assert hit({"gt": 10}, 11) and not hit({"gt": 10}, 10)
    assert hit({"lt": 10}, 9) and not hit({"lt": 10}, 10)
    assert hit({"len_gt": 3}, "abcd") and not hit({"len_gt": 3}, "abc")
    assert hit({"len_lt": 3}, "ab") and not hit({"len_lt": 3}, "abc")
    assert hit({"not_glob": ["*.txt"]}, "a.md") and not hit({"not_glob": ["*.txt"]}, "a.txt")
    assert hit({"glob": ["*.txt"], "len_gt": 3}, "abc.txt")  # matchers are ANDed
    assert not hit({"glob": ["*.txt"], "len_gt": 30}, "abc.txt")


def test_matcher_that_cannot_be_evaluated_counts_as_a_hit() -> None:
    from agentguard.core.policy import first_matching_rule

    config = parse_config(
        yaml.safe_dump({"rules": [{"id": "r", "tools": ["t"], "args": {"n": {"gt": 5}}, "effect": "deny"}]})
    )
    assert first_matching_rule(config, "t", {"n": "not a number"}) is not None
    assert first_matching_rule(config, "t", {}) is None  # absent argument: nothing to evaluate


def test_glob_semantics() -> None:
    assert glob_regex("**/.ssh/**").fullmatch("home/me/.ssh/id_rsa")
    assert glob_regex("**/.ssh/**").fullmatch(".ssh/id_rsa")
    assert not glob_regex("*.txt").fullmatch("dir/a.txt")  # `*` stays inside a segment
    assert glob_regex("/tmp/**").fullmatch("/tmp/a/b")


def test_no_rule_matched_default(tmp_path: Path) -> None:
    rules = [{"id": "TR-1", "tools": ["files__read_*"], "effect": "allow"}]
    guard = build_guard(tmp_path, {"rules": rules, "defaults": {"no_rule_matched": "deny"}})
    session = guard.open_session()
    assert call(guard, session, "files__read_document", path="p")[0].decision is Decision.ALLOW
    verdict, _ = call(guard, session, "web__search", query="q")
    assert (verdict.decision, verdict.rule_ids) == (Decision.DENY, ["defaults.no_rule_matched"])


def test_rate_limit_is_per_session_per_tool(tmp_path: Path) -> None:
    clock = FakeClock()
    guard = build_guard(tmp_path, {"rate_limit": {"max_calls": 2, "window_seconds": 10}}, clock=clock)
    session = guard.open_session()
    outcomes = [call(guard, session, "web__search", query="q")[0].decision for _ in range(3)]
    assert outcomes == [Decision.ALLOW, Decision.ALLOW, Decision.DENY]
    assert call(guard, session, "web__fetch", url="http://x.example/")[0].decision is Decision.ALLOW
    clock.advance(11)
    assert call(guard, session, "web__search", query="q")[0].decision is Decision.ALLOW


def test_stop_file_denies_everything_even_in_observe_mode(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, {"mode": "observe", "stop_file": "STOP-NOW"})
    session = guard.open_session()
    assert call(guard, session, "web__search", query="q")[0].decision is Decision.ALLOW
    (tmp_path / "STOP-NOW").write_text("", encoding="utf-8")
    verdict, _ = call(guard, session, "web__search", query="q")
    assert (verdict.decision, verdict.reason_code) == (Decision.DENY, Reason.STOPPED)


def test_warn_decision_allows_and_is_audited(tmp_path: Path) -> None:
    guard = build_guard(tmp_path, {"rules": [{"id": "W", "tools": ["web__*"], "effect": "warn"}]})
    session = guard.open_session()
    verdict, _ = call(guard, session, "web__search", query="q")
    assert verdict.decision is Decision.WARN
    assert audit_events(tmp_path, "call.decided")[-1]["rule_ids"] == ["W"]


def test_audit_failure_denies_in_enforce_mode_only(tmp_path: Path) -> None:
    guard = build_guard(tmp_path)
    session = guard.open_session()
    log_path = guard.audit.path
    log_path.unlink()
    log_path.mkdir()  # appending to a directory fails
    verdict, _ = call(guard, session, "web__search", query="q")
    assert (verdict.decision, verdict.reason_code) == (Decision.DENY, Reason.AUDIT_FAILURE)

    observing = build_guard(tmp_path / "obs", {"mode": "observe"})
    observing.audit.path.unlink()
    observing.audit.path.mkdir()
    assert call(observing, observing.open_session(), "web__search", query="q")[0].decision is Decision.ALLOW


def test_audit_directory_setting_is_used(tmp_path: Path) -> None:
    config = parse_config("audit: {path: logs/a.jsonl}\n", base_dir=tmp_path)
    log = AuditLog(config.resolve(config.audit.path))
    log.write("session.start")
    assert (tmp_path / "logs" / "a.jsonl").exists()
    _ = (os, stat, FLOW_CONFIG, read_data)  # imported for parity with sibling modules

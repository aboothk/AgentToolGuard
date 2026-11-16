"""Policy configuration (strict) and rule evaluation (§7).

Every model forbids unknown fields, and the YAML loader rejects duplicate keys, so a typo in
the policy file stops the gateway instead of silently doing nothing (S24).
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field, PrivateAttr, ValidationError, field_validator, model_validator

from agentguard.core.canonical import canonical_dumps, load_yaml_strict, to_plain
from agentguard.core.lock import sha256_digest
from agentguard.core.models import Decision, Model

FORBIDDEN_ENV_NAMES = {
    "PYTHONPATH",
    "PYTHONHOME",
    "NODE_OPTIONS",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
}


class ConfigError(Exception):
    """The configuration file is missing or invalid."""


# --- servers ------------------------------------------------------------------------------


class ServerConfig(Model):
    command: list[str] | None = None
    url: str | None = None
    auth_env: str | None = None  # name of the env var holding a bearer token (HTTP only)
    env: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> ServerConfig:
        if (self.command is None) == (self.url is None):
            raise ValueError("set exactly one of `command` and `url`")
        if self.command is not None and not self.command:
            raise ValueError("`command` must not be empty")
        if self.auth_env and self.url is None:
            raise ValueError("`auth_env` only applies to `url` servers")
        for name in self.env:
            if name.upper() in FORBIDDEN_ENV_NAMES or name.upper().endswith("_PROXY"):
                raise ValueError(f"environment variable {name} may not be set for a server")
        return self


# --- argument rules -----------------------------------------------------------------------


class ArgMatcher(Model):
    """All given matchers must hold (AND). A matcher that cannot be evaluated counts as a hit."""

    equals: Any = None
    in_: list[Any] | None = Field(default=None, alias="in")
    glob: list[str] | None = None
    not_glob: list[str] | None = None
    regex: str | None = None
    gt: float | None = None
    lt: float | None = None
    len_gt: int | None = None
    len_lt: int | None = None

    model_config = {"extra": "forbid", "populate_by_name": True}

    @field_validator("regex")
    @classmethod
    def _valid_regex(cls, pattern: str | None) -> str | None:
        if pattern is not None:
            re.compile(pattern)
        return pattern


class Rule(Model):
    id: str
    tools: list[str]
    args: dict[str, ArgMatcher] = Field(default_factory=dict)
    effect: Decision


class Grant(Model):
    tools: list[str]


# --- flow ---------------------------------------------------------------------------------


class FlowTarget(Model):
    kind: list[Literal["network", "message"]] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _not_empty(self) -> FlowTarget:
        if not self.kind and not self.tools:
            raise ValueError("`to` needs `kind` or `tools`")
        return self


class FlowRule(Model):
    id: str
    from_: list[str] = Field(alias="from")
    to: FlowTarget
    allow_destinations: list[str] = Field(default_factory=list)
    on_value_match: Decision = Decision.DENY
    on_session_exposure: Decision = Decision.REQUIRE_APPROVAL

    model_config = {"extra": "forbid", "populate_by_name": True}


class Declassifier(Model):
    """A tool whose successful call removes labels from the session (§6.7)."""

    tool: str
    removes: list[str]


class FlowConfig(Model):
    destinations: dict[str, list[str]] = Field(default_factory=dict)
    rules: list[FlowRule] = Field(default_factory=list)
    min_payload_bytes: int = Field(default=0, ge=0)  # skip E3 below this payload size
    fragment_min_chars: int = Field(default=40, ge=32)  # shortest verbatim fragment for E2
    index_max_windows: int = Field(default=200_000, ge=1)
    decode_budget_chars: int = Field(default=1_000_000, ge=1)
    declassify: list[Declassifier] = Field(default_factory=list)

    @model_validator(mode="after")
    def _destinations_exist(self) -> FlowConfig:
        for rule in self.rules:
            for name in rule.allow_destinations:
                if name not in self.destinations:
                    raise ValueError(f"rule {rule.id}: unknown destination set {name!r}")
        return self


# --- the rest -----------------------------------------------------------------------------


class Defaults(Model):
    unlisted_tool: Literal["deny"] = "deny"  # only `deny` is allowed: unlisted tools never run
    no_rule_matched: Decision = Decision.ALLOW


class ApprovalConfig(Model):
    timeout_seconds: int = Field(default=300, gt=0)
    channel: Literal["cli"] = "cli"
    dir: str = ".agentguard/approvals"
    max_pending_per_session: int = Field(default=8, ge=1)


class AuditConfig(Model):
    path: str = ".agentguard/audit.jsonl"


class RateLimit(Model):
    max_calls: int = Field(gt=0)
    window_seconds: float = Field(gt=0)


class Config(Model):
    version: Literal[1] = 1
    mode: Literal["enforce", "observe"] = "enforce"
    principal: str = "local-user"
    lock: str = "agentguard.lock"
    stop_file: str = ".agentguard/STOP"
    call_timeout_seconds: float = Field(default=60, gt=0)
    tools_recheck_seconds: float | None = Field(default=30, gt=0)  # None: only on list_changed
    servers: dict[str, ServerConfig] = Field(default_factory=dict)
    defaults: Defaults = Field(default_factory=Defaults)
    grants: dict[str, Grant] = Field(default_factory=dict)
    rules: list[Rule] = Field(default_factory=list)
    flow: FlowConfig = Field(default_factory=FlowConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    rate_limit: RateLimit | None = None

    _base_dir: Path = PrivateAttr(default=Path("."))

    @field_validator("servers")
    @classmethod
    def _server_names(cls, servers: dict[str, ServerConfig]) -> dict[str, ServerConfig]:
        for name in servers:
            if "__" in name or not name:
                raise ValueError(f"invalid server name {name!r}: must be non-empty, no '__'")
        return servers

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> Config:
        ids = [rule.id for rule in self.rules] + [rule.id for rule in self.flow.rules]
        duplicated = {rule_id for rule_id in ids if ids.count(rule_id) > 1}
        if duplicated:
            raise ValueError(f"duplicate rule ids: {sorted(duplicated)}")
        return self

    def resolve(self, path: str) -> Path:
        """Relative paths in the file are relative to the config file."""
        candidate = Path(path)
        return candidate if candidate.is_absolute() else self._base_dir / candidate

    def policy_hash(self) -> str:
        return sha256_digest(canonical_dumps(self.model_dump(mode="json", by_alias=True)))


def parse_config(text: str, base_dir: Path = Path(".")) -> Config:
    try:
        raw = load_yaml_strict(text)
        config = Config.model_validate(raw if raw is not None else {})
    except (yaml.YAMLError, ValidationError, ValueError) as exc:
        raise ConfigError(str(exc)) from exc
    config._base_dir = base_dir
    return config


def load_config(path: Path) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    return parse_config(text, base_dir=path.resolve().parent)


# --- rule evaluation ----------------------------------------------------------------------


def tool_matches(patterns: list[str], tool_id: str) -> bool:
    return any(fnmatch.fnmatchcase(tool_id, pattern) for pattern in patterns)


def is_granted(config: Config, principal: str, tool_id: str) -> bool:
    """No `grants` section means no restriction. Otherwise the principal must be listed."""
    if not config.grants:
        return True
    grant = config.grants.get(principal)
    return grant is not None and tool_matches(grant.tools, tool_id)


def first_matching_rule(config: Config, tool_id: str, args: dict[str, Any]) -> Rule | None:
    """The first rule whose tool pattern and argument matchers all hold."""
    for rule in config.rules:
        if tool_matches(rule.tools, tool_id) and _args_match(rule.args, args):
            return rule
    return None


def _args_match(matchers: dict[str, ArgMatcher], args: dict[str, Any]) -> bool:
    for name, matcher in matchers.items():
        if name not in args:
            return False  # nothing to evaluate
        try:
            if not _matcher_holds(matcher, args[name]):
                return False
        except (TypeError, ValueError, OverflowError):
            continue  # cannot evaluate -> counts as a hit (§7.2)
    return True


def _matcher_holds(matcher: ArgMatcher, value: Any) -> bool:
    value = to_plain(value)
    fields = matcher.model_fields_set
    checks = [
        "equals" not in fields or value == matcher.equals,
        matcher.in_ is None or value in matcher.in_,
        matcher.glob is None or _path_matches_any(_require_text(value), matcher.glob),
        matcher.not_glob is None or not _path_matches_any(_require_text(value), matcher.not_glob),
        matcher.regex is None or re.search(matcher.regex, _require_text(value)) is not None,
        matcher.gt is None or _require_number(value) > matcher.gt,
        matcher.lt is None or _require_number(value) < matcher.lt,
        matcher.len_gt is None or len(value) > matcher.len_gt,
        matcher.len_lt is None or len(value) < matcher.len_lt,
    ]
    return all(checks)


def _require_text(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("expected a string")
    return value


def _require_number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError("expected a number")
    return float(value)


def _path_matches_any(path: str, patterns: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    return any(glob_regex(pattern).fullmatch(normalized) for pattern in patterns)


def glob_regex(pattern: str) -> re.Pattern[str]:
    """Path-style glob: `*` stays inside one segment, `**` crosses `/`, `**/` may be empty."""
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            parts.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(parts))

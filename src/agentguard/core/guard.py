"""Guard: the single entry point of the core (§4.1, §7.3).

    Guard.before_call(session, call)  -> Verdict      (request side)
    Guard.after_call(session, call, result) -> labels (response side)
    Guard.filter_tools(server, tools)  -> exposed tools (lockfile check)

Adapters (MCP gateway, later LangGraph) only translate their own formats to and from these.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentguard.core.approval import (
    ApprovalError,
    ApprovalRecord,
    ApprovalStore,
    fingerprint,
)
from agentguard.core.audit import AuditError, AuditLog, redact_args
from agentguard.core.destinations import extract_destinations, find_urls_in_text, is_blocked_address
from agentguard.core.flow import FlowEngine
from agentguard.core.index import ValueIndex, iter_string_leaves
from agentguard.core.lock import (
    Exposure,
    LockedTool,
    LockFile,
    check_exposure,
    load_lock,
    lock_hash,
)
from agentguard.core.models import (
    Decision,
    Evidence,
    Finding,
    Reason,
    ToolCall,
    Verdict,
    make_tool_id,
    split_tool_id,
    strictest,
)
from agentguard.core.policy import (
    Config,
    first_matching_rule,
    is_granted,
    load_config,
    tool_matches,
)
from agentguard.core.session import Session, new_session_id

log = logging.getLogger("agentguard")


@dataclass
class LabeledResult:
    result: dict[str, Any]  # returned to the client unchanged
    labels: set[str]


class Guard:
    def __init__(
        self,
        config: Config,
        lock: LockFile,
        audit: AuditLog,
        approvals: ApprovalStore,
        lock_digest: str = "",
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.config = config
        self.lock = lock
        self.audit = audit
        self.approvals = approvals
        self.lock_digest = lock_digest
        self._clock = clock
        self._flow = FlowEngine(config.flow)
        self._policy_hash = config.policy_hash()
        self._exposed: dict[str, set[str]] = {}  # server -> tool names shown to the client

    @classmethod
    def from_files(cls, config_path: Path) -> Guard:
        config = load_config(config_path)
        lock_path = config.resolve(config.lock)
        return cls(
            config=config,
            lock=load_lock(lock_path),
            audit=AuditLog(config.resolve(config.audit.path)),
            approvals=ApprovalStore(config.resolve(config.approval.dir), config.approval.timeout_seconds),
            lock_digest=lock_hash(lock_path),
        )

    # --- sessions -------------------------------------------------------------------------

    def open_session(self, principal: str | None = None) -> Session:
        session = Session(
            session_id=new_session_id(),
            principal=principal or self.config.principal,
            index=ValueIndex(self.config.flow.index_max_windows),
        )
        if self._clock:
            session.clock = self._clock
        self._audit_quietly("session.start", session=session)
        return session

    # --- tool listing ---------------------------------------------------------------------

    def filter_tools(
        self, server: str, tools: list[dict[str, Any]], launch_matches: bool = True
    ) -> list[dict[str, Any]]:
        """Keep only tools that are approved and unchanged; audit everything else (§5.3)."""
        exposed: list[dict[str, Any]] = []
        if not launch_matches:
            self._audit_quietly("tool_drift", server=server, detail="server launch command changed")
            self._exposed[server] = set()
            return []
        for tool in tools:
            state, detail = check_exposure(self.lock, server, tool)
            name = tool.get("name") if isinstance(tool, dict) else None
            tool_id = make_tool_id(server, str(name))
            if state is Exposure.EXPOSED:
                exposed.append(tool)
            elif state in (Exposure.DRIFT_DESCRIPTION, Exposure.DRIFT_STRUCTURE):
                kind = "description_only" if state is Exposure.DRIFT_DESCRIPTION else "structure"
                self._audit_quietly("tool_drift", tool=tool_id, detail=kind)
            elif state is Exposure.INVALID:
                self._audit_quietly("tool_rejected", tool=tool_id, detail=detail)
            else:
                self._audit_quietly("tool_unknown", tool=tool_id, detail=detail)
        self._exposed[server] = {tool["name"] for tool in exposed}
        self._audit_quietly("tool.listed", server=server, exposed=sorted(self._exposed[server]))
        return exposed

    # --- request side ---------------------------------------------------------------------

    def before_call(self, session: Session, call: ToolCall) -> Verdict:
        try:
            raw = self._evaluate(session, call)
            if raw.decision is Decision.REQUIRE_APPROVAL and self.config.mode == "enforce":
                raw = self._resolve_approval(session, call, raw)
        except AuditError:
            return Verdict(decision=Decision.DENY, reason_code=Reason.AUDIT_FAILURE)
        except Exception:  # fail closed on any evaluation error (§7.4)
            log.exception("policy evaluation failed")
            raw = Verdict(decision=Decision.DENY, reason_code=Reason.INTERNAL_ERROR)

        verdict = self._apply_mode(raw)
        try:
            self._audit_decision(session, call, verdict)
        except AuditError as exc:
            if self.config.mode == "enforce":
                return Verdict(decision=Decision.DENY, reason_code=Reason.AUDIT_FAILURE)
            log.error("audit write failed (observe mode, continuing): %s", exc)
        return verdict

    def _apply_mode(self, raw: Verdict) -> Verdict:
        """In observe mode every decision is computed but nothing is blocked (§7.5)."""
        if self.config.mode == "enforce" or raw.reason_code == Reason.STOPPED:
            return raw
        return raw.model_copy(
            update={"decision": Decision.ALLOW, "would_decide": raw.decision, "approval_id": None}
        )

    def _evaluate(self, session: Session, call: ToolCall) -> Verdict:
        """Run the pipeline stages in order; stop at the first deny."""
        findings: list[Finding] = []
        for stage in (
            self._stage_emergency_stop,
            self._stage_tool_identity,
            self._stage_grants,
            self._stage_arg_rules,
            self._stage_destinations,
            self._stage_flow,
            self._stage_rate_limit,
        ):
            findings.extend(stage(session, call))
            if any(finding.decision is Decision.DENY for finding in findings):
                break
        return self._merge(findings)

    def _merge(self, findings: list[Finding]) -> Verdict:
        decision = Decision.ALLOW
        for finding in findings:
            decision = strictest(decision, finding.decision)
        rule_ids = [rule_id for finding in findings for rule_id in finding.rule_ids]

        default = self.config.defaults.no_rule_matched
        if decision is Decision.ALLOW and not rule_ids and default is not Decision.ALLOW:
            reason = Reason.RULE_DENY if default is Decision.DENY else Reason.RULE_APPROVAL
            if default is Decision.WARN:
                reason = Reason.RULE_WARN
            return Verdict(decision=default, reason_code=reason, rule_ids=["defaults.no_rule_matched"])

        deciding = [finding for finding in findings if finding.decision is decision]
        return Verdict(
            decision=decision,
            reason_code=deciding[0].reason_code if deciding else Reason.ALLOWED,
            rule_ids=rule_ids,
            evidence=[item for finding in deciding for item in finding.evidence],
        )

    # --- pipeline stages ------------------------------------------------------------------

    def _locked(self, call: ToolCall) -> LockedTool | None:
        parts = split_tool_id(call.tool_id)
        return self.lock.find(*parts) if parts else None

    def _stage_emergency_stop(self, session: Session, call: ToolCall) -> list[Finding]:
        if self.config.resolve(self.config.stop_file).exists():
            return [Finding(decision=Decision.DENY, reason_code=Reason.STOPPED)]
        return []

    def _stage_tool_identity(self, session: Session, call: ToolCall) -> list[Finding]:
        parts = split_tool_id(call.tool_id)
        if parts and parts[1] in self._exposed.get(parts[0], set()):
            return []
        return [Finding(decision=Decision.DENY, reason_code=Reason.TOOL_UNAPPROVED)]

    def _stage_grants(self, session: Session, call: ToolCall) -> list[Finding]:
        if is_granted(self.config, session.principal, call.tool_id):
            return []
        return [Finding(decision=Decision.DENY, reason_code=Reason.NOT_GRANTED)]

    def _stage_arg_rules(self, session: Session, call: ToolCall) -> list[Finding]:
        rule = first_matching_rule(self.config, call.tool_id, call.args)
        if rule is None:
            return []
        reasons = {
            Decision.DENY: Reason.RULE_DENY,
            Decision.REQUIRE_APPROVAL: Reason.RULE_APPROVAL,
            Decision.WARN: Reason.RULE_WARN,
            Decision.ALLOW: Reason.ALLOWED,
        }
        return [Finding(decision=rule.effect, reason_code=reasons[rule.effect], rule_ids=[rule.id])]

    def _stage_destinations(self, session: Session, call: ToolCall) -> list[Finding]:
        locked = self._locked(call)
        egress = locked.egress if locked else None
        if egress is None:
            self._audit_undeclared_destinations(session, call)
            return []
        if egress.kind != "network":
            return []
        for arg_name in egress.destination_args:
            for destination in extract_destinations(call.args.get(arg_name), "network"):
                if is_blocked_address(destination.host):
                    evidence = Evidence(level="dest", label="blocked_address", detail=destination.host)
                    return [
                        Finding(
                            decision=Decision.DENY,
                            reason_code=Reason.DEST_BLOCKED,
                            evidence=[evidence],
                        )
                    ]
        return []

    def _audit_undeclared_destinations(self, session: Session, call: ToolCall) -> None:
        """A tool without `egress` that receives URL-like arguments deserves a second look."""
        hosts = sorted(
            {
                destination.host
                for text in iter_string_leaves(call.args)
                for destination in find_urls_in_text(text)
            }
        )
        if hosts:
            self._audit("undeclared_destination", session=session, tool=call.tool_id, hosts=hosts)

    def _stage_flow(self, session: Session, call: ToolCall) -> list[Finding]:
        return self._flow.check_call(call, self._locked(call), session)

    def _stage_rate_limit(self, session: Session, call: ToolCall) -> list[Finding]:
        if session.is_rate_limited(call.tool_id, self.config.rate_limit):
            return [Finding(decision=Decision.DENY, reason_code=Reason.RATE_LIMITED)]
        return []

    # --- approvals ------------------------------------------------------------------------

    def _resolve_approval(self, session: Session, call: ToolCall, raw: Verdict) -> Verdict:
        """Allow if a human approved this exact call, otherwise register a pending approval."""
        for expired in self.approvals.sweep_expired():
            self._audit("approval.expired", session=session, approval_id=expired.approval_id)

        digest = fingerprint(session.principal, session.session_id, call.tool_id, call.args)
        used = self.approvals.consume(digest)
        if used is not None:
            self._audit(
                "approval.decided",
                session=session,
                approval_id=used.approval_id,
                decided_by=used.decided_by,
                outcome="approved_and_used",
                tool=call.tool_id,
            )
            return raw.model_copy(update={"decision": Decision.ALLOW, "reason_code": Reason.APPROVED})

        denied = self.approvals.consume_denial(digest)
        if denied is not None:
            self._audit(
                "approval.decided",
                session=session,
                approval_id=denied.approval_id,
                decided_by=denied.decided_by,
                outcome="denied",
                tool=call.tool_id,
            )

        locked = self._locked(call)
        try:
            record, created = self.approvals.request(
                fingerprint_value=digest,
                session_id=session.session_id,
                principal=session.principal,
                tool_id=call.tool_id,
                summary=redact_args(call.args, locked.egress if locked else None),
                rule_ids=raw.rule_ids,
                reason_code=raw.reason_code,
                evidence=[_describe(item) for item in raw.evidence],
                max_pending=self.config.approval.max_pending_per_session,
            )
        except ApprovalError:
            return raw.model_copy(update={"decision": Decision.DENY, "reason_code": Reason.APPROVAL_LIMIT})
        if created:
            self._audit(
                "approval.requested",
                session=session,
                approval_id=record.approval_id,
                tool=call.tool_id,
                rule_ids=raw.rule_ids,
            )
        return raw.model_copy(update={"approval_id": record.approval_id})

    # --- response side --------------------------------------------------------------------

    def after_call(self, session: Session, call: ToolCall, result: dict[str, Any]) -> LabeledResult:
        labels = self._flow.tag_result(session, call.call_id, self._locked(call), result)
        self._apply_declassification(session, call)
        self._audit_quietly(
            "call.result",
            session=session,
            tool=call.tool_id,
            call_id=call.call_id,
            labels=sorted(labels),
            is_error=bool(result.get("isError")),
        )
        if session.index.saturated and not session.saturation_reported:
            session.saturation_reported = True
            self._audit_quietly("index_saturated", session=session, windows=session.index.window_count)
        return LabeledResult(result=result, labels=labels)

    def _apply_declassification(self, session: Session, call: ToolCall) -> None:
        """Only tools named in `flow.declassify` can lower the session's labels (§6.7)."""
        for declassifier in self.config.flow.declassify:
            if tool_matches([declassifier.tool], call.tool_id):
                removed = sorted(session.labels & set(declassifier.removes))
                session.labels -= set(declassifier.removes)
                self._audit_quietly("label.declassified", session=session, tool=call.tool_id, removed=removed)

    # --- hot reload -----------------------------------------------------------------------

    def reload(self, config_path: Path) -> bool:
        """Swap in a new config and lock. An invalid one is rejected and the old one is kept."""
        try:
            config = load_config(config_path)
            lock_path = config.resolve(config.lock)
            lock = load_lock(lock_path)
            audit = (
                self.audit
                if config.resolve(config.audit.path) == self.audit.path
                else AuditLog(config.resolve(config.audit.path))
            )
            approvals = ApprovalStore(config.resolve(config.approval.dir), config.approval.timeout_seconds)
        except Exception as exc:  # any failure keeps the old config
            self._audit_quietly("config.reload_rejected", detail=str(exc)[:300])
            return False
        self.config, self.lock, self.audit, self.approvals = config, lock, audit, approvals
        self.lock_digest = lock_hash(lock_path)
        self._flow = FlowEngine(config.flow)
        self._policy_hash = config.policy_hash()
        self._audit_quietly("config.reloaded", policy_hash=self._policy_hash, lock_hash=self.lock_digest)
        return True

    def record_event(self, event: str, session: Session | None = None, **fields: Any) -> None:
        """Let adapters add their own events (e.g. an unsolicited upstream response)."""
        self._audit_quietly(event, session, **fields)

    # --- audit helpers --------------------------------------------------------------------

    def _audit(self, event: str, session: Session | None = None, **fields: Any) -> None:
        if session is not None:
            fields = {"session_id": session.session_id, "principal": session.principal, **fields}
        self.audit.write(event, **fields)

    def _audit_quietly(self, event: str, session: Session | None = None, **fields: Any) -> None:
        """For events that must not break the caller (listing, results)."""
        try:
            self._audit(event, session, **fields)
        except AuditError as exc:
            log.error("audit write failed for %s: %s", event, exc)

    def _audit_decision(self, session: Session, call: ToolCall, verdict: Verdict) -> None:
        locked = self._locked(call)
        self._audit(
            "call.decided",
            session=session,
            tool=call.tool_id,
            call_id=call.call_id,
            args=redact_args(call.args, locked.egress if locked else None),
            decision=verdict.decision.value,
            would_decide=verdict.would_decide.value if verdict.would_decide else None,
            rule_ids=verdict.rule_ids,
            reason_code=verdict.reason_code,
            evidence=[item.model_dump(exclude_none=True) for item in verdict.evidence],
            approval_id=verdict.approval_id,
            policy_hash=self._policy_hash,
            lock_hash=self.lock_digest,
        )


def _describe(evidence: Evidence) -> str:
    parts = [f"{evidence.level} {evidence.label}"]
    if evidence.detail:
        parts.append(evidence.detail)
    return ": ".join(parts)


__all__ = ["ApprovalRecord", "Guard", "LabeledResult"]

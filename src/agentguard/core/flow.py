"""Data-flow evaluation: labels, egress and the three evidence levels (§6).

Evidence, strongest first:
  E1  a protected value appears verbatim in an argument (also after base64/hex/percent decoding)
  E2  a long verbatim fragment of a protected value appears
  E3  the session read data with a protected label, but nothing matched
The real hard boundary is the destination allowlist. Labels only reduce how often a human has
to confirm something.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass
from typing import Any

from agentguard.core.destinations import Destination, extract_destinations, matches_allowlist
from agentguard.core.detectors import find_secrets
from agentguard.core.index import (
    WINDOW_CHARS,
    WINDOW_STEP,
    IndexHit,
    ValueIndex,
    decode_candidates,
    iter_string_leaves,
)
from agentguard.core.lock import Egress, LockedTool
from agentguard.core.models import SECRET, UNTRUSTED, Decision, Evidence, Finding, Reason, ToolCall
from agentguard.core.policy import FlowConfig, FlowRule, tool_matches
from agentguard.core.session import Session


@dataclass
class _Scan:
    hits: list[IndexHit]
    budget_exhausted: bool


class FlowEngine:
    def __init__(self, config: FlowConfig) -> None:
        self.config = config
        # A fragment of `fragment_min_chars` always contains at least this many stored windows.
        self.min_windows = max(1, (config.fragment_min_chars - WINDOW_CHARS + 1) // WINDOW_STEP)

    # --- request side ---------------------------------------------------------------------

    def check_call(self, call: ToolCall, locked: LockedTool | None, session: Session) -> list[Finding]:
        egress = locked.egress if locked else None
        findings: list[Finding] = []
        for rule in self.config.rules:
            if not self._rule_applies(rule, call.tool_id, egress):
                continue
            exposed = session.labels & set(rule.from_)
            if not exposed:
                continue
            if self._destinations_allowed(rule, call, egress, session):
                continue
            findings.append(self._evidence_for(rule, call, egress, session, exposed))
        return findings

    @staticmethod
    def _rule_applies(rule: FlowRule, tool_id: str, egress: Egress | None) -> bool:
        by_kind = egress is not None and egress.kind in rule.to.kind
        return by_kind or tool_matches(rule.to.tools, tool_id)

    def _allowed_set_names(self, rule: FlowRule, call: ToolCall, session: Session) -> list[str]:
        """The rule's allowlists, unless the current task replaced them for this tool (section 11.1)."""
        for tool_pattern, names in session.destination_overrides.items():
            if tool_matches([tool_pattern], call.tool_id):
                return names
        return rule.allow_destinations

    def _destinations_allowed(
        self, rule: FlowRule, call: ToolCall, egress: Egress | None, session: Session
    ) -> bool:
        """True only if every destination is on the allowlist; anything unparseable is not."""
        names = self._allowed_set_names(rule, call, session)
        if egress is None or not egress.destination_args or not names:
            return False
        patterns = [pattern for name in names for pattern in self.config.destinations[name]]
        found_any = False
        for arg_name in egress.destination_args:
            if arg_name not in call.args:
                continue
            value = call.args[arg_name]
            destinations = extract_destinations(value, egress.kind)
            if not destinations and any(text.strip() for text in iter_string_leaves(value)):
                return False  # a destination we cannot read cannot be allowed
            if not all(matches_allowlist(dest, patterns) for dest in destinations):
                return False
            found_any = found_any or bool(destinations)
        return found_any

    def _evidence_for(
        self,
        rule: FlowRule,
        call: ToolCall,
        egress: Egress | None,
        session: Session,
        exposed: set[str],
    ) -> Finding:
        payload = self._payload_texts(call, egress, scan_all=True)
        protected_labels = set(rule.from_) - {UNTRUSTED}  # untrusted data is never indexed
        scan = self._scan(session.index, payload, protected_labels)

        if scan.hits:
            best = min(scan.hits, key=lambda hit: hit.level)  # "E1" sorts before "E2"
            return Finding(
                decision=rule.on_value_match,
                reason_code=Reason.FLOW_VALUE_MATCH,
                rule_ids=[rule.id],
                evidence=[
                    Evidence(
                        level=best.level,
                        label=best.label,
                        source_call=best.source_call,
                        overlap=best.overlap,
                    )
                ],
            )

        detail = self._exposure_detail(session, scan)
        payload_size = sum(
            len(text.encode("utf-8")) for text in self._payload_texts(call, egress, scan_all=False)
        )
        below_exemption = payload_size < self.config.min_payload_bytes
        if below_exemption and not scan.budget_exhausted:
            return Finding(decision=Decision.ALLOW, reason_code=Reason.ALLOWED, rule_ids=[rule.id])
        return Finding(
            decision=rule.on_session_exposure,
            reason_code=Reason.FLOW_SESSION_EXPOSURE,
            rule_ids=[rule.id],
            evidence=[Evidence(level="E3", label=sorted(exposed)[0], detail=detail)],
        )

    @staticmethod
    def _exposure_detail(session: Session, scan: _Scan) -> str:
        if scan.budget_exhausted:
            return "decode budget exhausted; value check incomplete"
        if session.index.saturated:
            return "value index saturated; fragment check incomplete"
        return "session read data with this label; no verbatim match"

    @staticmethod
    def _payload_texts(call: ToolCall, egress: Egress | None, scan_all: bool) -> list[str]:
        """String leaves of the payload arguments (and destination arguments if `scan_all`).

        Destinations are scanned too because data can hide in a URL or address, but only the
        payload arguments count towards `min_payload_bytes`."""
        if egress is None:
            return []
        names = list(egress.payload_args)
        if scan_all:
            names += egress.destination_args
        return [
            text
            for name in dict.fromkeys(names)
            if name in call.args
            for text in iter_string_leaves(call.args[name])
        ]

    def _scan(self, index: ValueIndex, texts: list[str], labels: set[str]) -> _Scan:
        hits: list[IndexHit] = []
        budget = self.config.decode_budget_chars
        for text in texts:
            budget -= len(text)
            if budget < 0:
                return _Scan(hits, budget_exhausted=True)
            decoded, exhausted = decode_candidates(text, budget)
            budget -= sum(len(item) for item in decoded)
            for candidate in [text, *decoded]:
                hits.extend(index.find(candidate, labels, self.min_windows))
            if exhausted:
                return _Scan(hits, budget_exhausted=True)
        return _Scan(hits, budget_exhausted=False)

    # --- response side --------------------------------------------------------------------

    def tag_result(
        self, session: Session, call_id: str, locked: LockedTool | None, result: dict[str, Any]
    ) -> set[str]:
        """Label an MCP tool result (section 6.7). Returns the labels."""
        if result.get("isError"):
            return set()
        return self.tag_texts(session, call_id, locked, result_texts(result))

    def tag_texts(
        self, session: Session, call_id: str, locked: LockedTool | None, texts: list[str]
    ) -> set[str]:
        """Give a tool's output strings their labels and remember their values."""
        labels = set(locked.labels.produces) if locked else set()
        protected = labels - {UNTRUSTED}
        for text in texts:
            if protected:
                session.index.add(text, protected, call_id)
            for secret in find_secrets(text):
                session.index.add(secret, {SECRET}, call_id)
                labels.add(SECRET)
        session.labels |= labels  # labels only grow; nothing in the result text can lower them
        return labels


def result_texts(result: dict[str, Any]) -> list[str]:
    """All strings in an MCP tool result, plus the leaves of any JSON the text parses to."""
    texts: list[str] = []
    for item in result.get("content") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text" and isinstance(item.get("text"), str):
            texts.append(item["text"])
        elif item.get("type") == "resource" and isinstance(item.get("resource"), dict):
            resource_text = item["resource"].get("text")
            if isinstance(resource_text, str):
                texts.append(resource_text)
    if "structuredContent" in result:
        texts.extend(iter_string_leaves(result["structuredContent"]))
    for text in list(texts):
        stripped = text.lstrip()
        if stripped[:1] in ("{", "["):
            with contextlib.suppress(ValueError):
                texts.extend(iter_string_leaves(json.loads(stripped)))
    return texts


__all__ = ["Destination", "FlowEngine", "result_texts"]

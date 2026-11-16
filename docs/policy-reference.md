# Policy reference

English · [简体中文](policy-reference.zh-CN.md)

`agentguard.yaml`. Unknown fields and duplicate keys are errors. Relative paths are relative to the file. Every field below has a test that shows it changes behaviour.

```yaml
version: 1
mode: enforce                    # enforce | observe
principal: local-user            # the principal of the stdio session
lock: agentguard.lock
stop_file: .agentguard/STOP      # if this file exists, every call is denied (also in observe mode)
call_timeout_seconds: 60         # per downstream call; on timeout only that call fails
tools_recheck_seconds: 30        # re-list every server this often; null = only on list_changed

servers:
  files: {command: ["npx", "-y", "@example/files-mcp", "./docs"], env: {TOKEN: "x"}}
  mail:  {url: "http://127.0.0.1:3001/mcp", auth_env: MAIL_MCP_TOKEN}   # token read from this env var

defaults:
  unlisted_tool: deny            # only `deny` is accepted
  no_rule_matched: allow         # allow | deny | require_approval | warn

grants:                          # no section = no restriction
  local-user: {tools: ["files__*", "mail__send_email"]}

rules:                           # argument rules; the first match wins
  - id: TR-001
    tools: ["files__read_document"]
    args: {path: {glob: ["**/.env", "**/.ssh/**"]}}
    effect: deny                 # allow | deny | require_approval | warn

rate_limit: {max_calls: 30, window_seconds: 60}   # per session, per tool

flow: { ... }                    # below
approval: {timeout_seconds: 300, dir: .agentguard/approvals, max_pending_per_session: 8, channel: cli}
audit: {path: .agentguard/audit.jsonl}
```

## Decisions

`allow`, `deny`, `require_approval`, `warn` (allow and record). Merge order: `deny > require_approval > warn > allow`. The pipeline stops at the first `deny`.

## Argument matchers

`equals`, `in`, `glob`, `not_glob`, `regex`, `gt`, `lt`, `len_gt`, `len_lt`. Matchers inside one rule are ANDed. A matcher that cannot be evaluated (a number expected, a string found) counts as a **hit**. An argument that is absent means the rule does not apply.

Globs are path-style: `*` stays inside one path segment, `**` crosses `/`, and `**/` may match nothing (`**/.env` matches `.env`). Backslashes are treated as `/`.

> Note: the design document's example `path: {not_glob: [...]} effect: deny` would deny every path that is *not* `.env`. To deny `.env`, use `glob`.

`no_rule_matched` applies when no argument rule and no flow rule matched the call (an `allow` rule counts as a match).

## Data flow

```yaml
flow:
  destinations:                          # named allowlists
    corp_mail: ["*@corp.example"]        # e-mails: matched against the whole address
    corp_hosts: ["*.corp.example"]       # URLs: matched against the host name
  rules:
    - id: FL-001
      from: [confidential, secret]       # labels this rule protects (exact match)
      to: {kind: [network, message], tools: []}   # egress kinds and/or tool-name globs
      allow_destinations: [corp_mail, corp_hosts]
      on_value_match: deny               # E1 / E2
      on_session_exposure: require_approval   # E3
  min_payload_bytes: 0                   # skip E3 when the payload args are shorter than this
  fragment_min_chars: 40                 # shortest verbatim fragment that counts as E2 (>= 32)
  index_max_windows: 200000              # per session; beyond it E2 degrades to E3
  decode_budget_chars: 1000000           # per call; beyond it the check falls back to E3
  declassify:                            # tools that lower session labels when called
    - {tool: "dlp__redact", removes: [confidential]}
```

A flow rule fires for a call when the session has seen one of its `from` labels **and** the call targets the rule (egress kind or tool name) **and** the destinations are not all allowlisted. Then:

1. protected value or fragment in a payload or destination argument → `on_value_match` (E1/E2);
2. otherwise → `on_session_exposure` (E3), unless the payload is below `min_payload_bytes`.

All destination arguments must parse and match an allowlist for the rule to be skipped; a destination that cannot be parsed counts as outside. Literal private, loopback, link-local and metadata IP addresses in the destination of a `network` tool are denied (`AG_DEST_BLOCKED`) regardless of rules.

## Reason codes

`AG_ALLOWED`, `AG_APPROVED`, `AG_TOOL_UNAPPROVED`, `AG_NOT_GRANTED`, `AG_RULE_DENY`, `AG_RULE_APPROVAL`, `AG_RULE_WARN`, `AG_DEST_BLOCKED`, `AG_FLOW_VALUE_MATCH`, `AG_FLOW_SESSION_EXPOSURE`, `AG_APPROVAL_LIMIT`, `AG_RATE_LIMITED`, `AG_STOPPED`, `AG_AUDIT_FAILURE`, `AG_INTERNAL_ERROR`, `AG_UPSTREAM_TIMEOUT`, `AG_UPSTREAM_ERROR`. A blocked call is a tool result with `isError: true` and `_meta.agentguard.reason_code`.

## Audit events

`session.start`, `tool.listed`, `tool_drift`, `tool_unknown`, `tool_rejected`, `call.decided`, `call.result`, `approval.requested`, `approval.decided`, `approval.expired`, `config.reloaded`, `config.reload_rejected`, `index_saturated`, `undeclared_destination`, `label.declassified`, `request.rejected`, `response.unsolicited`, `upstream.error`.

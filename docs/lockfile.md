# Lockfile

English · [简体中文](lockfile.zh-CN.md)

`agentguard.lock` is YAML, sorted by server and tool so Git diffs stay small.

```yaml
lock_version: 1
servers:
  web:
    launch_digest: sha256:…          # how the server is started; a change hides the whole server
    tools:
      fetch:
        digest: sha256:…             # the full tool definition
        structural: sha256:…         # the same without descriptive text
        status: approved             # approved | pending | revoked
        approved_at: 2026-11-17T08:00:00Z
        labels: {produces: [untrusted]}
        egress: {kind: network, destination_args: [url], payload_args: [url]}
```

## Digests

- Canonical JSON: sorted keys, NFC strings, number literals kept as written (`1.0` stays `1.0`).
- `digest` covers the whole tool object. `structural` drops `description`, `title`, `examples` and `$comment` everywhere except where those words are property *names*, so "only the wording changed" can be told apart from "the capability changed".
- Tool definitions with duplicate keys, keys that differ only in case (`Description` / `description`), or invalid Unicode are rejected.

## Lifecycle

```text
agentguard lock            connect, record; new and changed tools become pending
agentguard lock diff       differences with poisoning hints
agentguard lock approve    approve pending tools (--server / --tool to narrow)
agentguard lock --check    verify only; exit 1 on any difference or pending tool (CI)
```

`lock approve` re-reads the servers and approves a pending tool only if the server still reports exactly what was recorded, so nothing unreviewed is approved in between. `labels` and `egress` are kept when a tool changes; new tools get suggestions from their names, which you should review.

## Runtime

| | |
|---|---|
| in the lockfile, digest equal, `approved` | shown |
| digest differs | hidden; `tool_drift` with `description_only` or `structure` |
| not in the lockfile | hidden; `tool_unknown` |
| `pending` / `revoked` | hidden |
| invalid definition | hidden; `tool_rejected` |
| `launch_digest` differs | the whole server is hidden |
| `list_changed`, or the periodic re-list | re-checked as above |
| a call to a hidden tool | `AG_TOOL_UNAPPROVED` |

v0.1 is strict: any change needs a new approval.

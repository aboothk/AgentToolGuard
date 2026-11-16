# Architecture

English · [简体中文](architecture.zh-CN.md)

One framework-free core and thin adapters. A test fails if anything in `core/` imports `mcp`, `langgraph`, `langchain`, `typer` or the adapters.

```text
core/  models  canonical  lock  poison  policy  flow  index  destinations  detectors  approval  audit  session  guard
adapters/mcp/  frames  upstream  gateway
cli.py
```

| Module | Job |
|---|---|
| `guard.py` | `before_call`, `after_call`, `filter_tools`; runs the pipeline and merges decisions |
| `lock.py` | digests, lockfile model, drift check, `lock` / `approve` logic |
| `policy.py` | strict config models, grants, argument matchers |
| `flow.py` | flow rules and E1/E2/E3 evidence; labels results |
| `index.py` | per-session hash index of protected values; decoding |
| `destinations.py` | URL/e-mail extraction, host and IP normalization, allowlists |
| `approval.py` | call fingerprints and the file-based approval store |
| `audit.py` | redaction and the hash chain |
| `frames.py` | strict newline-delimited JSON-RPC: size, depth, batches, duplicate keys |
| `upstream.py` | stdio and Streamable HTTP clients to servers; request-id correlation |
| `gateway.py` | the MCP-facing side: lists tools, routes calls, announces changes |

## Request path (`Guard.before_call`)

Stops at the first `deny`:

```text
emergency stop → tool identity → grants → argument rules → destinations → data flow → rate limit
        → merge → (approval) → observe-mode adjustment → audit → forward / refuse
```

Stateless checks come before stateful ones. If the audit write fails in `enforce` mode the call is denied.

## Response path (`Guard.after_call`)

The result goes back **unchanged**. AgentGuard reads it to add labels (`produces` from the lockfile, `secret` for credential-shaped strings), index protected values, and write `call.result`. Error results are not labelled.

## Approvals across processes

`agentguard approve` runs in another process, so approval state lives in directories under `.agentguard/approvals/` (`pending/`, `approved/`, `used/`, `denied/`, `expired/`). Moving a file with `os.replace` is atomic, so a timeout and a late approval cannot both win and an approval cannot be used twice. Only the gateway writes the audit log; the CLI only moves files, and the gateway records the decision when the retry consumes it.

## Value index

Only hashes are stored. Values of 8-31 characters are stored whole, one table per length. Longer values are stored as 32-character windows every 8 characters; a request is searched with a window slid over **every** position, so a fragment at any offset lines up with a stored window. Detail in the module docstring of `core/index.py`.

## Observed cost

Over stdio on a laptop: about 1.3 ms median and 1.8 ms p95 added per call for small arguments (empty or ~190,000-window index). Scanning costs about 0.7 ms per 1,000 characters of payload, plus decoding. Indexing a 1.5 MB response takes about 0.25 s. Reproduce with `python bench/latency/measure.py`.

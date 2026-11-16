# Threat model

English · [简体中文](threat-model.zh-CN.md)

## What the attacker can and cannot do

Can control: web pages and search results, the tool definitions and responses of an MCP server, documents and memory the agent can read.

Cannot control: the AgentGuard process or its host, the lockfile and policy files, the user's real authorization, the approval channel.

## Attacks and defences

| | Attack | Defence | Strength |
|---|---|---|---|
| A1 | A tool definition is swapped after approval (rug-pull) | Digest comparison; the changed tool is not shown | deterministic |
| A2 | A malicious tool is added | Not in the lockfile, not shown | deterministic |
| A3 | A same-named tool shadows another | Forced `server__tool` namespace | deterministic |
| A4 | Poisoned tool description | Hints during `lock diff` / `lock approve` | heuristic; helps the reviewer |
| A5 | Calling something the principal may not | `grants` plus argument rules | deterministic |
| A6 | Protected data sent verbatim or encoded | Value match → deny | deterministic for the value, fragments and common encodings |
| A7 | Protected data rewritten, then sent | Session exposure → approval | relies on a human |
| A8 | Untrusted content induces a risky action | After reading `untrusted`, risky tools need approval | relies on a human |
| A9 | Forged or replayed responses | Request-id correlation; each id is consumed once; a late answer is dropped | deterministic |

## Not defended

See [limitations.md](limitations.md): traffic that bypasses AgentGuard, a fully compromised server's own data, client-side channels, very slow exfiltration, and a user who approves the wrong thing.

## Rules the code follows

- The client cannot choose its principal or session. Nothing a client sends (`_meta`, headers) is used for that.
- Unknown configuration fields, duplicate keys and invalid lockfiles stop startup.
- Evaluation errors, unknown decisions and audit failures (in `enforce`) are denials.
- Denials say the reason code, not the rule that fired; details stay in the audit log.
- Downstream processes get a filtered environment. `PYTHONPATH`, `NODE_OPTIONS`, `LD_PRELOAD` and `*_PROXY` cannot be set for them.
- Batches are refused: they would bypass per-call checks.

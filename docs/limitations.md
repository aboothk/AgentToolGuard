# Limitations

Read this before relying on AgentGuard. It is a *parameter-level* control, not a sandbox.

## What is not protected (threat model §3.3)

- Tools and network connections that do not go through AgentGuard.
- A downstream server that is fully compromised, acting on its own data.
- Exfiltration channels on the client side, for example a client that renders a Markdown image and so makes a request.
- Very slow, byte-by-byte exfiltration.
- A user approving something they should not have approved.

## Why labels cannot be the hard boundary (§6.4)

When an LLM summarizes, translates or rewrites a protected value, the original text no longer appears in the arguments, so E1 and E2 cannot see it. That is inherent to any value-matching design.

- **E1/E2 are deterministic.** A protected value, or a verbatim fragment of at least `flow.fragment_min_chars` (default 40) characters, in an argument is denied. Raw, base64, base64url, hex and percent-encoded forms (two layers deep, within `flow.decode_budget_chars`) are caught.
- **E3 is a conservative upper bound.** "The session read protected data" cannot be denied outright, or nothing could be sent after reading a file. It goes to a human.
- **The destination allowlist is the real boundary.** Labels only reduce how many times a human is asked.

Other consequences:

- Rewritten, translated or summarized data is *not* matched. Such leaks surface only through E3 (approval) when the destination is not allowlisted.
- Fragments shorter than the window (32 characters) are not matched; fragments between 32 and `fragment_min_chars` may or may not be.
- Protected values of 8-31 characters are matched as substrings. A short common value (a first name) in confidential data can produce false positives. Those become approvals or denials only for destinations that are not allowlisted.
- `flow.min_payload_bytes` (default 0 = off) skips E3 for tiny payloads. Turning it on means a low-volume leak can pass without a human.
- When the per-session index is full (`flow.index_max_windows`), later large values are known only by their full hash: whole-argument matches still work, fragment matches degrade to E3, and an `index_saturated` event is written. The same fallback applies when the decode budget runs out.
- Untrusted content is never indexed (there is nothing to protect). Rules with `from: [untrusted]` use session exposure only.
- Labels match exactly. `public < internal < confidential < secret` is a convention; a rule for `confidential` does not cover `secret` unless you list both.
- Labels only grow within a session. Only tools named in `flow.declassify` lower them, and each use is audited.

## Destination checks are on parameters only (§6.6)

AgentGuard never opens a connection; the downstream server does. It therefore can:

- parse URLs and e-mail addresses out of the arguments you declared as `destination_args`;
- normalize host names (including `0x7f.1`, `2130706433`, octal forms) and compare them to the allowlist;
- deny literal private, loopback, link-local and cloud-metadata addresses.

It cannot stop DNS rebinding or follow redirects; the server resolves the name again after AgentGuard has looked at it. If you need connection-level guarantees, put an egress proxy such as pipelock in front of the servers. A destination that cannot be parsed is treated as *not allowlisted*.

Tools without a declared `egress` are not rule-checked on their arguments. AgentGuard does scan their arguments for URLs and writes an `undeclared_destination` audit event, a hint to declare them.

## Other limits of v0.1

- **Stdio towards the client only.** Streamable HTTP towards MCP *servers* works; serving HTTP clients (with tokens) is planned for v0.2.
- **Resources, prompts, sampling and every other MCP request are refused.** They can carry untrusted content into the context and are not part of the label system yet. There is no pass-through option.
- **Drift without `list_changed` is found by polling.** Every `tools_recheck_seconds` (default 30) the gateway re-lists each server. A swap in between is not seen. Streamable HTTP servers do not push `list_changed` to the gateway in v0.1, so they rely on the polling.
- **Hot reload** covers policy, flow, approval, audit and the lockfile. Changes to `servers:` need a restart.
- **Denied approvals are not remembered.** After `agentguard approve --deny`, the agent's retry creates a new pending approval (the denial is audited as `approval.decided`, `outcome: denied`).
- **The audit hash chain** detects edits and removed entries. It cannot detect deletion of the whole file; ship the log somewhere append-only if that matters.
- **`observe` mode still enforces the emergency stop file** (`.agentguard/STOP`), which the design document did not specify.
- **One session per gateway process** (stdio): a session is the process lifetime.
- Policy regular expressions are written by you; a pathological pattern can be slow.

## Not implemented yet (design document §15 M5-M6)

LangGraph middleware, AgentDojo adapter and results, `drift_policy: cue`, resources/prompts in the label system, elicitation-based approval, evidence conflicts ("shadowing").

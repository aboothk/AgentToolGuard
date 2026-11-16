# AgentGuard

**A lockfile for MCP tools, and data-flow rules between them.** AgentGuard answers two questions:

1. *Is this tool still the one I reviewed?* A `agentguard.lock` file you commit to Git, diff in pull requests and verify in CI.
2. *Can this data flow to that tool?* Rules like "`confidential` data must not reach anything outside `corp_mail`", checked on the arguments of every call.

It sits between your MCP client (Claude Code, Cursor, …) and your MCP servers. It does not try to out-scan dedicated content scanners such as [pipelock](https://github.com/pipelab-org/pipelock); it is complementary to them (see [Limitations](docs/limitations.md)).

```text
MCP client ──stdio──> AgentGuard ──stdio──> files server
                         │        ──stdio──> web server
                         │        ──HTTP───> mail server
                 lockfile · policy · audit
```

## What you get

| | |
|---|---|
| **Tool lockfile** | Tools that are new, changed (even only their description) or not approved are never shown to the model. `agentguard lock --check` fails CI on any drift. |
| **Namespaces** | Every tool is exposed as `server__tool`. Two servers cannot shadow each other. |
| **Data-flow rules** | Tools declare what they *produce* (`confidential`, `untrusted`, …) and where they can *send* data. Rules say which labels may go where. |
| **Three levels of evidence** | E1/E2: a protected value (or a ≥40-character fragment, also base64/hex/URL-encoded) appears in an argument → **deny**. E3: the session read protected data but nothing matched → **ask a human**. The destination allowlist is the hard boundary. |
| **Approvals that reach the agent** | The agent is told to retry; you run `agentguard approve ap_xxxx`; the identical retry goes through, once. |
| **Explainable audit log** | Hash-chained JSONL. Arguments are never logged, only length, digest and destination host. `agentguard audit explain` shows the rule, the evidence and which earlier call the data came from. |
| **Observe mode** | `mode: observe` records what *would* be blocked without blocking anything. |

## Try it (no MCP servers needed)

```bash
pip install -e .            # from a checkout; Python 3.11+
python examples/01_rug_pull/run.py
python examples/02_cross_tool_exfil/run.py
python examples/03_approval_flow/run.py
```

Each prints what the agent tried and what AgentGuard did, for example:

```text
  mail to alice@corp.example:        ALLOWED
  mail to evil@attacker.example:     BLOCKED         (AG_FLOW_VALUE_MATCH)
  same, base64-encoded:              BLOCKED         (AG_FLOW_VALUE_MATCH)
  as a web search query:             BLOCKED         (AG_FLOW_VALUE_MATCH)
  an unrelated mail, outside:        NEEDS APPROVAL  (ap_61499a13)
```

## Use it with your servers

```bash
agentguard init                          # writes agentguard.yaml and an empty agentguard.lock
# edit agentguard.yaml: list your servers under `servers:`
agentguard lock                          # connects to them; new/changed tools become "pending"
agentguard lock diff                     # review, with hints about suspicious tool descriptions
# open agentguard.lock: declare `labels.produces` and `egress` for tools that read or send data
agentguard lock approve                  # approve what you reviewed
git add agentguard.yaml agentguard.lock  # and run `agentguard lock --check` in CI
```

Then replace your servers in the client's MCP config with one entry:

```json
{ "mcpServers": { "guarded": { "command": "agentguard", "args": ["serve", "--config", "/path/to/agentguard.yaml"] } } }
```

Start with `mode: observe`, look at `agentguard audit tail`, then switch to `enforce`.

Declaring `produces` and `egress` is the one manual step. `agentguard lock` suggests values from tool and argument names; check them. Example from the lockfile:

```yaml
web:
  tools:
    fetch:
      labels: {produces: [untrusted]}
      egress:
        kind: network
        destination_args: [url]
        payload_args: [url]     # a URL's path and query string can carry data too
```

## Commands

| | |
|---|---|
| `agentguard init` | starter config and lockfile |
| `agentguard serve` | run the gateway on stdin/stdout |
| `agentguard lock [--check]`, `lock diff`, `lock approve` | lockfile lifecycle |
| `agentguard approvals`, `agentguard approve ID [--deny]` | human decisions |
| `agentguard audit tail \| show \| explain \| verify` | inspect the log |

Emergency stop: create the file `.agentguard/STOP` and every call is refused immediately.

## Status

v0.1: stdio gateway, lockfile, policy, data flow, approvals, audit, CLI, three examples, 150+ tests. Not yet: Streamable HTTP *towards the client*, LangGraph middleware, AgentDojo results (v0.2); see [CHANGELOG](CHANGELOG.md) and [limitations](docs/limitations.md). Measured overhead over stdio on a laptop is ~1.8 ms at p95 for small arguments ([`bench/latency`](bench/latency/measure.py)); scanning costs about 0.7 ms per 1,000 characters of payload.

## Documentation

[Architecture](docs/architecture.md) · [Policy reference](docs/policy-reference.md) · [Lockfile](docs/lockfile.md) · [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md) · [Compatibility](docs/compatibility.md)

## License

MIT

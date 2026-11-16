# Compatibility

English · [简体中文](compatibility.zh-CN.md)

| Component | Tested with |
|---|---|
| Python | Tested on 3.13. Written for 3.11+ (no newer syntax); the CI workflow runs 3.11-3.13 but has not been run yet |
| OS | Tested on Windows 11. The CI workflow covers Linux, macOS and Windows but has not been run yet |
| MCP protocol versions answered to clients | 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25 (listed in `adapters/mcp/protocol.py`; an unknown requested version gets the latest of these) |
| `mcp` package | Not a runtime dependency: framing and message routing are implemented in `adapters/mcp/frames.py` and `upstream.py` because the checks needed (batches, duplicate keys, size limits, id correlation) happen before parsing. One integration test (list tools, call an allowed and a blocked tool) drives the gateway with the official client and passes with `mcp` 1.28 and with 2.3. The rest of the gateway tests use a hand-written client and were run with 1.28 installed only. |
| Transports | towards servers: stdio, Streamable HTTP; towards the client: stdio |
| LangGraph adapter | `langgraph` 1.2.22, `langchain` 1.5.0 (the `create_agent` middleware API), `langchain-core` 1.8.1; the extra allows `langchain` 1.5.x and `langgraph` 1.2.x only. Install with the `langgraph` extra. The middleware API changes between releases; only this adapter file depends on it. |
| AgentDojo adapter | `agentdojo` 0.1.35, benchmark `v1.2.2`. Install with the `agentdojo` extra; the exact versions the adapter tests and lockfiles were checked with are in `constraints/adapters.txt` (the CI adapter job installs with `-c`). Tool digests come from Pydantic's JSON schema, so the shipped lockfiles are tied to the AgentDojo and Pydantic versions; `python bench/agentdojo/build_locks.py --check` tells you when to review them again. |

The design document names MCP specification 2026-07-28. This implementation was written against the protocol versions above; check the spec text and re-run the integration tests before relying on newer session semantics.

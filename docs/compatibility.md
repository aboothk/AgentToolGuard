# Compatibility

| Component | Tested with |
|---|---|
| Python | Tested on 3.13. Written for 3.11+ (no newer syntax); the CI workflow runs 3.11-3.13 but has not been run yet |
| OS | Tested on Windows 11. The CI workflow covers Linux, macOS and Windows but has not been run yet |
| MCP protocol versions answered to clients | 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25 (those the installed `mcp` package supports; an unknown requested version gets the latest) |
| `mcp` package | 1.28; used only for protocol version constants. Framing and message routing are implemented in `adapters/mcp/frames.py` and `upstream.py` because the checks needed (batches, duplicate keys, size limits, id correlation) happen before parsing. |
| Transports | towards servers: stdio, Streamable HTTP; towards the client: stdio |
| LangGraph | not supported yet (planned for v0.2; the version range will be listed here) |

The design document names MCP specification 2026-07-28. This implementation was written against the protocol versions above; check the spec text and re-run the integration tests before relying on newer session semantics.

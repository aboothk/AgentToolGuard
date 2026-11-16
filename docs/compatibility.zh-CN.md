# 兼容性

[English](compatibility.md) · 简体中文

| 组件 | 验证范围 |
| --- | --- |
| Python | 在 3.13 测试，代码面向 3.11+，未使用更高版本语法。CI 配置覆盖 3.11–3.13，但尚未通过一次完整运行。 |
| 操作系统 | 在 Windows 11 测试。CI 配置覆盖 Linux、macOS 和 Windows，但尚未通过一次完整运行。 |
| 客户端 MCP 协议版本 | 2024-11-05、2025-03-26、2025-06-18、2025-11-25，列在 `adapters/mcp/protocol.py`。客户端请求未知版本时使用其中最新的版本。 |
| `mcp` 包 | 不是运行时依赖：分帧和路由在 `adapters/mcp/frames.py` 与 `upstream.py` 实现，以便在解析前检查批处理、重复键、大小和 ID 关联。一项集成测试（列出工具、调用一个放行和一个被拦截的工具）用官方客户端驱动网关，在 `mcp` 1.28 和 2.3 下都通过。其余网关测试使用手写客户端，只在安装 1.28 时运行过。 |
| 传输 | 面向服务器支持 stdio、Streamable HTTP，面向客户端支持 stdio。 |
| LangGraph 适配器 | `langgraph` 1.2.22、`langchain` 1.5.0（`create_agent` 中间件 API）、`langchain-core` 1.8.1；扩展依赖只允许 `langchain` 1.5.x 和 `langgraph` 1.2.x。用 `langgraph` 扩展安装。中间件 API 会随版本变化，只有这个适配器文件依赖它。 |
| AgentDojo 适配器 | `agentdojo` 0.1.35，基准 `v1.2.2`。用 `agentdojo` 扩展安装；适配器测试和锁文件所用的确切版本在 `constraints/adapters.txt`（CI 的适配器任务用 `-c` 安装）。工具摘要来自 Pydantic 的 JSON Schema，所以随附的锁文件与 AgentDojo、Pydantic 的版本绑定；运行 `python bench/agentdojo/build_locks.py --check` 可知何时需要重新审核。 |

设计文档提及 MCP 2026-07-28 规范。实现使用上表中的协议版本。依赖较新会话语义前，应核对规范并重跑集成测试。

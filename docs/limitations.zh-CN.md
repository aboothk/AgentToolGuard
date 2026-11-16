# 实现限制

[English](limitations.md) · 简体中文

使用 AgentGuard 前应理解其参数级检查的适用范围。

## 防护范围之外（威胁模型 §3.3）

- 不经过 AgentGuard 的工具和网络连接。
- 完全被攻陷的下游服务器自行处理其可访问的数据。
- 客户端侧外泄通道，例如渲染 Markdown 图片时发起网络请求。
- 极慢、逐字节的外泄。
- 用户错误批准危险调用。

## 标签与原文检测的边界（§6.4）

LLM 对受保护内容进行摘要、翻译或改写后，参数可能不再包含原文，E1/E2 无法直接发现。

- **E1/E2 按值确定性匹配。** 在文档所述策略下，完整值或至少 `flow.fragment_min_chars`（默认 40）字符的原文片段会被拒绝。可检测原始文本、base64、base64url、hex、百分号编码，支持两层解码，受 `flow.decode_budget_chars` 限制。
- **E3 是保守估计。** 会话曾读取机密数据并不意味着所有后续发送都应拒绝，因此转交人工审批。
- **目的地允许列表决定哪些出口获准。** 标签用于减少人工审批频率。

具体影响如下。

- 改写、翻译、摘要内容无法按原文匹配。目的地在允许列表外时，依靠 E3 审批。
- 长值的片段短于 32 字符窗口时无法匹配，32 字符至 fragment_min_chars 之间可能匹配也可能不匹配。
- 8–31 字符的受保护值按子串匹配。机密内容中常见短词可能误报，但仅在列表外目的地触发审批或拒绝。
- `flow.min_payload_bytes` 默认 0，表示不启用豁免。启用后，极小载荷会跳过 E3，低流量泄漏可能无需人工审批。
- 会话索引达到 `flow.index_max_windows` 后，后续大值只记录完整哈希。完整参数匹配仍生效，片段检测退化至 E3，并记录 `index_saturated`。解码预算耗尽时也采用退化处理。
- untrusted 内容不建立受保护值索引，`from: [untrusted]` 仅依赖会话接触情况。
- 标签精确匹配。`public < internal < confidential < secret` 只是约定，仅列 confidential 不会覆盖 secret。
- 会话标签只增不减，仅 `flow.declassify` 指定工具可移除，并记录审计。

## 目的地检查针对参数（§6.6）

网关解析 `destination_args` 中的 URL 和邮件地址，规范化主机及 IP（包括 `0x7f.1`、`2130706433`、八进制形式），与允许列表比较，并拒绝私网、回环、链路本地和云元数据 IP 字面量。

实际连接由下游服务器建立。网关无法阻止 DNS 重绑定或跟踪重定向，因为下游服务器会重新解析域名。如需连接级保证，可在服务器前部署 pipelock 等出口代理。无法解析的目的地按允许列表外处理。

未声明 egress 的工具无法依靠出口声明检查参数。网关仍扫描 URL，并写入 `undeclared_destination` 提示补充声明。显式按工具名匹配的 flow 规则仍可作用于这些工具。

## v0.1 的其他限制

- 客户端仅支持 stdio，下游支持 Streamable HTTP。面向 HTTP 客户端及令牌认证尚未实现。
- resources、prompts、sampling 及其他 MCP 请求被拒绝，因为这些内容还未纳入标签系统，尚无透传选项。
- 未收到 list_changed 时，按 tools_recheck_seconds（默认 30 秒）重新列举工具，轮询间隙的替换无法即时发现。v0.1 的 HTTP 上游依赖轮询。
- 热重载覆盖策略、数据流、审批、审计和锁文件。修改 servers 需要重启。
- 拒绝审批后，重试会创建新待审批请求。原拒绝记录为 `approval.decided`、`outcome: denied`。
- 哈希链用于检测编辑和记录移除，无法检测整份日志被删除。如有需要，应同步到只可追加存储。
- observe 模式也执行紧急停止文件 `.agentguard/STOP`。
- stdio 网关每进程一个会话，会话寿命等于进程寿命。
- 用户编写的病态正则表达式可能导致检查缓慢。

## SDK 与适配器的限制

- **本地工具的函数体不被锁定。** 摘要只覆盖名称、文档字符串以及参数名和类型；实现被修改时无法发现，这部分靠代码审查和依赖锁定。
- **任务保存在 `ContextVar` 中。** 它会跟随 asyncio 任务和 `contextvars.copy_context().run(...)`，不会跟随裸线程；来自这类线程的调用会被拒绝（`AG_NO_TASK`）。
- **LangGraph 中断后，工具节点会从头重新执行。** 审批会再问一次，决策会再审计一次（同一次调用出现重复的 `call.decided` 和 `approval.requested` 记录）；工具本身只执行一次。
- **同一条模型消息中的多个工具调用并行执行，各有自己的任务。** 如果其中两个都需要审批，对 `Command(resume="approve")` 这样的裸回答，LangGraph 会抛出 `RuntimeError`；应按 `tests/adapters/test_langgraph.py` 中的做法，用“中断 id → 回答”的映射恢复。没有得到回答的调用不会执行。
- **run id 和会话保存在进程内存中。** 进程重启后会开始新会话，不会从检查点恢复。
- **AgentDojo 回放不是 LLM 基准。** 它度量的是按 AgentDojo 标准答案行事的脚本化智能体。LLM 运行的结果和它的范围见 `bench/agentdojo/README.zh-CN.md`。部分 AgentDojo 注入任务按“尝试过的调用”计分，被拦截的尝试在那里仍算攻击成功。

## 尚未实现（设计文档 §15 M6）

`drift_policy: cue`、资源和提示词纳入标签体系、基于 elicitation 的审批、证据冲突（“shadowing”）、面向客户端的 Streamable HTTP、其他智能体框架的适配器。

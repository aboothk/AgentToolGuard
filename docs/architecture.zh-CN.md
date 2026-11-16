# 架构

[English](architecture.md) · 简体中文

核心逻辑不依赖智能体框架，适配器保持轻量。测试会检查 `core/`，禁止它导入 `mcp`、`langgraph`、`langchain`、`typer` 或适配器。

```text
core/  models  canonical  lock  poison  policy  flow  index  destinations  detectors  approval  audit  session  guard
adapters/mcp/  frames  upstream  gateway
cli.py
```

| 模块 | 职责 |
| --- | --- |
| `guard.py` | `before_call`、`after_call`、`filter_tools`，执行检查并合并判定 |
| `lock.py` | 摘要、锁文件模型、变更检测、登记与批准 |
| `policy.py` | 严格配置模型、授权和参数匹配 |
| `flow.py` | 数据流规则、E1/E2/E3 证据和结果标签 |
| `index.py` | 会话内受保护值的哈希索引及解码 |
| `destinations.py` | URL 和邮件地址提取、主机及 IP 规范化、允许列表 |
| `approval.py` | 调用指纹和基于文件的审批存储 |
| `audit.py` | 脱敏和审计哈希链 |
| `frames.py` | 换行分隔的 JSON-RPC 严格校验，限制大小、深度、批处理和重复键 |
| `upstream.py` | stdio、Streamable HTTP 上游客户端及请求 ID 关联 |
| `gateway.py` | MCP 工具列表、调用路由和变更通知 |

## 请求路径

`Guard.before_call` 遇到首个 `deny` 即停止检查。

```text
紧急停止 → 工具身份 → 授权 → 参数规则 → 目的地 → 数据流 → 速率限制
        → 合并 → 审批 → 观察模式调整 → 审计 → 转发或拒绝
```

无状态检查先于有状态检查。在 `enforce` 模式下，审计写入失败会拒绝调用。

## 响应路径

`Guard.after_call` 将结果原样返回。它根据锁文件的 `produces` 和凭据特征检测添加标签（凭据标记为 `secret`），为受保护值建立索引并记录 `call.result`。错误结果不添加标签。

## 跨进程审批

`agentguard approve` 在另一个进程运行。审批状态保存在 `.agentguard/approvals/` 的 `pending/`、`approved/`、`used/`、`denied/`、`expired/` 子目录中。`os.replace` 原子移动文件，避免超时与迟到批准同时生效，也避免同一批准被重复使用。网关负责写审计日志，CLI 只移动文件，网关在重试消费审批时记录决定。

## 值索引

只保存哈希。8–31 字符的值按完整内容保存，每种长度一张表。更长内容按 32 字符窗口、8 字符步长建立索引。请求检查则逐字符滑动窗口，因此不同偏移的原文片段也能与索引对齐。细节见 `core/index.py` 的模块说明。

## 已观察到的开销

英文原文报告的笔记本 stdio 测量中，小参数调用增加约 1.3 ms 中位延迟、1.8 ms p95 延迟，索引为空或约有 190,000 个窗口。扫描每 1,000 字符约需 0.7 ms，另加解码成本。为 1.5 MB 响应建索引约需 0.25 s。这些是原文测量条件下的结果，可用 `python bench/latency/measure.py` 在自己的环境复测。

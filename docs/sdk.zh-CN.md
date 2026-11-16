# 在 Python 智能体中使用 AgentGuard

[English](sdk.md) · 简体中文

已有 MCP 客户端可指向 `agentguard serve`。本地 Python 工具、任务级授权、run id 以及应用内审批可通过 SDK 接入。

SDK 不依赖特定智能体框架。框架适配器位于 `agentguard.adapters.*`，也可以自行包装函数。以下为接入结构示意，run_id 和 text 由应用提供。先按下方流程登记并批准工具后再执行调用。

```python
from pathlib import Path

from agentguard import Guard

guard = Guard.from_files(Path("agentguard.yaml"))        # 锁文件路径来自配置

@guard.tool("send_report")                         # 工具名称为 local__send_report
def send_report(to: str, body: str) -> str:
    """发送每周报告。"""
    ...

with guard.task(principal="user_123", run_id=run_id):
    send_report(to="alice@corp.example", body=text)
```

此处使用 Path 对象，符合当前 Guard.from_files 接口。

## 接入步骤

1. 用 `@guard.tool(name)` 或 `guard.wrap(fn, name)` 包装函数。同步、异步函数均支持，保留名称、签名和文档字符串供框架生成 schema。
2. 用 `agentguard lock --from-python my_module:TOOLS` 登记，可指定单个函数或函数的 list、tuple、dict。再运行 `agentguard lock diff --from-python my_module:TOOLS` 和 `agentguard lock approve --from-python my_module:TOOLS`。工具归属保留名称 local。普通 lock 不改动 local 条目，`agentguard lock --check --from-python my_module:TOOLS` 可检查本地工具。
3. 在锁文件中声明 `labels.produces` 和 `egress`。
4. 在 `guard.task(...)` 内运行智能体。完整可运行例子见[中文首页](../README.zh-CN.md#接入-python-函数)。

## 锁定内容

本地工具定义包括名称、文档字符串、参数名称和 JSON 类型。批准后更改这些内容会产生 tool_drift。函数体不参与摘要，需用代码审查和依赖锁定验证实现变更。

## 任务、会话与授权

- `guard.task(principal=..., run_id=...)` 指定主体。任务外调用以 `AG_NO_TASK` 拒绝。
- 同一 Guard 实例、同一主体与 run_id 延续数据标签及值索引，适合中断后恢复。不同 run id 相互隔离，也支持并发。
- 任务通过 ContextVar 传播，可随 asyncio 任务和 `contextvars.copy_context().run(...)` 传递。普通 threading.Thread 或 ThreadPoolExecutor.submit 不自动复制，缺失任务时会拒绝调用。需要时使用 `ctx = contextvars.copy_context(); pool.submit(ctx.run, tool, ...)`。
- `grants={"local__send_report": {"destinations": ["corp_mail"]}}` 在任务期间替换该工具流规则的允许列表，可扩大或收紧范围。工具模式支持 glob，集合必须存在于 flow.destinations，否则创建任务时拒绝。

## 参数

策略看到的是绑定参数并应用默认值后的 JSON。数据库句柄、测试环境等非数据参数可放入 `exclude=("env",)`，从策略、审计和工具定义中排除。其他非 JSON 对象转为 `<TypeName>`，不使用 repr()。`**kwargs` 展开为普通参数。

## 审批

默认需审批的调用抛出 ApprovalRequired 并携带审批 ID。人工执行 `agentguard approve <id>` 后，在相同主体与 run_id 下重试相同调用，仅放行一次。

应用内审批可传入处理器，以下为示意。

```python
from agentguard.sdk import Approved, Denied, Modified

def ask(request):            # 可读取 request.tool_id、脱敏的 .summary、.rule_ids、.evidence 等
    return Approved(decided_by="alice")     # 也可以返回 Denied() 或 Modified({"to": "alice@corp.example"})

with guard.task(run_id=run_id, on_approval=ask): ...
```

- Modified 使新参数重新经过完整检查，若再次需要审批则拒绝。
- 处理器抛出普通异常或返回未知类型时拒绝。
- 需要挂起调用时，可用 guard.add_passthrough(ExceptionType) 注册可原样传播的异常，例如框架中断异常。
- observe 模式不会调用审批处理器。
- 异步工具支持异步审批处理器，同步工具使用异步处理器会被拒绝。

## 返回值

字符串、字典、列表、dataclass、Pydantic 模型和 bytes 的结果被提取为字符串叶节点，按 produces 添加标签并记录。非 JSON 对象使用 str() 转换供检查，记录 result.unserializable。应用获得的原始返回值保持原样。

## 异常

CallBlocked 的 reason_code 表示工具函数未执行，ApprovalRequired 是其子类。可转换为框架工具错误消息。消息仅包含原因码，规则细节在审计日志中。

## 线程安全

决策和结果记录通过锁串行化，包装后的工具可从多个线程调用。工具执行期间不持有该锁，因此长时间运行的工具不会一直占用决策锁。仍需按前述方法传播任务上下文。

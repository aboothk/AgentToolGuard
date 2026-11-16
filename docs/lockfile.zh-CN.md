# 锁文件

[English](lockfile.md) · 简体中文

`agentguard.lock` 使用 YAML，按服务器和工具排序，便于在 Git 中审查差异。

```yaml
lock_version: 1
servers:
  web:
    launch_digest: sha256:…  # 服务器启动方式的摘要，变化时隐藏整个服务器
    tools:
      fetch:
        digest: sha256:…     # 完整工具定义
        structural: sha256:… # 去除描述性文本的结构定义
        status: approved     # approved | pending | revoked
        approved_at: 2026-11-17T08:00:00Z
        labels: {produces: [untrusted]}
        egress: {kind: network, destination_args: [url], payload_args: [url]}
```

## 摘要

- 规范化 JSON 使用排序后的键、NFC 字符串，并保留数字字面形式，例如 `1.0` 不变为 `1`。
- `digest` 覆盖整个工具对象。`structural` 移除各层的 `description`、`title`、`examples` 和 `$comment`，但这些词作为属性名称时保留，从而区分措辞变化与能力变化。
- 重复键、仅大小写不同的键（如 `Description` 与 `description`）或无效 Unicode 会导致工具定义被拒绝。

## 审核流程

| 命令 | 作用 |
| --- | --- |
| `agentguard lock` | 连接服务器并记录定义，新增及变更工具进入 pending |
| `agentguard lock diff` | 查看差异及工具描述投毒提示 |
| `agentguard lock approve` | 批准待审核工具，可用 `--server`、`--tool` 缩小范围 |
| `agentguard lock --check` | 只检查，发现变更或待审核工具即以状态码 1 退出，适用于 CI |

`lock approve` 重新读取服务器，只有仍与已记录定义一致的工具才会获批，避免审核期间出现未审查变更。工具变化时保留 `labels` 和 `egress`。新工具的声明建议来自名称推断，需要人工核对。

## 运行时

| 条件 | 处理 |
| --- | --- |
| 锁文件中存在、摘要一致且 approved | 展示 |
| 摘要不同 | 隐藏，记录 `tool_drift`，区分 `description_only` 与 `structure` |
| 锁文件中不存在 | 隐藏，记录 `tool_unknown` |
| pending 或 revoked | 隐藏 |
| 定义无效 | 隐藏，记录 `tool_rejected` |
| `launch_digest` 不同 | 隐藏整个服务器 |
| 收到 `list_changed` 或定期重新列举工具 | 重新执行上述检查 |
| 调用被隐藏的工具 | 返回 `AG_TOOL_UNAPPROVED` |

v0.1 要求所有变更重新审批。

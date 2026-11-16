# 策略参考

[English](policy-reference.md) · 简体中文

配置文件为 `agentguard.yaml`。未知字段和重复键视为错误。相对路径相对于配置文件解析。原文要求每个配置字段都有证明其影响行为的测试。

下面保留配置键和示例值。示例中的 `flow: { ... }` 是章节占位符，实际配置请换成下方完整的 flow 块。

```yaml
version: 1
mode: enforce                    # 执行模式 | 观察模式
principal: local-user            # stdio 会话主体
lock: agentguard.lock
stop_file: .agentguard/STOP      # 文件存在时拒绝所有调用，观察模式也生效
call_timeout_seconds: 60         # 单次下游调用超时，仅影响该次调用
tools_recheck_seconds: 30        # 重新列举服务器工具的间隔，null 表示仅依赖 list_changed

servers:
  files: {command: ["npx", "-y", "@example/files-mcp", "./docs"], env: {TOKEN: "x"}}
  mail:  {url: "http://127.0.0.1:3001/mcp", auth_env: MAIL_MCP_TOKEN}   # 从该环境变量读取令牌

defaults:
  unlisted_tool: deny            # 仅接受 deny
  no_rule_matched: allow         # allow | deny | require_approval | warn

grants:                          # 省略表示不额外限制
  local-user: {tools: ["files__*", "mail__send_email"]}

rules:                           # 参数规则，首个匹配生效
  - id: TR-001
    tools: ["files__read_document"]
    args: {path: {glob: ["**/.env", "**/.ssh/**"]}}
    effect: deny                 # allow | deny | require_approval | warn

rate_limit: {max_calls: 30, window_seconds: 60}   # 按会话、按工具

flow: { ... }                    # 见下方
approval: {timeout_seconds: 300, dir: .agentguard/approvals, max_pending_per_session: 8, channel: cli}
audit: {path: .agentguard/audit.jsonl}
```

`mode` 可为 enforce 或 observe。`principal` 是 stdio 会话的主体。`stop_file` 存在时所有调用均被拒绝，观察模式也生效。`call_timeout_seconds` 是单次下游调用超时，只影响该次调用。`tools_recheck_seconds` 控制定期重新列举工具的间隔，null 表示仅在收到 list_changed 时重新检查。HTTP 服务器的认证令牌从 auth_env 指定的环境变量读取。

`unlisted_tool` 只接受 deny。未配置 grants 表示不额外限制可用工具。参数规则按顺序采用首个匹配项。速率限制按会话、按工具分别计算。

## 决定

`allow` 放行，`deny` 拒绝，`require_approval` 请求审批，`warn` 放行并记录。合并优先级为 `deny > require_approval > warn > allow`。遇到首个 deny 后停止检查。

## 参数匹配器

支持 `equals`、`in`、`glob`、`not_glob`、`regex`、`gt`、`lt`、`len_gt`、`len_lt`。同一规则中的匹配器按 AND 组合。无法求值的匹配器（例如预期数字但收到字符串）按命中处理。参数缺失时该规则不适用。

glob 使用路径语义。`*` 不跨路径段，`**` 可以跨越 `/`，`**/` 也能匹配空内容，因此 `**/.env` 能匹配 `.env`。反斜杠按 `/` 处理。

设计文档中的 `path: {not_glob: [...]} effect: deny` 会拒绝不在列表内的路径。如果目标是禁止读取 .env，应使用 glob。

没有任何参数规则或数据流规则命中时，应用 `no_rule_matched`。allow 规则也算命中。

## 数据流

```yaml
flow:
  destinations:                          # 具名允许列表
    corp_mail: ["*@corp.example"]        # 邮件匹配完整地址
    corp_hosts: ["*.corp.example"]       # URL 匹配主机名
  rules:
    - id: FL-001
      from: [confidential, secret]       # 受保护标签，精确匹配
      to: {kind: [network, message], tools: []}   # 出口类型或工具名称模式
      allow_destinations: [corp_mail, corp_hosts]
      on_value_match: deny               # E1 / E2
      on_session_exposure: require_approval   # E3
  min_payload_bytes: 0                   # 载荷字节数小于此值时跳过 E3
  fragment_min_chars: 40                 # E2 原文片段的最短字符数，至少 32
  index_max_windows: 200000              # 每会话上限，超限后 E2 退化至 E3
  decode_budget_chars: 1000000           # 每调用预算，耗尽后退化至 E3
  declassify:                            # 调用后可移除会话标签的工具
    - {tool: "dlp__redact", removes: [confidential]}
```

当会话已接触 from 中任一标签、调用命中目标出口类型或工具名称、且目的地未全部获准时，数据流规则生效。

1. 载荷或目的地参数中出现受保护的完整值或片段时，执行 `on_value_match`（E1/E2）。
2. 否则执行 `on_session_exposure`（E3），载荷小于 `min_payload_bytes` 时除外。

邮件允许列表匹配完整地址，URL 允许列表匹配主机名。标签精确匹配。出口类型和工具名模式可任选或组合使用。`fragment_min_chars` 默认 40，最小 32。`index_max_windows` 是每会话索引上限，超限后片段检测退化至 E3。`decode_budget_chars` 是每次调用解码预算，耗尽后也退化至 E3。`declassify` 声明可移除会话标签的工具。

所有目的地参数都必须成功解析且匹配允许列表，才能跳过规则。无法解析的目的地按列表外处理。network 工具目的地中的私网、回环、链路本地和元数据地址 IP 字面量，无论规则如何，都以 `AG_DEST_BLOCKED` 拒绝。

## 原因码

`AG_ALLOWED`、`AG_APPROVED`、`AG_TOOL_UNAPPROVED`、`AG_NOT_GRANTED`、`AG_RULE_DENY`、`AG_RULE_APPROVAL`、`AG_RULE_WARN`、`AG_DEST_BLOCKED`、`AG_FLOW_VALUE_MATCH`、`AG_FLOW_SESSION_EXPOSURE`、`AG_APPROVAL_LIMIT`、`AG_RATE_LIMITED`、`AG_STOPPED`、`AG_AUDIT_FAILURE`、`AG_INTERNAL_ERROR`、`AG_UPSTREAM_TIMEOUT`、`AG_UPSTREAM_ERROR`。

被拦截的调用以工具结果返回，带有 `isError: true` 和 `_meta.agentguard.reason_code`。

## 审计事件

`session.start`、`tool.listed`、`tool_drift`、`tool_unknown`、`tool_rejected`、`call.decided`、`call.result`、`approval.requested`、`approval.decided`、`approval.expired`、`config.reloaded`、`config.reload_rejected`、`index_saturated`、`undeclared_destination`、`label.declassified`、`request.rejected`、`response.unsolicited`、`upstream.error`。

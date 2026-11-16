# AgentDojo

[English](README.md) · 简体中文

本目录包含 agentguard.adapters.agentdojo 适配器、各套件的策略与锁文件（suites/<suite>/）、标准答案工具调用回放及其结果，以及真实 LLM 基准脚本。

当前提供的是无模型回放结果。设计文档要求固定模型、至少三次重复、三种配置的 LLM 基准，需要 API 密钥并产生费用。run_benchmark.py 的循环用脚本化的假模型测试过（`tests/adapters/test_agentdojo.py`），见下文的 LLM 运行说明。

## 标准答案回放（无需模型）

replay.py 将 AgentDojo 标准答案中的工具调用通过 AgentGuard 执行，无需模型或密钥。原文使用 AgentDojo 0.1.35、基准 v1.2.2，每个注入任务与各套件均匀选取的六个用户任务配对，执行过程确定。

- 正常任务完成率使用用户任务的标准答案调用，由 AgentDojo utility 评分。
- 攻击成功率先执行用户任务调用，再执行注入任务调用，由 security 评分。这模拟先完成用户任务、再执行攻击者目标的理想劫持行为。真实模型可能拒绝、改变步骤或提前停止，需用 LLM 基准测量。
- 审批自动回答。全部拒绝和全部批准分别表示人工可能允许行为的下界和上界。

| 套件 | 配置 | 正常任务完成率 | 每任务审批次数 | 攻击成功率 |
|---|---|---:|---:|---:|
| banking | 完整防护，全部拒绝审批 | 44% | 0.56 | 0% |
| banking | 完整防护，全部批准审批 | 81% | 0.56 | 89% |
| banking | 锁文件与参数规则 | 100% | 0.00 | 98% |
| banking | 无防护 | 100% | 0.00 | 98% |
| slack | 完整防护，全部拒绝审批 | 5% | 2.14 | 37% |
| slack | 完整防护，全部批准审批 | 100% | 2.14 | 60% |
| slack | 锁文件与参数规则 | 100% | 0.00 | 100% |
| slack | 无防护 | 100% | 0.00 | 100% |
| travel | 完整防护，全部拒绝审批 | 70% | 0.30 | 0% |
| travel | 完整防护，全部批准审批 | 100% | 0.30 | 57% |
| travel | 锁文件与参数规则 | 100% | 0.00 | 86% |
| travel | 无防护 | 100% | 0.00 | 86% |
| workspace | 完整防护，全部拒绝审批 | 45% | 0.50 | 0% |
| workspace | 完整防护，全部批准审批 | 80% | 0.50 | 36% |
| workspace | 锁文件与参数规则 | 100% | 0.00 | 43% |
| workspace | 无防护 | 100% | 0.00 | 43% |

## 结果解读

- 应与无防护基线比较。即使无防护，不是所有配对的攻击标准答案都会成功，例如 workspace 为 43%、travel 为 86%、banking 为 98%。原因尚未调查。
- 锁文件与参数规则在此回放中未改变结果。套件静态，未编写针对特定参数的规则，也未模拟审批到使用之间的工具变更。该配置用于与设计中的配置保持对应。
- 全部拒绝审批会阻止大部分攻击，也降低正常任务完成率。Slack 任务常先读消息或网页再发布内容，因此频繁触发“读取不可信文本后，修改状态需人工审批”。这说明观察模式及允许列表的重要性。
- 全部批准审批代表允许行为的上界。继续成功的攻击需要审核者识别，网关只保证需要人工决定时会提出请求。
- 值匹配拒绝不能用审批覆盖。banking 的 3 个、workspace 的 8 个正常任务即使批准所有审批仍失败，因为合法任务会复制刚读取的数据到消息或支付参数，例如将 IBAN 放入支付主题。FL-001 将其识别为值匹配，当前策略未为这些任务设置允许列表，应否放行属于策略选择。

## 失败情况

- Slack injection_task_3 要求访问网站。在全部拒绝审批配置下也未阻止，因为抓取网页是只读操作且未携带受保护数据，没有规则触发。get_webpage 的目的地允许列表可以限制访问，但此策略未声明可信网站。
- Slack injection_task_5 使用 security_from_traces 根据尝试发起的工具调用评分，因此被拦截的尝试也算成功。这是四个套件中唯一采用该方式的任务。
- 全部批准审批时，与用户操作类型一致的攻击（发邮件、支付、发帖）可通过，属于 E3 的边界，详见[实现限制](../../docs/limitations.zh-CN.md)。
- 全部拒绝审批时，正常任务大多因 AG_APPROVAL_DENIED 失败，其余因 AG_FLOW_VALUE_MATCH 失败。results/replay.json 列出每个任务及首个被拦截调用。

## 策略编写依据

策略根据工具语义编写，不参考注入任务。测试检查配置中不出现具体任务名称。

- 返回用户自身数据的工具产生 confidential 标签，返回他人文本（收到的邮件、共享文件、评论、网页、消息）的工具产生 untrusted。
- 发送数据的工具声明 egress。
- 策略限制私有数据发往外部目的地，并要求读取不可信文本后的状态修改操作经人工审批。

## 复现

下面保留原文的类 Unix shell 命令，Windows 用户需将虚拟环境 bin 路径换为 Scripts，并按所用 shell 设置环境变量。API 基准会产生费用。

```bash
python -m venv .venv-agentdojo && .venv-agentdojo/bin/pip install agentdojo -e .
.venv-agentdojo/bin/python bench/agentdojo/replay.py --pairs 6      # 结果写入 results/replay.json
.venv-agentdojo/bin/python bench/agentdojo/build_locks.py --check   # 检查锁文件与已安装套件一致
OPENAI_API_KEY=... python bench/agentdojo/run_benchmark.py --model <model> --config full_approvals_denied --repeats 3   # 会产生 API 费用
```

工具摘要依赖 Pydantic 输出的 schema，因此锁文件与生成时的 AgentDojo、Pydantic 版本绑定。build_locks.py --check 可检查是否需要重新审核。

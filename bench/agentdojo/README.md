# AgentDojo

English · [简体中文](README.zh-CN.md)

What is here, and what is not.

**Shipped:** the adapter (`agentguard.adapters.agentdojo`), a policy and a lockfile per suite (`suites/<suite>/`), a ground-truth replay with its results, and the script for the real LLM benchmark.

**Not shipped: any LLM result.** The benchmark of the design document (a fixed model, at least 3 repeats, three configurations) needs an API key and costs money. `run_benchmark.py` has never been run against a real model, and no numbers from it exist. Its loop (guarded executor inside AgentDojo's own benchmark functions, logger, attack loading) is exercised in `tests/adapters/test_agentdojo.py` with a scripted stand-in for the model; a first real run may still hit model-specific problems.

## Ground-truth replay (no model)

`replay.py` plays AgentDojo's own ground-truth tool calls through the tools with AgentGuard in front. It needs no model and no key. AgentDojo 0.1.35, benchmark v1.2.2, every injection task paired with 6 user tasks per suite (spread evenly over the suite); everything is deterministic.

* **Normal tasks completed**: the ground-truth calls of each user task, scored by AgentDojo's `utility`.
* **Attack success**: the ground-truth calls of a user task, then those of an injection task, scored by AgentDojo's `security`. That is an *ideal hijacked agent*: it does its job, then the attacker's. A real model may refuse, improvise or stop early; only the LLM run measures that.
* **Approvals** are answered automatically: *denied* is the lower bound of what a human would allow, *granted* the upper bound.

| suite | configuration | normal tasks completed | approvals asked per task | attack success |
|---|---|---:|---:|---:|
| banking | full, approvals denied | 44% | 0.56 | 0% |
| banking | full, approvals granted | 81% | 0.56 | 89% |
| banking | lockfile + argument rules | 100% | 0.00 | 98% |
| banking | no protection | 100% | 0.00 | 98% |
| slack | full, approvals denied | 5% | 2.14 | 37% |
| slack | full, approvals granted | 100% | 2.14 | 60% |
| slack | lockfile + argument rules | 100% | 0.00 | 100% |
| slack | no protection | 100% | 0.00 | 100% |
| travel | full, approvals denied | 70% | 0.30 | 0% |
| travel | full, approvals granted | 100% | 0.30 | 57% |
| travel | lockfile + argument rules | 100% | 0.00 | 86% |
| travel | no protection | 100% | 0.00 | 86% |
| workspace | full, approvals denied | 45% | 0.50 | 0% |
| workspace | full, approvals granted | 80% | 0.50 | 36% |
| workspace | lockfile + argument rules | 100% | 0.00 | 43% |
| workspace | no protection | 100% | 0.00 | 43% |

Read it like this:

* **Compare against "no protection", not against 100%.** The replay of an attacker's ground truth does not succeed for every pairing even without protection (workspace 43%, travel 86%, banking 98%), (the cause was not investigated).
* **The lockfile and argument rules change nothing here.** The suites are static and no rule is written against a particular argument; the lockfile protects against changes between approval and use, which this replay does not simulate. The row exists so the configurations match the design.
* **"Approvals denied" stops almost every attack and costs normal tasks.** Slack tasks nearly always read a message or web page and then post, so they nearly always ask. That is the price of the rule "after reading text written by others, anything that changes state needs a human", and the number shows why `observe` mode and the allowlists exist.
* **"Approvals granted" is the upper bound** on what a human could allow. Attacks that remain are the ones whose calls a reviewer would have to recognise as attacks; AgentGuard only makes sure a human is asked.
* **Value matches cannot be approved away.** The normal tasks that fail even when approvals are granted (banking 3, workspace 8) are tasks that legitimately copy data they just read into an outgoing message or payment (for example the IBAN into a payment subject). Rule FL-001 denies that as a value match. Whether such a task should be allowed is a policy decision; the policies here have no allowlist for it.

## Failures, as they are

* **slack `injection_task_3`** ("visit a website") is not stopped under "approvals denied": fetching a page is read-only and carries no protected data, so no rule fires. Fetching an attacker's URL is not blocked by data-flow rules; a destination allowlist for `get_webpage` would stop it, but the policy here does not know which sites are fine.
* **slack `injection_task_5`** is scored by AgentDojo from the *attempted* tool calls (`security_from_traces`), so a blocked attempt still counts as success. It is the only such task in these four suites.
* Under "approvals granted" the attacks that follow the user's own kind of action (send mail, send money, post) go through. This is the E3 limit described in `docs/limitations.md`.
* Normal tasks fail under "denied" mostly with `AG_APPROVAL_DENIED`; the rest with `AG_FLOW_VALUE_MATCH`. `results/replay.json` lists each task and its first blocked call.

## How the policies were written

From what the tools are, never from an injection task (a test checks that the files do not name any task):

* tools returning the user's own data produce `confidential`; tools returning text written by other people (received mail, shared files, reviews, web pages, messages) produce `untrusted`;
* tools that send something declare their `egress`;
* the policy says "private data must not leave for outside destinations" and "after untrusted text, tools that change state need a human".

## Reproduce

```bash
python -m venv .venv-agentdojo && .venv-agentdojo/bin/pip install agentdojo -e .
.venv-agentdojo/bin/python bench/agentdojo/replay.py --pairs 6      # results/replay.json
.venv-agentdojo/bin/python bench/agentdojo/build_locks.py --check   # shipped locks match the installed suite
OPENAI_API_KEY=... python bench/agentdojo/run_benchmark.py --model <model> --config full_approvals_denied --repeats 3   # costs money
```

Pydantic's schema output feeds the tool digests, so the shipped lockfiles are tied to the AgentDojo and Pydantic versions they were generated with; `build_locks.py --check` tells you when they need a new review.

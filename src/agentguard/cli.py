"""Command line interface (§5.3, §8.2, §9.3)."""

from __future__ import annotations

import asyncio
import getpass
import logging
import sys
import time
from pathlib import Path
from typing import Annotated, Any

import typer

from agentguard.adapters.mcp.gateway import run_stdio
from agentguard.adapters.mcp.upstream import discover_tools
from agentguard.core.approval import ApprovalError, ApprovalStore, escape_for_terminal
from agentguard.core.audit import AuditError, read_entries, verify_chain
from agentguard.core.lock import (
    Change,
    ChangeKind,
    LockError,
    LockFile,
    ToolStatus,
    approve,
    compute_changes,
    launch_digest,
    load_lock,
    save_lock,
    update_lock,
)
from agentguard.core.poison import scan_tool
from agentguard.core.policy import LOCAL_SERVER, Config, ConfigError, load_config
from agentguard.sdk.local_tools import load_python_tools

app = typer.Typer(help="MCP tool lockfile + data-flow policy gateway.", no_args_is_help=True)
lock_app = typer.Typer(help="Create, review and approve the tool lockfile.", invoke_without_command=True)
audit_app = typer.Typer(help="Inspect the audit log.", no_args_is_help=True)
app.add_typer(lock_app, name="lock")
app.add_typer(audit_app, name="audit")

ConfigOption = Annotated[Path, typer.Option("--config", "-c", help="Path to agentguard.yaml.")]
FromPythonOption = Annotated[
    list[str] | None,
    typer.Option("--from-python", help="module:attribute holding local Python tools (repeatable)."),
]
DEFAULT_CONFIG = Path("agentguard.yaml")

INIT_CONFIG = """\
# AgentGuard policy. Reference: docs/policy-reference.md
version: 1
mode: enforce            # use `observe` first to see what would be blocked without blocking it
principal: local-user

# Put your MCP servers here (and keep only AgentGuard in your MCP client's config):
servers: {}
#  files: {command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "./docs"]}
#  web:   {command: ["uvx", "mcp-server-fetch"]}
#  mail:  {url: "http://127.0.0.1:3001/mcp", auth_env: MAIL_MCP_TOKEN}

flow:
  destinations:
    corp_mail: ["*@corp.example"]          # edit: addresses data may be sent to
    corp_hosts: ["*.corp.example"]         # edit: hosts data may be sent to
  rules:
    - id: FL-001                           # protected data must not reach outside destinations
      from: [confidential, secret]
      to: {kind: [network, message]}
      allow_destinations: [corp_mail, corp_hosts]
      on_value_match: deny
      on_session_exposure: require_approval
    - id: FL-002                           # after reading untrusted content, risky tools need a human
      from: [untrusted]
      to: {tools: ["*__send_*", "*__delete_*"]}
      on_session_exposure: require_approval

rules: []
approval: {timeout_seconds: 300}
audit: {path: .agentguard/audit.jsonl}
"""


def _config(path: Path) -> Config:
    try:
        return load_config(path)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


def _lock(config: Config) -> LockFile:
    try:
        return load_lock(config.resolve(config.lock))
    except LockError as exc:
        typer.echo(f"error: {exc}\nrun `agentguard lock` to create it.", err=True)
        raise typer.Exit(2) from exc


def _launch_digests(config: Config) -> dict[str, str]:
    return {name: launch_digest(cfg.command, cfg.url) for name, cfg in config.servers.items()}


def _discover(config: Config) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    live, errors = asyncio.run(discover_tools(config.servers))
    for where, message in errors.items():
        typer.echo(f"error: {where}: {message}", err=True)
    return live, errors


def _discover_or_exit(
    config: Config, from_python: list[str] | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Discovery for commands that read or write the lockfile. Any failure stops them: a server
    that cannot be reached must never look like 'no differences' or 'tools removed'.

    Local Python tools (`--from-python`) are added under the reserved server name `local`."""
    live, errors = _discover(config)
    if from_python:
        try:
            live[LOCAL_SERVER] = [d for spec in from_python for d in load_python_tools(spec)]
        except (ValueError, ImportError, AttributeError) as exc:
            errors[LOCAL_SERVER] = str(exc)
            typer.echo(f"error: local: {exc}", err=True)
    if errors:
        typer.echo("lockfile not checked or changed because discovery failed", err=True)
        raise typer.Exit(1)
    return live


def _keep_local(from_python: list[str] | None) -> frozenset[str]:
    """Without --from-python the local tools are not in scope, so their entries stay as they are."""
    return frozenset() if from_python else frozenset({LOCAL_SERVER})


# --- init / serve -------------------------------------------------------------------------


@app.command()
def init(
    config: ConfigOption = DEFAULT_CONFIG,
    force: Annotated[bool, typer.Option(help="Overwrite existing files.")] = False,
) -> None:
    """Write a starter agentguard.yaml and an empty agentguard.lock."""
    lock_path = config.parent / "agentguard.lock"
    for path in (config, lock_path):
        if path.exists() and not force:
            typer.echo(f"error: {path} already exists (use --force)", err=True)
            raise typer.Exit(1)
    config.write_text(INIT_CONFIG, encoding="utf-8")
    save_lock(LockFile(), lock_path)
    typer.echo(f"wrote {config} and {lock_path}")
    typer.echo("next: add your servers to the config, then run `agentguard lock`.")


@app.command()
def serve(
    config: ConfigOption = DEFAULT_CONFIG,
    poll_seconds: Annotated[float, typer.Option(hidden=True)] = 2.0,
) -> None:
    """Run the gateway on stdin/stdout (point your MCP client at this command)."""
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="agentguard: %(message)s")
    try:
        asyncio.run(run_stdio(config, poll_seconds))
    except (ConfigError, LockError, AuditError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except KeyboardInterrupt:
        pass


# --- lock ---------------------------------------------------------------------------------


@lock_app.callback()
def lock_command(
    ctx: typer.Context,
    config: ConfigOption = DEFAULT_CONFIG,
    check: Annotated[bool, typer.Option(help="Verify only; exit 1 on any difference (for CI).")] = False,
    from_python: FromPythonOption = None,
) -> None:
    """With no subcommand: connect to the servers and update the lockfile."""
    if ctx.invoked_subcommand is not None:
        return
    settings = _config(config)
    lock_path = settings.resolve(settings.lock)
    old = load_lock(lock_path) if lock_path.exists() else LockFile()
    live = _discover_or_exit(settings, from_python)
    changes = compute_changes(old, live, _launch_digests(settings))

    if check:
        _print_changes(changes)
        if changes:
            raise typer.Exit(1)
        typer.echo("lockfile is up to date and fully approved")
        return
    save_lock(update_lock(old, live, _launch_digests(settings), _keep_local(from_python)), lock_path)
    _print_changes(changes)
    typer.echo(f"wrote {lock_path}. Review with `agentguard lock diff`, then `agentguard lock approve`.")


def _print_changes(changes: list[Change]) -> None:
    labels = {
        ChangeKind.NEW: "new",
        ChangeKind.CHANGED: "changed",
        ChangeKind.REMOVED: "removed",
        ChangeKind.PENDING: "awaiting approval",
        ChangeKind.LAUNCH_CHANGED: "launch command changed",
    }
    for change in changes:
        where = f"{change.server}/{change.tool}" if change.tool else change.server
        detail = f" ({change.detail})" if change.detail else ""
        typer.echo(f"  {labels[change.kind]:<22} {where}{detail}")


@lock_app.command("diff")
def lock_diff(config: ConfigOption = DEFAULT_CONFIG, from_python: FromPythonOption = None) -> None:
    """Show how the servers differ from the lockfile, with poisoning hints."""
    settings = _config(config)
    lock, live = _lock(settings), _discover_or_exit(settings, from_python)
    changes = compute_changes(lock, live, _launch_digests(settings))
    if not changes:
        typer.echo("no differences")
        return
    _print_changes(changes)
    _print_hints(live, {(c.server, c.tool) for c in changes if c.tool is not None})


def _print_hints(live: dict[str, list[dict[str, Any]]], wanted: set[tuple[str, str]]) -> None:
    all_names = [tool["name"] for tools in live.values() for tool in tools]
    for server, tools in live.items():
        for tool in tools:
            if (server, tool["name"]) not in wanted:
                continue
            for hint in scan_tool(tool, all_names):
                snippet = escape_for_terminal(hint.snippet)
                typer.echo(f"  hint [{hint.kind}] {server}/{tool['name']} {hint.path}: {snippet}")


@lock_app.command("approve")
def lock_approve(
    config: ConfigOption = DEFAULT_CONFIG,
    server: Annotated[str | None, typer.Option(help="Only this server.")] = None,
    tool: Annotated[str | None, typer.Option(help="Only this tool.")] = None,
    from_python: FromPythonOption = None,
) -> None:
    """Approve pending tools, but only if the server still reports what was locked."""
    settings = _config(config)
    lock_path = settings.resolve(settings.lock)
    lock, live = _lock(settings), _discover_or_exit(settings, from_python)
    pending = {
        (name, tool_name)
        for name, locked_server in lock.servers.items()
        for tool_name, locked in locked_server.tools.items()
        if locked.status is ToolStatus.PENDING
    }
    _print_hints(live, pending)
    approved = approve(lock, server, tool, live=live)
    save_lock(lock, lock_path)
    for item in approved:
        typer.echo(f"  approved {item}")
    skipped = len([1 for name, tool_name in pending if f"{name}/{tool_name}" not in approved])
    if skipped:
        typer.echo(
            f"{skipped} pending tool(s) not approved (filtered out, or changed since `agentguard lock`)."
        )
    if not approved and not skipped:
        typer.echo("nothing to approve")


# --- approvals ----------------------------------------------------------------------------


def _store(config: Config) -> ApprovalStore:
    return ApprovalStore(config.resolve(config.approval.dir), config.approval.timeout_seconds, time.time)


@app.command("approvals")
def list_approvals(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """List approvals that are waiting for a decision."""
    pending = _store(_config(config)).list_pending()
    if not pending:
        typer.echo("no pending approvals")
    for record in pending:
        typer.echo(
            f"{record.approval_id}  {escape_for_terminal(record.tool_id)}  {', '.join(record.rule_ids)}"
        )


@app.command("approve")
def approve_call(
    approval_id: Annotated[str, typer.Argument(help="Approval id, e.g. ap_7f3a1c2d")],
    config: ConfigOption = DEFAULT_CONFIG,
    deny: Annotated[bool, typer.Option("--deny", help="Reject instead of approving.")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")] = False,
) -> None:
    """Approve (or deny) one pending call. The agent then retries the same call."""
    store = _store(_config(config))
    record = store.get_pending(approval_id)
    if record is None:
        typer.echo(f"error: {approval_id} is not pending (unknown, decided, or expired)", err=True)
        raise typer.Exit(1)
    typer.echo(f"tool:      {escape_for_terminal(record.tool_id)}")
    typer.echo(
        f"principal: {escape_for_terminal(record.principal)}"
        f"   session: {escape_for_terminal(record.session_id)}"
    )
    typer.echo(f"rules:     {escape_for_terminal(', '.join(record.rule_ids))}")
    for line in record.evidence:
        typer.echo(f"evidence:  {escape_for_terminal(line)}")
    for arg, summary in record.summary.items():
        host = f"  -> {summary['domain']}" if "domain" in summary else ""
        typer.echo(
            f"arg:       {escape_for_terminal(arg)}  ({summary['len']} chars){escape_for_terminal(host)}"
        )
    if not yes and not typer.confirm("Deny this call?" if deny else "Approve this call?", default=False):
        raise typer.Exit(1)
    try:
        store.decide(approval_id, approve=not deny, decided_by=getpass.getuser())
    except ApprovalError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo("denied" if deny else "approved: ask the agent to retry the same call")


# --- audit --------------------------------------------------------------------------------


def _audit_path(config: Path) -> Path:
    settings = _config(config)
    return settings.resolve(settings.audit.path)


def _entries(config: Path) -> list[dict[str, Any]]:
    try:
        return read_entries(_audit_path(config))
    except (OSError, AuditError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


def _format_entry(entry: dict[str, Any]) -> str:
    parts = [f"{entry['seq']:>5}", entry["ts"], f"{entry['event']:<18}"]
    for key in ("tool", "decision", "would_decide", "reason_code", "detail"):
        if key in entry:
            parts.append(f"{key}={entry[key]}")
    return " ".join(str(part) for part in parts)


@audit_app.command("tail")
def audit_tail(
    config: ConfigOption = DEFAULT_CONFIG,
    lines: Annotated[int, typer.Option("-n", help="How many entries to show.")] = 20,
    follow: Annotated[bool, typer.Option("--follow", "-f", help="Keep printing new entries.")] = False,
) -> None:
    """Show the latest audit entries."""
    entries = _entries(config)
    for entry in entries[-lines:]:
        typer.echo(_format_entry(entry))
    seen = entries[-1]["seq"] if entries else 0
    while follow:
        time.sleep(1)
        for entry in (e for e in _entries(config) if e["seq"] > seen):
            typer.echo(_format_entry(entry))
            seen = entry["seq"]


@audit_app.command("show")
def audit_show(
    session: Annotated[str, typer.Option("--session", help="Session id, e.g. s_1a2b3c")],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Show the call chain of one session."""
    for entry in _entries(config):
        if entry.get("session_id") == session:
            typer.echo(_format_entry(entry))


@audit_app.command("explain")
def audit_explain(
    seq: Annotated[int, typer.Argument(help="Sequence number of a call.decided entry")],
    config: ConfigOption = DEFAULT_CONFIG,
) -> None:
    """Explain one decision: rules, evidence, and where the protected data came from."""
    entries = _entries(config)
    entry = next((e for e in entries if e["seq"] == seq), None)
    if entry is None or entry["event"] != "call.decided":
        typer.echo(f"error: entry {seq} is not a call.decided entry", err=True)
        raise typer.Exit(1)
    typer.echo(f"{entry['tool']} -> {entry['decision']} ({entry['reason_code']})")
    if entry.get("would_decide"):
        typer.echo(f"  observe mode: would have been {entry['would_decide']}")
    typer.echo(f"  rules: {', '.join(entry.get('rule_ids', [])) or '-'}")
    typer.echo(f"  policy {entry['policy_hash']}   lock {entry['lock_hash']}")
    for evidence in entry.get("evidence", []):
        typer.echo(f"  evidence {evidence['level']} label={evidence['label']}")
        source = evidence.get("source_call")
        if source:
            origin = next(
                (e for e in entries if e.get("call_id") == source and e["session_id"] == entry["session_id"]),
                None,
            )
            typer.echo(f"    data came from call {source}" + (f" ({origin['tool']})" if origin else ""))
        if evidence.get("detail"):
            typer.echo(f"    {evidence['detail']}")


@audit_app.command("verify")
def audit_verify(config: ConfigOption = DEFAULT_CONFIG) -> None:
    """Check the hash chain. Detects edited or removed entries (not a deleted file)."""
    path = _audit_path(config)
    if not path.exists():
        typer.echo(f"error: {path} does not exist", err=True)
        raise typer.Exit(2)
    problems = verify_chain(path)
    for problem in problems:
        typer.echo(f"  {problem}")
    if problems:
        typer.echo("audit log FAILED verification")
        raise typer.Exit(1)
    typer.echo("audit log chain is intact")


if __name__ == "__main__":
    app()

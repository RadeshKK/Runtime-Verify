"""
Production Command Line Interface for RuntimeVerify (Phase 10).
Provides developer-friendly commands for initializing workspaces, dry-run checking actions,
real-time monitoring, policy testing & validation, supervised agent execution,
human approvals, and structured audit querying.
"""

from datetime import datetime, timezone
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import uuid
import yaml

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from runtimeverify.audit.redaction import SecretRedactor

app = typer.Typer(name="verify", help="AI Runtime Verification Framework CLI")
console = Console(soft_wrap=True, highlight=False)
redactor = SecretRedactor()


def sanitize_text(text: Optional[str]) -> str:
    """Sanitizes raw secrets from string output."""
    if not text:
        return ""
    cleaned, _ = redactor.redact_string(str(text))
    return cleaned


def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redacts raw secrets from dictionary structures."""
    cleaned, _ = redactor.redact(data)
    return cleaned


# Default configuration template
DEFAULT_CONFIG = {
    "version": "1.0",
    "workspace": {
        "model_dir": ".runtimeverify/models",
        "session_db": ".runtimeverify/sessions.db",
    },
    "verification": {
        "alpha": 0.05,
        "beta": 0.05,
        "smoothing": 0.01,
        "default_model": "default.json",
    },
    "policy": {
        "default_action": "ALLOW",
        "threshold": 5.0,
    },
}

DEFAULT_RULES = [
    {
        "target_state": "READ_SYSTEM_SECRET",
        "conditions": {
            "action": "read",
            "resource_type": "system_secret",
        },
    },
    {
        "target_state": "WRITE_SOURCE_CODE",
        "conditions": {
            "action": "write",
            "resource_type": "source_code",
        },
    },
]


# ============================================================================
# 1. Workspace Lifecycle & Initialization: init, doctor, status, version
# ============================================================================


@app.command()
def init(
    directory: str = typer.Argument(".", help="Target directory for initialization"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing configuration"),
    json_output: bool = typer.Option(False, "--json", help="Output status as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode: suppress non-essential output"),
):
    """Initializes a new runtime verification workspace."""
    target_dir = os.path.join(directory, ".runtimeverify")
    config_file = os.path.join(target_dir, "config.yaml")
    rules_file = os.path.join(target_dir, "rules.json")
    policy_file = os.path.join(target_dir, "policy.yaml")
    models_dir = os.path.join(target_dir, "models")

    if os.path.exists(target_dir) and not force:
        if json_output:
            console.print(
                json.dumps(
                    {
                        "status": "error",
                        "error": "Workspace is already initialized. Use --force to overwrite.",
                        "code": 2,
                    }
                )
            )
        elif not quiet:
            console.print("[red]Workspace is already initialized. Use --force to overwrite.[/red]")
        raise typer.Exit(code=2)

    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    with open(config_file, "w") as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)

    with open(rules_file, "w") as f:
        json.dump(DEFAULT_RULES, f, indent=2)

    # Initialize a starter policy.yaml if not present
    if not os.path.exists(policy_file):
        default_policy_src = "examples/policies/default.yaml"
        if os.path.exists(default_policy_src):
            with open(default_policy_src, "r") as src_f, open(policy_file, "w") as dst_f:
                dst_f.write(src_f.read())
        else:
            starter_policy = {
                "name": "default-security-policy",
                "version": "1.0",
                "conflict_resolution": "PRIORITY_WINS",
                "default_decision": "ALLOW",
                "policies": [
                    {
                        "id": "block-destructive-rm",
                        "name": "Block Destructive rm",
                        "decision": "BLOCK",
                        "severity": "CRITICAL",
                        "priority": 95,
                        "match": {"command": {"destructive": True}},
                        "reason": "Destructive shell commands are prohibited.",
                    },
                    {
                        "id": "deny-ssh-keys",
                        "name": "Deny SSH Keys",
                        "decision": "BLOCK",
                        "severity": "CRITICAL",
                        "priority": 90,
                        "match": {"path": {"glob": "~/.ssh/*"}},
                        "reason": "Access to SSH private keys is prohibited.",
                    },
                ],
            }
            with open(policy_file, "w") as dst_f:
                yaml.dump(starter_policy, dst_f, default_flow_style=False)

    if json_output:
        console.print(
            json.dumps(
                {
                    "status": "success",
                    "workspace": target_dir,
                    "config": config_file,
                    "rules": rules_file,
                    "policy": policy_file,
                    "models": models_dir,
                },
                indent=2,
            )
        )
    elif quiet:
        console.print(target_dir)
    else:
        console.print(f"[green]Successfully initialized verify workspace at {target_dir}[/green]")


@app.command()
def status(
    directory: str = typer.Option(".", "--dir", "-d", help="Workspace root directory"),
    json_output: bool = typer.Option(False, "--json", help="Output status as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
):
    """Shows RuntimeVerify workspace health, configuration, and engine status."""
    from runtimeverify.policy import load_policy_from_yaml

    target_dir = os.path.join(directory, ".runtimeverify")
    initialized = os.path.exists(target_dir)
    config_file = os.path.join(target_dir, "config.yaml")
    config_exists = os.path.exists(config_file)
    audit_file = os.path.join(target_dir, "audit.log")
    approvals_file = os.path.join(target_dir, "approvals.json")
    models_dir = os.path.join(target_dir, "models")

    # Resolve policy
    policy_path = os.path.join(target_dir, "policy.yaml")
    if not os.path.exists(policy_path):
        policy_path = "examples/policies/default.yaml"

    policy_info: Dict[str, Any] = {"file": policy_path, "rules_count": 0, "name": "none"}
    if os.path.exists(policy_path):
        try:
            pset = load_policy_from_yaml(policy_path)
            policy_info = {"file": policy_path, "rules_count": len(pset.policies), "name": pset.name}
        except Exception:
            policy_info["name"] = "unparseable"

    # Audit records count
    audit_count = 0
    if os.path.exists(audit_file):
        try:
            with open(audit_file, "r") as f:
                audit_count = sum(1 for line in f if line.strip())
        except Exception:
            pass

    # Pending approvals count
    pending_approvals = 0
    if os.path.exists(approvals_file):
        try:
            with open(approvals_file, "r") as f:
                data = json.load(f)
                pending_approvals = sum(1 for item in data.values() if item.get("status") == "PENDING")
        except Exception:
            pass

    # Models count
    models_count = 0
    if os.path.exists(models_dir):
        models_count = len([m for m in os.listdir(models_dir) if m.endswith(".json")])

    # Check Laya semantic engine
    laya_available = False
    try:
        from laya import Router  # noqa: F401

        laya_available = True
    except ImportError:
        pass

    if json_output:
        console.print(
            json.dumps(
                {
                    "version": "0.1.0",
                    "initialized": initialized,
                    "workspace": target_dir,
                    "config_exists": config_exists,
                    "policy": policy_info,
                    "audit_records_count": audit_count,
                    "pending_approvals_count": pending_approvals,
                    "models_count": models_count,
                    "laya_available": laya_available,
                    "python": sys.version.split()[0],
                    "platform": sys.platform,
                },
                indent=2,
            )
        )
        return

    if quiet:
        console.print("initialized" if initialized else "uninitialized")
        return

    console.print(Panel("[bold cyan]RuntimeVerify System Status[/bold cyan]"))
    console.print(f"  * [bold]Version:[/bold] 0.1.0 (Python {sys.version.split()[0]} on {sys.platform})")
    console.print(
        f"  * [bold]Workspace:[/bold] {'[green]Initialized[/green] (' + target_dir + ')' if initialized else '[yellow]Uninitialized[/yellow]'}"
    )
    console.print(
        f"  * [bold]Active Policy:[/bold] {policy_info['name']} ({policy_info['rules_count']} rules from {policy_info['file']})"
    )
    console.print(f"  * [bold]Audit Records:[/bold] {audit_count} records logged")
    console.print(
        f"  * [bold]Pending Approvals:[/bold] {'[yellow]' + str(pending_approvals) + '[/yellow]' if pending_approvals else '0'}"
    )
    console.print(f"  * [bold]Trained Models:[/bold] {models_count} model checkpoint(s)")
    console.print(
        f"  * [bold]Semantic Engine (Laya):[/bold] {'[green]Available[/green]' if laya_available else '[dim]Not installed (optional)[/dim]'}"
    )


@app.command()
def version(
    json_output: bool = typer.Option(False, "--json", help="Output version info as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Output version string only"),
):
    """Prints framework version information."""
    ver = "0.1.0"
    if quiet:
        console.print(ver)
        return
    if json_output:
        console.print(
            json.dumps(
                {
                    "framework": "runtimeverify",
                    "version": ver,
                    "python": sys.version.split()[0],
                    "platform": platform.platform(),
                },
                indent=2,
            )
        )
        return
    console.print(f"AI Runtime Verification Framework (verify) [bold cyan]v{ver}[/bold cyan]")


@app.command()
def doctor():
    """Performs verification workspace diagnostic checks."""
    all_pass = True
    console.print("[bold cyan]Running verification environment diagnostics...[/bold cyan]\n")

    # 1. Check workspace
    if os.path.exists(".runtimeverify"):
        console.print("  [green][PASS][/green] .runtimeverify configuration folder found.")
    else:
        console.print("  [yellow][WARN][/yellow] No .runtimeverify configuration folder found in current directory.")
        all_pass = False

    # 2. Check defaults
    if os.path.exists(".runtimeverify/models/default.json"):
        console.print("  [green][PASS][/green] Default trained model found.")
    else:
        console.print("  [yellow][WARN][/yellow] Default trained model not found. Run 'verify train'.")
        all_pass = False

    # 3. Check libraries
    try:
        import pydantic

        console.print(f"  [green][PASS][/green] Pydantic library available (version {pydantic.__version__}).")
    except ImportError:
        console.print("  [red][FAIL][/red] Pydantic library not found.")
        all_pass = False

    try:
        from laya import Router  # noqa: F401

        console.print("  [green][PASS][/green] Laya semantic decision engine library available.")
    except ImportError:
        console.print("  [dim][INFO][/dim] Laya semantic engine not installed (optional, 'pip install laya').")

    if all_pass:
        console.print("\n[bold green]Doctor checks completed successfully! Workspace is healthy.[/bold green]")
    else:
        console.print(
            "\n[bold yellow]Doctor identified warning markers. Follow recommendations to resolve.[/bold yellow]"
        )


# ============================================================================
# 2. Pre-Execution Inspection: check
# ============================================================================


@app.command()
def check(
    action_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Action type: shell, filesystem, network, process, git"
    ),
    target: Optional[str] = typer.Option(
        None, "--target", help="Action target: path, command string, URL, branch, etc."
    ),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Shortcut for filesystem read action on a file path"),
    command: Optional[str] = typer.Option(None, "--command", "-c", help="Shortcut for shell command execution action"),
    policy_path: str = typer.Option(
        "examples/policies/default.yaml", "--policy", "-p", help="Path to policy YAML file"
    ),
    mode: str = typer.Option("enforce", "--mode", "-m", help="Interception mode: observe or enforce"),
    agent_id: str = typer.Option("cli-agent", "--agent", "-a", help="Agent identifier"),
    session_id: str = typer.Option("cli-session", "--session", "-s", help="Session identifier"),
    json_output: bool = typer.Option(False, "--json", help="Output evaluation result as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode: emit decision status only"),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose mode: emit detailed rule and trace diagnostics"
    ),
):
    """
    Evaluates an intended action against active security policies.
    Exit codes:
      0 = ALLOW
      1 = Error / invalid arguments
      2 = BLOCK
      3 = REVIEW required
    """
    from runtimeverify.interception import (
        Action,
        ActionType,
        ExecutionContext,
        ExecutionBlockedError,
        ExecutionReviewRequiredError,
        InterceptionMode,
        RuntimeActionInterceptor,
    )
    from runtimeverify.policy import PolicyEvaluator, load_policy_from_yaml

    # 1. Determine action parameters
    if file is not None:
        act_type = ActionType.FILESYSTEM
        raw_target = file
        action = Action.filesystem(operation="read", path=raw_target, session_id=session_id, agent_id=agent_id)
    elif command is not None:
        act_type = ActionType.SHELL
        raw_target = command
        action = Action.shell(command=raw_target, session_id=session_id, agent_id=agent_id)
    elif action_type is not None and target is not None:
        try:
            act_type = ActionType(action_type.lower())
        except ValueError:
            valid_types = ", ".join([t.value for t in ActionType])
            if json_output:
                console.print(json.dumps({"error": f"Invalid action type '{action_type}'. Valid types: {valid_types}"}))
            else:
                console.print(f"[red]Invalid action type '{action_type}'. Valid types: {valid_types}[/red]")
            raise typer.Exit(code=1)

        raw_target = target
        if act_type == ActionType.SHELL:
            action = Action.shell(command=raw_target, session_id=session_id, agent_id=agent_id)
        elif act_type == ActionType.FILESYSTEM:
            action = Action.filesystem(operation="read", path=raw_target, session_id=session_id, agent_id=agent_id)
        elif act_type == ActionType.NETWORK:
            action = Action.network(url=raw_target, session_id=session_id, agent_id=agent_id)
        elif act_type == ActionType.PROCESS:
            action = Action.process(command_line=raw_target, session_id=session_id, agent_id=agent_id)
        elif act_type == ActionType.GIT:
            action = Action.git(operation="push", branch=raw_target, session_id=session_id, agent_id=agent_id)
        else:
            action = Action(
                action_type=act_type,
                name="execute",
                target=raw_target,
                context=ExecutionContext(session_id=session_id, agent_id=agent_id),
                agent_id=agent_id,
                session_id=session_id,
            )
    else:
        if json_output:
            console.print(json.dumps({"error": "Must provide either --file, --command, or both --type and --target."}))
        else:
            console.print("[red]Must provide either --file, --command, or both --type and --target.[/red]")
        raise typer.Exit(code=1)

    # 2. Resolve policy
    resolved_policy_path = policy_path
    if not os.path.exists(resolved_policy_path) and os.path.exists(".runtimeverify/policy.yaml"):
        resolved_policy_path = ".runtimeverify/policy.yaml"

    try:
        policy_set = load_policy_from_yaml(resolved_policy_path)
    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": f"Failed to load policy file: {e}"}))
        else:
            console.print(f"[red]Failed to load policy file '{resolved_policy_path}': {e}[/red]")
        raise typer.Exit(code=1)

    # 3. Interceptor setup
    interceptor_mode = InterceptionMode(mode.lower())
    interceptor = RuntimeActionInterceptor(
        mode=interceptor_mode,
        policy_evaluator=PolicyEvaluator(policy_set=policy_set),
    )

    clean_target = sanitize_text(raw_target)

    # 4. Evaluation
    try:
        decision, _ = interceptor.intercept(action, execute_fn=lambda act: None)
        status_val = decision.status
        reason_val = sanitize_text(decision.reason)
        pol_id = decision.policy_decision.policy_id if decision.policy_decision else "default"
        severity_val = decision.policy_decision.severity.value if decision.policy_decision else "LOW"

        if json_output:
            console.print(
                json.dumps(
                    {
                        "decision": status_val,
                        "status": status_val,
                        "execution_permitted": decision.execution_permitted,
                        "action_type": action.action_type.value,
                        "target": clean_target,
                        "policy_id": pol_id,
                        "severity": severity_val,
                        "reason": reason_val,
                        "mode": mode,
                        "agent_id": agent_id,
                        "session_id": session_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    indent=2,
                )
            )
        elif quiet:
            console.print(status_val)
        else:
            status_style = "green" if status_val == "ALLOW" else "yellow"
            console.print(
                Panel(
                    f"[{status_style}]Decision: {status_val}[/{status_style}]",
                    title=f"Action Check: {action.action_id}",
                    border_style=status_style,
                )
            )
            console.print(f"  * [bold]Target:[/bold] {clean_target}")
            console.print(f"  * [bold]Policy ID:[/bold] {pol_id}")
            console.print(f"  * [bold]Permitted:[/bold] {decision.execution_permitted}")
            console.print(f"  * [bold]Reason:[/bold] {reason_val}")
            if verbose and decision.policy_decision and decision.policy_decision.matched_rule:
                console.print(f"  * [bold]Matched Rule:[/bold] {decision.policy_decision.matched_rule.get('name')}")

        if status_val == "REVIEW":
            raise typer.Exit(code=3)
        raise typer.Exit(code=0)

    except ExecutionBlockedError as e:
        clean_reason = sanitize_text(e.reason)
        if json_output:
            console.print(
                json.dumps(
                    {
                        "decision": "BLOCK",
                        "status": "BLOCK",
                        "execution_permitted": False,
                        "action_type": action.action_type.value,
                        "target": clean_target,
                        "policy_id": e.policy_id,
                        "severity": e.severity,
                        "reason": clean_reason,
                        "mode": mode,
                        "agent_id": agent_id,
                        "session_id": session_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    indent=2,
                )
            )
        elif quiet:
            console.print("BLOCK")
        else:
            console.print(
                Panel(
                    "[red bold]Decision: BLOCK[/red bold]",
                    title=f"Action Check: {action.action_id}",
                    border_style="red",
                )
            )
            console.print(f"  * [bold]Target:[/bold] {clean_target}")
            console.print(f"  * [bold]Policy ID:[/bold] {e.policy_id}")
            console.print(f"  * [bold]Severity:[/bold] {e.severity}")
            console.print(f"  * [bold]Reason:[/bold] {clean_reason}")
        raise typer.Exit(code=2)

    except ExecutionReviewRequiredError as e:
        clean_reason = sanitize_text(e.reason)
        if json_output:
            console.print(
                json.dumps(
                    {
                        "decision": "REVIEW",
                        "status": "REVIEW",
                        "execution_permitted": False,
                        "action_type": action.action_type.value,
                        "target": clean_target,
                        "policy_id": e.policy_id,
                        "reason": clean_reason,
                        "mode": mode,
                        "agent_id": agent_id,
                        "session_id": session_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                    indent=2,
                )
            )
        elif quiet:
            console.print("REVIEW")
        else:
            console.print(
                Panel(
                    "[yellow bold]Decision: REVIEW REQUIRED[/yellow bold]",
                    title=f"Action Check: {action.action_id}",
                    border_style="yellow",
                )
            )
            console.print(f"  * [bold]Target:[/bold] {clean_target}")
            console.print(f"  * [bold]Policy ID:[/bold] {e.policy_id}")
            console.print(f"  * [bold]Reason:[/bold] {clean_reason}")
        raise typer.Exit(code=3)


# ============================================================================
# 3. Supervised Execution: run
# ============================================================================


@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def run(
    ctx: typer.Context,
    command: List[str] = typer.Argument(None, help="Agent command to execute"),
    policy_path: str = typer.Option("examples/policies/default.yaml", "--policy", "-p", help="Policy YAML path"),
    agent_id: str = typer.Option("cli-agent", "--agent", "-a", help="Agent identifier"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s", help="Session identifier"),
    mode: str = typer.Option("enforce", "--mode", "-m", help="Interception mode: enforce or observe"),
    json_output: bool = typer.Option(False, "--json", help="Output execution summary as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode: suppress wrapper banners"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode: emit execution details"),
):
    """
    Executes an agent process command under RuntimeVerify supervision.
    Usage:
      runtimeverify run --policy policy.yaml -- python my_agent.py
    """
    from runtimeverify.interception import (
        Action,
        ExecutionBlockedError,
        ExecutionReviewRequiredError,
        InterceptionMode,
        RuntimeActionInterceptor,
    )
    from runtimeverify.policy import PolicyEvaluator, load_policy_from_yaml

    cmd_args = list(command or []) + list(ctx.args or [])
    if not cmd_args:
        if json_output:
            console.print(
                json.dumps({"error": "No command provided to run. Usage: runtimeverify run [options] -- <command...>"})
            )
        else:
            console.print("[red]No command provided to run. Usage: runtimeverify run [options] -- <command...>[/red]")
        raise typer.Exit(code=1)

    cmd_str = " ".join(cmd_args)
    clean_cmd = sanitize_text(cmd_str)
    sess_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"

    resolved_policy_path = policy_path
    if not os.path.exists(resolved_policy_path) and os.path.exists(".runtimeverify/policy.yaml"):
        resolved_policy_path = ".runtimeverify/policy.yaml"

    try:
        policy_set = load_policy_from_yaml(resolved_policy_path)
    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": f"Failed to load policy file: {e}"}))
        else:
            console.print(f"[red]Failed to load policy file '{resolved_policy_path}': {e}[/red]")
        raise typer.Exit(code=1)

    interceptor = RuntimeActionInterceptor(
        mode=InterceptionMode(mode.lower()),
        policy_evaluator=PolicyEvaluator(policy_set=policy_set),
    )

    action = Action.shell(command=cmd_str, session_id=sess_id, agent_id=agent_id)

    # 1. Pre-execution verification
    try:
        decision, _ = interceptor.intercept(action, execute_fn=lambda act: None)
    except ExecutionBlockedError as e:
        clean_reason = sanitize_text(e.reason)
        if json_output:
            console.print(
                json.dumps(
                    {
                        "status": "BLOCK",
                        "execution_permitted": False,
                        "command": clean_cmd,
                        "policy_id": e.policy_id,
                        "severity": e.severity,
                        "reason": clean_reason,
                        "exit_code": 2,
                    },
                    indent=2,
                )
            )
        elif not quiet:
            console.print(
                Panel(
                    f"[red bold]EXECUTION BLOCKED by policy '{e.policy_id}':[/red bold]\n{clean_reason}",
                    title="RuntimeVerify Security Guard",
                    border_style="red",
                )
            )
        raise typer.Exit(code=2)
    except ExecutionReviewRequiredError as e:
        clean_reason = sanitize_text(e.reason)
        if json_output:
            console.print(
                json.dumps(
                    {
                        "status": "REVIEW",
                        "execution_permitted": False,
                        "command": clean_cmd,
                        "policy_id": e.policy_id,
                        "reason": clean_reason,
                        "exit_code": 3,
                    },
                    indent=2,
                )
            )
        elif not quiet:
            console.print(
                Panel(
                    f"[yellow bold]EXECUTION ON HOLD (HUMAN REVIEW REQUIRED):[/yellow bold]\n{clean_reason}",
                    title="RuntimeVerify Security Guard",
                    border_style="yellow",
                )
            )
        raise typer.Exit(code=3)

    # 2. Permitted command: execute safely
    if not quiet and not json_output:
        console.print(f"[dim]RuntimeVerify: executing '{clean_cmd}' under {mode.upper()} mode...[/dim]\n")

    t_start = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(cmd_args, shell=False)
        returncode = proc.returncode
    except FileNotFoundError:
        from runtimeverify.security.commands import CommandPipelineParser

        is_dangerous, warnings = CommandPipelineParser.check_dangerous_constructs(cmd_str)
        if is_dangerous:
            msg = f"Refusing shell fallback execution: dangerous shell construct detected ({'; '.join(warnings)})"
            if json_output:
                console.print(json.dumps({"error": msg, "exit_code": 1}))
            else:
                console.print(f"[red]{msg}[/red]")
            raise typer.Exit(code=1)
        proc = subprocess.run(cmd_str, shell=True)
        returncode = proc.returncode
    except Exception as exc:
        if json_output:
            console.print(json.dumps({"error": f"Failed to execute command: {exc}", "exit_code": 1}))
        else:
            console.print(f"[red]Failed to execute command: {exc}[/red]")
        raise typer.Exit(code=1)

    duration_ms = (datetime.now(timezone.utc) - t_start).total_seconds() * 1000

    if json_output:
        console.print(
            json.dumps(
                {
                    "status": "ALLOW",
                    "execution_permitted": True,
                    "command": clean_cmd,
                    "returncode": returncode,
                    "duration_ms": round(duration_ms, 2),
                    "session_id": sess_id,
                    "agent_id": agent_id,
                    "mode": mode,
                },
                indent=2,
            )
        )
    elif verbose and not quiet:
        console.print(f"\n[dim]RuntimeVerify: finished in {duration_ms:.2f}ms with exit code {returncode}.[/dim]")

    if returncode != 0:
        raise typer.Exit(code=returncode)


# ============================================================================
# 4. Monitoring: monitor
# ============================================================================


@app.command()
def monitor(
    agent_id: Optional[str] = typer.Option(None, "--agent", "-a", help="Filter by agent identifier"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s", help="Filter by session identifier"),
    policy_path: str = typer.Option("examples/policies/default.yaml", "--policy", "-p", help="Policy YAML path"),
    mode: str = typer.Option("enforce", "--mode", "-m", help="Interception mode: observe or enforce"),
    trace_file: Optional[str] = typer.Option(None, "--trace", "-t", help="Optional trace file to replay"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to audit NDJSON log file"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max audit records to display"),
    json_output: bool = typer.Option(False, "--json", help="Output events as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode"),
):
    """Monitors live agent actions or replays telemetry traces."""
    from runtimeverify.audit import FileAuditRepository
    from runtimeverify.interception import (
        Action,
        ExecutionBlockedError,
        ExecutionReviewRequiredError,
        InterceptionMode,
        RuntimeActionInterceptor,
    )
    from runtimeverify.policy import PolicyEvaluator, load_policy_from_yaml

    resolved_policy_path = policy_path
    if not os.path.exists(resolved_policy_path) and os.path.exists(".runtimeverify/policy.yaml"):
        resolved_policy_path = ".runtimeverify/policy.yaml"

    try:
        policy_set = load_policy_from_yaml(resolved_policy_path)
    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": f"Failed to load policy file: {e}"}))
        else:
            console.print(f"[red]Failed to load policy file '{resolved_policy_path}': {e}[/red]")
        raise typer.Exit(code=1)

    interceptor = RuntimeActionInterceptor(
        mode=InterceptionMode(mode.lower()),
        policy_evaluator=PolicyEvaluator(policy_set=policy_set),
    )

    # Case A: Replay trace file
    if trace_file and os.path.exists(trace_file):
        try:
            with open(trace_file, "r") as f:
                records = json.load(f)
            if not isinstance(records, list):
                records = [records]

            allowed_count = 0
            blocked_count = 0
            reviewed_count = 0
            results = []

            for idx, rec in enumerate(records, 1):
                cmd = rec.get("command") or rec.get("target") or "echo ok"
                act = Action.shell(
                    command=cmd, session_id=session_id or "trace-session", agent_id=agent_id or "agent-01"
                )
                try:
                    dec, _ = interceptor.intercept(act, execute_fn=lambda a: None)
                    status_str = dec.status
                    if status_str == "ALLOW":
                        allowed_count += 1
                    else:
                        reviewed_count += 1
                except ExecutionBlockedError:
                    blocked_count += 1
                    status_str = "BLOCK"
                except ExecutionReviewRequiredError:
                    reviewed_count += 1
                    status_str = "REVIEW"

                results.append(
                    {
                        "index": idx,
                        "target": sanitize_text(act.target),
                        "status": status_str,
                    }
                )

            if json_output:
                console.print(
                    json.dumps(
                        {
                            "mode": mode,
                            "total": len(records),
                            "allowed": allowed_count,
                            "reviewed": reviewed_count,
                            "blocked": blocked_count,
                            "results": results,
                        },
                        indent=2,
                    )
                )
                return

            if quiet:
                console.print(f"{allowed_count} ALLOW, {reviewed_count} REVIEW, {blocked_count} BLOCK")
                return

            console.print(Panel(f"[bold cyan]Trace Replay Monitor ({mode.upper()} mode)[/bold cyan]"))
            for r in results:
                col = "green" if r["status"] == "ALLOW" else ("yellow" if r["status"] == "REVIEW" else "red")
                console.print(f"  [{r['index']}] [{col}]{r['status']}[/{col}] {r['target']}")
            console.print(
                f"\n[bold]Summary:[/bold] {allowed_count} Allowed, {reviewed_count} Reviewed, {blocked_count} Blocked."
            )
        except Exception as e:
            if json_output:
                console.print(json.dumps({"error": f"Trace replay error: {e}"}))
            else:
                console.print(f"[red]Trace replay error: {e}[/red]")
            raise typer.Exit(code=1)
        return

    # Case B: Query recent audit store events
    log_path = store_path or (".runtimeverify/audit.log" if os.path.exists(".runtimeverify/audit.log") else None)
    if log_path and os.path.exists(log_path):
        repo = FileAuditRepository(log_path=log_path)
        records = repo.query(agent_id=agent_id, session_id=session_id, limit=limit)

        if json_output:
            console.print(json.dumps([r.model_dump(mode="json") for r in records], indent=2))
            return

        if quiet:
            console.print(f"{len(records)} audit records found")
            return

        console.print(Panel(f"[bold cyan]RuntimeVerify Interception Monitor ({mode.upper()} mode)[/bold cyan]"))
        if agent_id:
            console.print(f"Filtering on Agent: [bold]{agent_id}[/bold]")
        table = Table(title=f"Recent Interceptions ({len(records)} shown)")
        table.add_column("Timestamp", style="dim")
        table.add_column("Agent", style="blue")
        table.add_column("Type", style="magenta")
        table.add_column("Severity")
        table.add_column("Summary")

        for record in records:
            table.add_row(
                record.timestamp.strftime("%H:%M:%S"),
                record.agent_id or "-",
                record.record_type.value,
                record.severity.value,
                sanitize_text(record.summary[:50]),
            )
        console.print(table)
    else:
        if json_output:
            console.print(json.dumps({"mode": mode, "status": "idle", "records": []}))
        elif not quiet:
            console.print(Panel(f"[bold cyan]RuntimeVerify Interception Monitor ({mode.upper()} mode)[/bold cyan]"))
            console.print(
                "No active telemetry log found. Use 'runtimeverify check' or 'runtimeverify run' to generate events."
            )


# ============================================================================
# 5. Policy Engine: validate & test
# ============================================================================

policy_app = typer.Typer(name="policy", help="Inspect, validate, and test deterministic security policies")
app.add_typer(policy_app, name="policy")


@policy_app.command(name="validate")
def policy_validate(
    policy_path: str = typer.Argument("examples/policies/default.yaml", help="Path to policy YAML file"),
    json_output: bool = typer.Option(False, "--json", help="Output validation result as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
):
    """Validates policy file structure, syntax, and regex patterns."""
    from runtimeverify.policy import load_policy_from_yaml

    resolved_path = policy_path
    if not os.path.exists(resolved_path) and os.path.exists(".runtimeverify/policy.yaml"):
        resolved_path = ".runtimeverify/policy.yaml"

    try:
        policy_set = load_policy_from_yaml(resolved_path)
    except Exception as e:
        if json_output:
            console.print(json.dumps({"valid": False, "error": str(e), "path": policy_path}))
        elif quiet:
            console.print("INVALID")
        else:
            console.print(f"[red]Policy validation error:[/red] {e}")
        raise typer.Exit(code=1)

    if json_output:
        console.print(
            json.dumps(
                {
                    "valid": True,
                    "path": resolved_path,
                    "name": policy_set.name,
                    "version": policy_set.version,
                    "rules_count": len(policy_set.policies),
                    "conflict_resolution": policy_set.conflict_resolution.value,
                    "default_decision": policy_set.default_decision.value,
                    "policies": [
                        {
                            "id": p.id,
                            "decision": p.decision.value,
                            "severity": p.severity.value,
                            "priority": p.priority,
                            "description": p.description,
                        }
                        for p in policy_set.policies
                    ],
                },
                indent=2,
            )
        )
        return

    if quiet:
        console.print("VALID")
        return

    console.print(Panel(f"[bold green]Policy Set: {policy_set.name} (v{policy_set.version})[/bold green]"))
    console.print(f"  * [bold]Conflict Resolution:[/bold] {policy_set.conflict_resolution.value}")
    console.print(f"  * [bold]Default Decision:[/bold] {policy_set.default_decision.value}")
    console.print(f"  * [bold]Total Rules:[/bold] {len(policy_set.policies)}")

    table = Table(title="Configured Policy Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Decision", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Priority", style="green")
    table.add_column("Description")

    for p in policy_set.policies:
        dec_color = "red" if p.decision.value == "BLOCK" else ("yellow" if p.decision.value == "REVIEW" else "green")
        table.add_row(
            p.id,
            f"[{dec_color}]{p.decision.value}[/{dec_color}]",
            p.severity.value,
            str(p.priority),
            p.description or "",
        )
    console.print(table)
    console.print("\n[bold green]Policy file is valid and ready for runtime enforcement.[/bold green]")


@policy_app.command(name="test")
def policy_test(
    policy_path: str = typer.Argument("examples/policies/default.yaml", help="Path to policy YAML file"),
    test_file: Optional[str] = typer.Option(None, "--test-file", "-t", help="Path to test scenarios YAML/JSON"),
    json_output: bool = typer.Option(False, "--json", help="Output test report as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode"),
):
    """Evaluates security policy rules against a test suite of intended actions."""
    from runtimeverify.interception.models import Action
    from runtimeverify.policy import PolicyEvaluator, load_policy_from_yaml

    resolved_path = policy_path
    if not os.path.exists(resolved_path) and os.path.exists(".runtimeverify/policy.yaml"):
        resolved_path = ".runtimeverify/policy.yaml"

    try:
        policy_set = load_policy_from_yaml(resolved_path)
    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": f"Failed to load policy: {e}", "passed": False}))
        elif not quiet:
            console.print(f"[red]Failed to load policy file '{policy_path}': {e}[/red]")
        raise typer.Exit(code=1)

    evaluator = PolicyEvaluator(policy_set=policy_set)

    scenarios: List[Dict[str, Any]] = []
    if test_file and os.path.exists(test_file):
        with open(test_file, "r") as f:
            if test_file.endswith(".yaml") or test_file.endswith(".yml"):
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
            scenarios = data.get("tests", data) if isinstance(data, dict) else data
    else:
        # Standard built-in regression test suite
        scenarios = [
            {"name": "Safe Git Status", "type": "shell", "target": "git status", "expected": "ALLOW"},
            {"name": "Safe Pytest Execution", "type": "shell", "target": "pytest", "expected": "ALLOW"},
            {"name": "Block Destructive rm -rf", "type": "shell", "target": "rm -rf /", "expected": "BLOCK"},
            {
                "name": "Deny SSH Private Key Access",
                "type": "filesystem",
                "target": "~/.ssh/id_rsa",
                "expected": "BLOCK",
            },
            {
                "name": "Deny AWS Credentials Access",
                "type": "filesystem",
                "target": "~/.aws/credentials",
                "expected": "BLOCK",
            },
            {"name": "Deny Environment Files", "type": "filesystem", "target": ".env", "expected": "BLOCK"},
            {
                "name": "Block Cloud Metadata Service",
                "type": "network",
                "target": "http://169.254.169.254/latest/meta-data",
                "expected": "BLOCK",
            },
        ]

    passed_count = 0
    failed_count = 0
    results: List[Dict[str, Any]] = []

    for sc in scenarios:
        name = sc.get("name", "Test")
        act_type = sc.get("type", "shell").lower()
        target = sc.get("target", "")
        expected = sc.get("expected", "ALLOW").upper()

        if act_type == "shell":
            action = Action.shell(command=target, session_id="test-sess", agent_id="test-agent")
        elif act_type == "filesystem":
            action = Action.filesystem(
                operation=sc.get("operation", "read"), path=target, session_id="test-sess", agent_id="test-agent"
            )
        elif act_type == "network":
            action = Action.network(url=target, session_id="test-sess", agent_id="test-agent")
        else:
            action = Action.shell(command=target, session_id="test-sess", agent_id="test-agent")

        ev = action.to_canonical_event()
        dec = evaluator.evaluate(ev)
        actual = dec.decision.value.upper()

        success = actual == expected
        if success:
            passed_count += 1
        else:
            failed_count += 1

        results.append(
            {
                "name": name,
                "type": act_type,
                "target": sanitize_text(target),
                "expected": expected,
                "actual": actual,
                "passed": success,
                "policy_id": dec.policy_id,
                "reason": sanitize_text(dec.reason),
            }
        )

    if json_output:
        console.print(
            json.dumps(
                {
                    "policy": resolved_path,
                    "total": len(scenarios),
                    "passed": passed_count,
                    "failed": failed_count,
                    "all_passed": (failed_count == 0),
                    "results": results,
                },
                indent=2,
            )
        )
        raise typer.Exit(code=0 if failed_count == 0 else 1)

    if quiet:
        console.print(f"{passed_count}/{len(scenarios)} passed")
        raise typer.Exit(code=0 if failed_count == 0 else 1)

    table = Table(title=f"Policy Test Results for '{policy_set.name}' ({passed_count}/{len(scenarios)} passed)")
    table.add_column("Scenario", style="cyan")
    table.add_column("Type", style="dim")
    table.add_column("Target")
    table.add_column("Expected", style="magenta")
    table.add_column("Actual")
    table.add_column("Result")

    for r in results:
        res_str = "[green bold]PASS[/green bold]" if r["passed"] else "[red bold]FAIL[/red bold]"
        actual_str = f"[green]{r['actual']}[/green]" if r["passed"] else f"[red]{r['actual']}[/red]"
        table.add_row(
            r["name"],
            r["type"],
            r["target"],
            r["expected"],
            actual_str,
            res_str,
        )

    console.print(table)
    if failed_count > 0:
        console.print(
            f"\n[red bold]FAILED:[/red bold] {failed_count} test scenario(s) violated expected security decisions."
        )
        raise typer.Exit(code=1)
    else:
        console.print(f"\n[green bold]SUCCESS:[/green bold] All {passed_count} policy test scenarios passed.")


# ============================================================================
# 6. Canonical Events: events
# ============================================================================

events_app = typer.Typer(name="events", help="Query and inspect canonical runtime telemetry events")
app.add_typer(events_app, name="events")


def _run_events_list(
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 50,
    store_path: Optional[str] = None,
    json_output: bool = False,
    quiet: bool = False,
    verbose: bool = False,
):
    from runtimeverify.audit import AuditRecordType, FileAuditRepository

    path = store_path or (".runtimeverify/audit.log" if os.path.exists(".runtimeverify/audit.log") else None)
    if not path or not os.path.exists(path):
        if json_output:
            console.print("[]")
        elif not quiet:
            console.print("[dim]No events found (audit log does not exist).[/dim]")
        return

    repo = FileAuditRepository(log_path=path)
    records = repo.query(
        agent_id=agent_id,
        session_id=session_id,
        record_type=AuditRecordType.EVENT,
        limit=limit,
    )

    if event_type:
        records = [
            r
            for r in records
            if r.details.get("event_type", "").upper() == event_type.upper() or event_type.upper() in r.summary.upper()
        ]

    if json_output:
        console.print(json.dumps([r.model_dump(mode="json") for r in records], indent=2))
        return

    if quiet:
        console.print(f"{len(records)} events")
        return

    table = Table(title=f"Canonical Telemetry Events ({len(records)} shown)")
    table.add_column("Timestamp", style="dim")
    table.add_column("Event ID", style="cyan")
    table.add_column("Agent", style="blue")
    table.add_column("Session", style="dim")
    table.add_column("Summary")

    for r in records:
        table.add_row(
            r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            r.record_id[:8] + "...",
            r.agent_id or "-",
            r.session_id or "-",
            sanitize_text(r.summary[:50]),
        )
    console.print(table)


@events_app.callback(invoke_without_command=True)
def events_default(
    ctx: typer.Context,
    agent_id: Optional[str] = typer.Option(None, "--agent", "-a", help="Filter by agent identifier"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s", help="Filter by session identifier"),
    event_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by event type"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max events to display"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to audit NDJSON log file"),
    json_output: bool = typer.Option(False, "--json", help="Output events as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode"),
):
    """Lists canonical telemetry events from the audit log."""
    if ctx.invoked_subcommand is None:
        _run_events_list(agent_id, session_id, event_type, limit, store_path, json_output, quiet, verbose)


@events_app.command(name="list")
def events_list_cmd(
    agent_id: Optional[str] = typer.Option(None, "--agent", "-a", help="Filter by agent identifier"),
    session_id: Optional[str] = typer.Option(None, "--session", "-s", help="Filter by session identifier"),
    event_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by event type"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max events to display"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to audit NDJSON log file"),
    json_output: bool = typer.Option(False, "--json", help="Output events as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose mode"),
):
    """Lists canonical telemetry events from the audit log."""
    _run_events_list(agent_id, session_id, event_type, limit, store_path, json_output, quiet, verbose)


@events_app.command(name="show")
def events_show(
    event_id: str = typer.Argument(..., help="Event ID or prefix"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to audit NDJSON log file"),
    json_output: bool = typer.Option(False, "--json", help="Output event as JSON"),
):
    """Shows full details of a single canonical telemetry event."""
    from runtimeverify.audit import FileAuditRepository

    path = store_path or (".runtimeverify/audit.log" if os.path.exists(".runtimeverify/audit.log") else None)
    if not path or not os.path.exists(path):
        if json_output:
            console.print(json.dumps({"error": "Audit store not found."}))
        else:
            console.print(f"[red]Audit store '{path}' not found.[/red]")
        raise typer.Exit(code=1)

    repo = FileAuditRepository(log_path=path)
    rec = repo.get(event_id)
    if not rec and len(event_id) < 36:
        matches = [
            r
            for r in repo.query(limit=5000)
            if r.record_id.startswith(event_id) or (r.event_id and r.event_id.startswith(event_id))
        ]
        if len(matches) == 1:
            rec = matches[0]

    if not rec:
        if json_output:
            console.print(json.dumps({"error": f"Event '{event_id}' not found."}))
        else:
            console.print(f"[red]Event '{event_id}' not found.[/red]")
        raise typer.Exit(code=1)

    if json_output:
        console.print(json.dumps(rec.model_dump(mode="json"), indent=2))
        return

    console.print(Panel(f"[bold cyan]Canonical Event: {rec.record_id}[/bold cyan]"))
    console.print(f"  * [bold]Timestamp:[/bold] {rec.timestamp.isoformat()}")
    console.print(f"  * [bold]Agent:[/bold] {rec.agent_id or '-'}")
    console.print(f"  * [bold]Session:[/bold] {rec.session_id or '-'}")
    console.print(f"  * [bold]Summary:[/bold] {sanitize_text(rec.summary)}")
    if rec.details:
        console.print("\n[bold]Details:[/bold]")
        console.print(json.dumps(sanitize_dict(rec.details), indent=2))


# ============================================================================
# 7. Performance Benchmarking: benchmark
# ============================================================================


@app.command()
def benchmark(
    iterations: int = typer.Option(1000, "--iterations", "-n", help="Number of benchmark iterations"),
    policy_path: str = typer.Option("examples/policies/default.yaml", "--policy", "-p", help="Policy YAML path"),
    security: bool = typer.Option(
        False,
        "--security",
        "-s",
        help="Run comprehensive security verification benchmark across all 4 strategies and 9 scenarios",
    ),
    dataset: str = typer.Option("synthetic", "--dataset", "-d", help="Benchmark dataset: synthetic or real-world"),
    output_json: Optional[str] = typer.Option(None, "--output-json", help="Path to write benchmark results as JSON"),
    output_csv: Optional[str] = typer.Option(None, "--output-csv", help="Path to write benchmark results as CSV"),
    report: Optional[str] = typer.Option(None, "--report", "-r", help="Path to write markdown benchmark report"),
    json_output: bool = typer.Option(False, "--json", help="Output benchmark metrics as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
):
    """Runs performance benchmark suite or comprehensive security strategy comparison."""
    if security:
        from runtimeverify.evaluation.datasets import (
            build_realworld_dataset,
            build_synthetic_dataset,
        )
        from runtimeverify.evaluation.reports import ReportGenerator
        from runtimeverify.evaluation.runner import SecurityBenchmarkRunner

        ds = (
            build_realworld_dataset()
            if dataset.lower() in ("real-world", "realworld", "real")
            else build_synthetic_dataset(seed=42)
        )
        runner = SecurityBenchmarkRunner(dataset=ds)
        res = runner.run()

        if output_json:
            with open(output_json, "w", encoding="utf-8") as f:
                f.write(res.to_json())
        if output_csv:
            with open(output_csv, "w", encoding="utf-8") as f:
                f.write(res.to_csv())
        if report:
            with open(report, "w", encoding="utf-8") as f:
                f.write(ReportGenerator.generate_security_benchmark_markdown(res))

        if json_output:
            console.print(res.to_json())
            return

        if quiet:
            console.print(f"Benchmark completed: {len(res.strategies)} strategies")
            return

        table = Table(title=f"RuntimeVerify Security Benchmark ({'Synthetic' if res.is_synthetic else 'Real-World'})")
        table.add_column("Strategy", style="cyan")
        table.add_column("Accuracy", style="green")
        table.add_column("Precision", style="white")
        table.add_column("Recall", style="white")
        table.add_column("F1", style="bold magenta")
        table.add_column("False Allow", style="red")
        table.add_column("False Block", style="yellow")
        table.add_column("Latency (ms)", style="dim")

        for k, m in res.strategies.items():
            table.add_row(
                m.strategy_name,
                f"{m.accuracy * 100:.1f}%",
                f"{m.precision:.3f}",
                f"{m.recall:.3f}",
                f"{m.f1_score:.3f}",
                f"{m.false_allow_rate * 100:.1f}%",
                f"{m.false_block_rate * 100:.1f}%",
                f"{m.mean_latency_ms:.3f} ms",
            )
        console.print(table)
        return

    from runtimeverify.events.canonical import CanonicalEvent
    from runtimeverify.events.enums import EventAction, EventType
    from runtimeverify.policy import PolicyEvaluator, load_policy_from_yaml

    resolved_policy_path = policy_path
    if not os.path.exists(resolved_policy_path) and os.path.exists(".runtimeverify/policy.yaml"):
        resolved_policy_path = ".runtimeverify/policy.yaml"

    try:
        policy_set = load_policy_from_yaml(resolved_policy_path)
    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": f"Failed to load policy: {e}"}))
        else:
            console.print(f"[red]Failed to load policy: {e}[/red]")
        raise typer.Exit(code=1)

    evaluator = PolicyEvaluator(policy_set=policy_set)
    test_event = CanonicalEvent(
        session_id="bench-sess",
        agent_id="bench-agent",
        event_type=EventType.SHELL_COMMAND,
        action=EventAction.EXECUTE,
        target="git status",
        payload={"command": "git status"},
    )

    # 1. Policy Benchmark
    t0 = time.perf_counter()
    for _ in range(iterations):
        evaluator.evaluate(test_event)
    pol_duration = time.perf_counter() - t0
    pol_ops_sec = iterations / pol_duration if pol_duration > 0 else 0
    pol_mean_us = (pol_duration / iterations) * 1_000_000

    # 2. Redaction Benchmark
    sample_text = "curl -H 'Authorization: Bearer sk-proj-123456789012345678901234567890' https://api.openai.com/v1"
    t1 = time.perf_counter()
    for _ in range(iterations):
        redactor.redact_string(sample_text)
    red_duration = time.perf_counter() - t1
    red_ops_sec = iterations / red_duration if red_duration > 0 else 0
    red_mean_us = (red_duration / iterations) * 1_000_000

    if json_output:
        console.print(
            json.dumps(
                {
                    "iterations": iterations,
                    "policy_benchmark": {
                        "total_duration_sec": round(pol_duration, 4),
                        "throughput_ops_per_sec": round(pol_ops_sec, 1),
                        "mean_latency_us": round(pol_mean_us, 2),
                    },
                    "redaction_benchmark": {
                        "total_duration_sec": round(red_duration, 4),
                        "throughput_ops_per_sec": round(red_ops_sec, 1),
                        "mean_latency_us": round(red_mean_us, 2),
                    },
                },
                indent=2,
            )
        )
        return

    if quiet:
        console.print(f"{round(pol_ops_sec, 1)} ops/sec")
        return

    table = Table(title=f"RuntimeVerify Performance Benchmark ({iterations} iterations)")
    table.add_column("Benchmark Component", style="cyan")
    table.add_column("Total Duration", style="dim")
    table.add_column("Throughput (ops/sec)", style="green")
    table.add_column("Mean Latency (us)", style="magenta")

    table.add_row(
        "Deterministic Policy Evaluation",
        f"{pol_duration:.4f}s",
        f"{pol_ops_sec:,.1f}",
        f"{pol_mean_us:.2f} us",
    )
    table.add_row(
        "Secret Redaction Scanner",
        f"{red_duration:.4f}s",
        f"{red_ops_sec:,.1f}",
        f"{red_mean_us:.2f} us",
    )
    console.print(table)


# ============================================================================
# 8. Human Approvals: approvals
# ============================================================================

approvals_app = typer.Typer(name="approvals", help="Manage and inspect human approval workflows")
app.add_typer(approvals_app, name="approvals")


@approvals_app.command(name="list")
def approvals_list(
    status: Optional[str] = typer.Option(
        None, "--status", "-s", help="Filter by status: PENDING, APPROVED, DENIED, EXPIRED, ALL"
    ),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to approval store JSON file"),
    json_output: bool = typer.Option(False, "--json", help="Output approval requests as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
):
    """Lists human approval requests."""
    from runtimeverify.approvals import ApprovalStatus, get_default_approval_store

    store = get_default_approval_store(persistence_path=store_path)
    status_filter = None
    if status and status.upper() != "ALL":
        try:
            status_filter = ApprovalStatus(status.upper())
        except ValueError:
            valid_statuses = "PENDING, APPROVED, DENIED, EXPIRED, ALL"
            if json_output:
                console.print(json.dumps({"error": f"Invalid status '{status}'. Valid: {valid_statuses}"}))
            else:
                console.print(f"[red]Invalid status filter '{status}'. Valid: {valid_statuses}[/red]")
            raise typer.Exit(code=1)

    requests = store.list_requests(status=status_filter)

    if json_output:
        console.print(json.dumps([r.model_dump(mode="json") for r in requests], indent=2))
        return

    if quiet:
        console.print(str(len(requests)))
        return

    if not requests:
        console.print("[dim]No approval requests found.[/dim]")
        return

    table = Table(title=f"Human Approval Requests ({len(requests)} total)")
    table.add_column("Request ID", style="cyan", no_wrap=True)
    table.add_column("Agent", style="blue", no_wrap=True)
    table.add_column("Action", style="magenta")
    table.add_column("Risk", style="yellow")
    table.add_column("Status", no_wrap=True)
    table.add_column("Expires In", style="dim", no_wrap=True)
    table.add_column("Reason")

    now = datetime.now(timezone.utc)
    for r in requests:
        if r.status == ApprovalStatus.PENDING:
            st_str = "[yellow bold]PENDING[/yellow bold]"
        elif r.status == ApprovalStatus.APPROVED:
            st_str = "[green bold]APPROVED[/green bold]"
        elif r.status == ApprovalStatus.DENIED:
            st_str = "[red bold]DENIED[/red bold]"
        elif r.status == ApprovalStatus.EXPIRED:
            st_str = "[dim]EXPIRED[/dim]"
        else:
            st_str = str(r.status.value)

        if r.status == ApprovalStatus.PENDING and not r.is_expired(now):
            exp_tz = r.expiration if r.expiration.tzinfo else r.expiration.replace(tzinfo=timezone.utc)
            delta = exp_tz - now
            rem_str = f"{max(0, int(delta.total_seconds()))}s"
        else:
            rem_str = "expired"

        action_label = r.action.get("target") or r.action.get("action_type") or "unknown"
        table.add_row(
            r.request_id[:8] + "...",
            r.agent_id or "unknown",
            sanitize_text(str(action_label)[:30]),
            r.risk,
            st_str,
            rem_str,
            sanitize_text(r.reason[:40] + ("..." if len(r.reason) > 40 else "")),
        )

    console.print(table)


@approvals_app.command(name="approve")
def approvals_approve(
    request_id: str = typer.Argument(..., help="Approval request ID or prefix"),
    user: str = typer.Option("cli-operator", "--user", "-u", help="Approver user identity"),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Reason for approval"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to approval store JSON file"),
    json_output: bool = typer.Option(False, "--json", help="Output decision as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
):
    """Approves a pending human approval request."""
    from runtimeverify.approvals import (
        ApprovalDecision,
        ApprovalDecisionType,
        ApprovalExpiredError,
        DuplicateApprovalError,
        UnauthorizedApproverError,
        UnknownApprovalRequestError,
        get_default_approval_store,
    )

    store = get_default_approval_store(persistence_path=store_path)

    matched_id = request_id
    if len(request_id) < 36:
        all_reqs = store.list_requests()
        matches = [r.request_id for r in all_reqs if r.request_id.startswith(request_id)]
        if len(matches) == 1:
            matched_id = matches[0]
        elif len(matches) > 1:
            if json_output:
                console.print(
                    json.dumps(
                        {"error": f"Ambiguous request ID prefix '{request_id}' matches {len(matches)} requests."}
                    )
                )
            else:
                console.print(f"[red]Ambiguous request ID prefix '{request_id}' matches {len(matches)} requests.[/red]")
            raise typer.Exit(code=1)

    decision = ApprovalDecision(
        request_id=matched_id,
        decision=ApprovalDecisionType.APPROVE,
        decided_by=user,
        reason=reason or f"Approved by {user} via CLI",
    )

    try:
        updated = store.record_decision(matched_id, decision)
        if json_output:
            console.print(
                json.dumps(
                    {
                        "verdict": "APPROVE",
                        "request_id": updated.request_id,
                        "agent_id": updated.agent_id,
                        "decided_by": user,
                        "status": updated.status.value,
                    },
                    indent=2,
                )
            )
        elif quiet:
            console.print("APPROVED")
        else:
            console.print(
                Panel(
                    f"[bold green]Approval GRANTED[/bold green]\n"
                    f"  * [bold]Request ID:[/bold] {updated.request_id}\n"
                    f"  * [bold]Agent:[/bold] {updated.agent_id}\n"
                    f"  * [bold]Decided By:[/bold] {user}\n"
                    f"  * [bold]Reason:[/bold] {decision.reason}\n"
                    f"  * [bold]Status:[/bold] {updated.status.value}",
                    title="Human Authorization",
                    border_style="green",
                )
            )
    except UnknownApprovalRequestError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)
    except DuplicateApprovalError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red bold]Duplicate Approval Error:[/red bold] {e}")
        raise typer.Exit(code=2)
    except ApprovalExpiredError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red bold]Approval Expired Error:[/red bold] {e}")
        raise typer.Exit(code=3)
    except UnauthorizedApproverError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red bold]Unauthorized Approver Error:[/red bold] {e}")
        raise typer.Exit(code=4)


@approvals_app.command(name="deny")
def approvals_deny(
    request_id: str = typer.Argument(..., help="Approval request ID or prefix"),
    user: str = typer.Option("cli-operator", "--user", "-u", help="Approver user identity"),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Reason for denial"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to approval store JSON file"),
    json_output: bool = typer.Option(False, "--json", help="Output decision as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
):
    """Denies a pending human approval request."""
    from runtimeverify.approvals import (
        ApprovalDecision,
        ApprovalDecisionType,
        ApprovalExpiredError,
        DuplicateApprovalError,
        UnauthorizedApproverError,
        UnknownApprovalRequestError,
        get_default_approval_store,
    )

    store = get_default_approval_store(persistence_path=store_path)

    matched_id = request_id
    if len(request_id) < 36:
        all_reqs = store.list_requests()
        matches = [r.request_id for r in all_reqs if r.request_id.startswith(request_id)]
        if len(matches) == 1:
            matched_id = matches[0]
        elif len(matches) > 1:
            if json_output:
                console.print(
                    json.dumps(
                        {"error": f"Ambiguous request ID prefix '{request_id}' matches {len(matches)} requests."}
                    )
                )
            else:
                console.print(f"[red]Ambiguous request ID prefix '{request_id}' matches {len(matches)} requests.[/red]")
            raise typer.Exit(code=1)

    decision = ApprovalDecision(
        request_id=matched_id,
        decision=ApprovalDecisionType.DENY,
        decided_by=user,
        reason=reason or f"Denied by {user} via CLI",
    )

    try:
        updated = store.record_decision(matched_id, decision)
        if json_output:
            console.print(
                json.dumps(
                    {
                        "verdict": "DENY",
                        "request_id": updated.request_id,
                        "agent_id": updated.agent_id,
                        "decided_by": user,
                        "status": updated.status.value,
                    },
                    indent=2,
                )
            )
        elif quiet:
            console.print("DENIED")
        else:
            console.print(
                Panel(
                    f"[bold red]Approval DENIED[/bold red]\n"
                    f"  * [bold]Request ID:[/bold] {updated.request_id}\n"
                    f"  * [bold]Agent:[/bold] {updated.agent_id}\n"
                    f"  * [bold]Decided By:[/bold] {user}\n"
                    f"  * [bold]Reason:[/bold] {decision.reason}\n"
                    f"  * [bold]Status:[/bold] {updated.status.value}",
                    title="Human Authorization",
                    border_style="red",
                )
            )
    except UnknownApprovalRequestError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)
    except DuplicateApprovalError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red bold]Duplicate Approval Error:[/red bold] {e}")
        raise typer.Exit(code=2)
    except ApprovalExpiredError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red bold]Approval Expired Error:[/red bold] {e}")
        raise typer.Exit(code=3)
    except UnauthorizedApproverError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red bold]Unauthorized Approver Error:[/red bold] {e}")
        raise typer.Exit(code=4)


@approvals_app.command(name="show")
def approvals_show(
    request_id: str = typer.Argument(..., help="Approval request ID or prefix"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to approval store JSON file"),
    json_output: bool = typer.Option(False, "--json", help="Output request as JSON"),
):
    """Shows full details and evidentiary records for an approval request."""
    from runtimeverify.approvals import (
        UnknownApprovalRequestError,
        get_default_approval_store,
    )

    store = get_default_approval_store(persistence_path=store_path)

    matched_id = request_id
    if len(request_id) < 36:
        all_reqs = store.list_requests()
        matches = [r.request_id for r in all_reqs if r.request_id.startswith(request_id)]
        if len(matches) == 1:
            matched_id = matches[0]

    try:
        req = store.get_request(matched_id)
    except UnknownApprovalRequestError as e:
        if json_output:
            console.print(json.dumps({"error": str(e)}))
        else:
            console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)

    if json_output:
        console.print(json.dumps(req.model_dump(mode="json"), indent=2))
        return

    console.print(Panel(f"[bold cyan]Approval Request: {req.request_id}[/bold cyan]"))
    console.print(f"  * [bold]Status:[/bold] {req.status.value}")
    console.print(f"  * [bold]Risk Level:[/bold] {req.risk}")
    console.print(f"  * [bold]Agent:[/bold] {req.agent_id or 'unknown'} (Session: {req.session_id or 'n/a'})")
    console.print(f"  * [bold]Reason:[/bold] {sanitize_text(req.reason)}")
    console.print(f"  * [bold]Created At:[/bold] {req.created_at.isoformat()}")
    console.print(f"  * [bold]Expiration:[/bold] {req.expiration.isoformat()}")
    console.print(f"  * [bold]Action:[/bold] {sanitize_dict(req.action)}")

    if req.decision:
        console.print("\n[bold]Decision Record:[/bold]")
        console.print(f"  * [bold]Verdict:[/bold] {req.decision.decision.value}")
        console.print(f"  * [bold]Decided By:[/bold] {req.decision.decided_by}")
        console.print(f"  * [bold]Reason:[/bold] {sanitize_text(req.decision.reason)}")
        console.print(f"  * [bold]Timestamp:[/bold] {req.decision.timestamp.isoformat()}")

    if req.evidence:
        console.print(f"\n[bold]Attached Evidence ({len(req.evidence)} items):[/bold]")
        for i, ev in enumerate(req.evidence, start=1):
            console.print(
                f"  {i}. [{ev.get('severity', 'INFO')}] {ev.get('title', 'Evidence')}: {sanitize_text(ev.get('description', ''))}"
            )


# ============================================================================
# 9. Audit Trail: audit
# ============================================================================

audit_app = typer.Typer(name="audit", help="Query, inspect, and manage structured audit records")
app.add_typer(audit_app, name="audit")


@audit_app.command(name="list")
def audit_list(
    session_id: Optional[str] = typer.Option(None, "--session", help="Filter by session ID"),
    agent_id: Optional[str] = typer.Option(None, "--agent", help="Filter by agent ID"),
    trace_id: Optional[str] = typer.Option(None, "--trace", help="Filter by trace ID"),
    record_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by record type"),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="Filter by severity (INFO, WARNING, HIGH, CRITICAL)"
    ),
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum number of records to display"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to audit NDJSON log file"),
    json_output: bool = typer.Option(False, "--json", help="Output audit records as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
):
    """Lists structured audit records matching correlation filters."""
    from runtimeverify.audit import AuditRecordType, AuditSeverity, FileAuditRepository

    path = store_path or ".runtimeverify/audit.log"
    repo = FileAuditRepository(log_path=path)

    type_filter = None
    if record_type:
        try:
            type_filter = AuditRecordType(record_type.upper())
        except ValueError:
            valid_types = ", ".join(t.value for t in AuditRecordType)
            if json_output:
                console.print(json.dumps({"error": f"Invalid record type '{record_type}'. Valid types: {valid_types}"}))
            else:
                console.print(f"[red]Invalid record type '{record_type}'. Valid types: {valid_types}[/red]")
            raise typer.Exit(code=1)

    sev_filter = None
    if severity:
        try:
            sev_filter = AuditSeverity(severity.upper())
        except ValueError:
            valid_sevs = ", ".join(s.value for s in AuditSeverity)
            if json_output:
                console.print(json.dumps({"error": f"Invalid severity '{severity}'. Valid severities: {valid_sevs}"}))
            else:
                console.print(f"[red]Invalid severity '{severity}'. Valid severities: {valid_sevs}[/red]")
            raise typer.Exit(code=1)

    records = repo.query(
        trace_id=trace_id,
        session_id=session_id,
        agent_id=agent_id,
        record_type=type_filter,
        severity=sev_filter,
        limit=limit,
    )

    if json_output:
        console.print(json.dumps([r.model_dump(mode="json") for r in records], indent=2))
        return

    if quiet:
        console.print(str(len(records)))
        return

    if not records:
        console.print("[dim]No audit records found.[/dim]")
        return

    table = Table(title=f"Audit Records ({len(records)} shown, store: {path})")
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Record ID", style="cyan", no_wrap=True)
    table.add_column("Type", style="magenta", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Agent", style="blue", no_wrap=True)
    table.add_column("Trace ID", style="dim", no_wrap=True)
    table.add_column("Summary")
    table.add_column("Redacted", no_wrap=True)

    for r in records:
        sev_color = {
            AuditSeverity.INFO: "green",
            AuditSeverity.WARNING: "yellow",
            AuditSeverity.HIGH: "red",
            AuditSeverity.CRITICAL: "bold red",
        }.get(r.severity, "white")
        sev_str = f"[{sev_color}]{r.severity.value}[/{sev_color}]"

        ts_str = r.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        redacted_str = "[yellow]YES[/yellow]" if r.redacted else "[dim]NO[/dim]"
        trace_short = (r.trace_id[:8] + "...") if r.trace_id else "-"

        table.add_row(
            ts_str,
            r.record_id[:8] + "...",
            r.record_type.value,
            sev_str,
            r.agent_id or "-",
            trace_short,
            sanitize_text(r.summary[:45] + ("..." if len(r.summary) > 45 else "")),
            redacted_str,
        )

    console.print(table)


@audit_app.command(name="show")
def audit_show(
    record_id: str = typer.Argument(..., help="Audit record ID or prefix"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to audit NDJSON log file"),
    json_output: bool = typer.Option(False, "--json", help="Output audit record as JSON"),
):
    """Shows full details and correlation metadata for an audit record."""
    from runtimeverify.audit import FileAuditRepository

    path = store_path or ".runtimeverify/audit.log"
    repo = FileAuditRepository(log_path=path)

    rec = repo.get(record_id)
    if not rec and len(record_id) < 36:
        all_recs = repo.query(limit=5000)
        matches = [r for r in all_recs if r.record_id.startswith(record_id)]
        if len(matches) == 1:
            rec = matches[0]
        elif len(matches) > 1:
            if json_output:
                console.print(
                    json.dumps({"error": f"Ambiguous record ID prefix '{record_id}' matches {len(matches)} records."})
                )
            else:
                console.print(f"[red]Ambiguous record ID prefix '{record_id}' matches {len(matches)} records.[/red]")
            raise typer.Exit(code=1)

    if not rec:
        if json_output:
            console.print(json.dumps({"error": f"Audit record '{record_id}' not found."}))
        else:
            console.print(f"[red]Audit record '{record_id}' not found in store '{path}'.[/red]")
        raise typer.Exit(code=1)

    if json_output:
        console.print(json.dumps(rec.model_dump(mode="json"), indent=2))
        return

    sev_color = {
        "INFO": "green",
        "WARNING": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }.get(rec.severity.value, "white")

    console.print(Panel(f"[bold cyan]Audit Record: {rec.record_id}[/bold cyan]", border_style="cyan"))
    console.print(f"  * [bold]Timestamp:[/bold] {rec.timestamp.isoformat()}")
    console.print(f"  * [bold]Type:[/bold] {rec.record_type.value}")
    console.print(f"  * [bold]Severity:[/bold] [{sev_color}]{rec.severity.value}[/{sev_color}]")
    console.print(f"  * [bold]Redacted:[/bold] {'[yellow]YES (secrets scrubbed)[/yellow]' if rec.redacted else 'NO'}")
    if rec.environment:
        console.print(f"  * [bold]Environment:[/bold] {rec.environment}")
    console.print(f"  * [bold]Summary:[/bold] {sanitize_text(rec.summary)}")

    console.print("\n[bold]Correlation Context:[/bold]")
    console.print(f"  * [bold]Trace ID:[/bold] {rec.trace_id or '-'}")
    console.print(f"  * [bold]Session ID:[/bold] {rec.session_id or '-'}")
    console.print(f"  * [bold]Event ID:[/bold] {rec.event_id or '-'}")
    console.print(f"  * [bold]Agent ID:[/bold] {rec.agent_id or '-'}")
    console.print(f"  * [bold]Action ID:[/bold] {rec.action_id or '-'}")
    console.print(f"  * [bold]Span ID:[/bold] {rec.span_id or '-'}")

    if rec.details:
        console.print("\n[bold]Details Payload:[/bold]")
        console.print(json.dumps(sanitize_dict(rec.details), indent=2))

    if rec.metadata:
        console.print("\n[bold]Metadata:[/bold]")
        console.print(json.dumps(sanitize_dict(rec.metadata), indent=2))


@audit_app.command(name="prune")
def audit_prune(
    max_age_days: Optional[int] = typer.Option(None, "--max-age-days", help="Prune records older than N days"),
    max_records: Optional[int] = typer.Option(None, "--max-records", help="Retain at most N newest records"),
    store_path: Optional[str] = typer.Option(None, "--store", help="Path to audit NDJSON log file"),
    json_output: bool = typer.Option(False, "--json", help="Output result as JSON"),
):
    """Prunes audit records based on age or volume retention limits."""
    from runtimeverify.audit import FileAuditRepository

    if max_age_days is None and max_records is None:
        if json_output:
            console.print(
                json.dumps({"error": "Must specify at least one retention policy: --max-age-days or --max-records."})
            )
        else:
            console.print("[red]Must specify at least one retention policy: --max-age-days or --max-records.[/red]")
        raise typer.Exit(code=1)

    path = store_path or ".runtimeverify/audit.log"
    repo = FileAuditRepository(log_path=path)

    initial_count = repo.count()
    pruned = repo.apply_retention(max_age_days=max_age_days, max_records=max_records)
    remaining = repo.count()

    if json_output:
        console.print(
            json.dumps(
                {
                    "store": path,
                    "pruned": pruned,
                    "initial_count": initial_count,
                    "remaining_count": remaining,
                },
                indent=2,
            )
        )
        return

    console.print(
        f"[green]Audit retention applied to '{path}': pruned {pruned} record(s) "
        f"(from {initial_count} down to {remaining}).[/green]"
    )


# ============================================================================
# 10. Markov Engine Operations: train, inspect, explain (Preserved)
# ============================================================================


@app.command()
def train(
    traces_path: str = typer.Argument(..., help="Path to telemetry trace file or folder of logs"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination path for serialized model"),
    smoothing: float = typer.Option(0.01, help="Laplace smoothing parameter"),
):
    """Trains a Markov model from session traces."""
    from runtimeverify.markov.metrics import MarkovMetrics
    from runtimeverify.markov.model import MarkovModel

    if not os.path.exists(traces_path):
        console.print(f"[red]Traces path '{traces_path}' does not exist.[/red]")
        raise typer.Exit(code=2)

    corpus = []
    if os.path.isdir(traces_path):
        files = [
            os.path.join(traces_path, f) for f in os.listdir(traces_path) if f.endswith(".json") or f.endswith(".jsonl")
        ]
        for file in files:
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        corpus.append(data)
            except Exception as e:
                console.print(f"[yellow]Skipping invalid file '{file}': {e}[/yellow]")
    else:
        try:
            with open(traces_path, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    if data and isinstance(data[0], list):
                        corpus = data
                    else:
                        corpus = [data]
        except Exception as e:
            console.print(f"[red]Failed to load file '{traces_path}': {e}[/red]")
            raise typer.Exit(code=4)

    if not corpus:
        console.print("[red]No valid training traces found.[/red]")
        raise typer.Exit(code=4)

    model = MarkovModel(smoothing=smoothing)
    model.train(corpus)

    dest = output or ".runtimeverify/models/default.json"
    dest_dir = os.path.dirname(dest)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    model.save(dest)

    sparsity = MarkovMetrics.calculate_sparsity(model.trainer.matrix)
    console.print(f"[green]Model successfully trained on {len(corpus)} trace sessions.[/green]")
    console.print(f"Saved checkpoint to: [bold cyan]{dest}[/bold cyan]")
    console.print(f"Vocabulary states: {len(model.trainer.counter.states)}")
    console.print(f"Matrix Sparsity: {sparsity:.4f}")


@app.command()
def inspect(
    model_path: str = typer.Argument(".runtimeverify/models/default.json", help="Path to trained model checkpoint"),
):
    """Inspects metrics and states of a trained model."""
    from runtimeverify.markov.metrics import MarkovMetrics
    from runtimeverify.markov.model import MarkovModel

    if not os.path.exists(model_path):
        console.print(f"[red]Model file '{model_path}' not found.[/red]")
        raise typer.Exit(code=4)

    model = MarkovModel()
    try:
        model.load(model_path)
    except Exception as e:
        console.print(f"[red]Failed to parse model file: {e}[/red]")
        raise typer.Exit(code=4)

    sparsity = MarkovMetrics.calculate_sparsity(model.trainer.matrix)
    avg_entropy = MarkovMetrics.calculate_average_entropy(model.trainer.matrix)

    console.print(Panel(f"[bold green]Model Details: {model_path}[/bold green]"))
    console.print("  * [bold]Schema Version:[/bold] 1.0")
    console.print(f"  * [bold]Model Version:[/bold] {model.model_version}")
    console.print(f"  * [bold]Smoothing Value:[/bold] {model.trainer.matrix.smoothing}")
    console.print(f"  * [bold]Unique States Count:[/bold] {len(model.trainer.counter.states)}")
    console.print(f"  * [bold]Transition Matrix Sparsity:[/bold] {sparsity:.4f}")
    console.print(f"  * [bold]Average Shannon Entropy:[/bold] {avg_entropy:.4f}")

    table = Table(title="State Occupancy Vocabulary")
    table.add_column("State Name", style="cyan")
    table.add_column("Occurrence Count", style="magenta")

    for state in sorted(model.trainer.counter.states):
        count = model.trainer.counter.state_counts.get(state, 0)
        table.add_row(state, str(count))

    console.print(table)


@app.command()
def explain(
    prev_state: str = typer.Argument(..., help="Source state label"),
    curr_state: str = typer.Argument(..., help="Target state label"),
    model_path: str = typer.Option(".runtimeverify/models/default.json", "--model", "-m", help="Path to trained model"),
):
    """Explains calculated transition probability between two states."""
    from runtimeverify.markov.model import MarkovModel

    if not os.path.exists(model_path):
        console.print(f"[red]Model file '{model_path}' not found. Run 'verify train' first.[/red]")
        raise typer.Exit(code=4)

    model = MarkovModel()
    model.load(model_path)

    explanation = model.explain(prev_state, curr_state)

    console.print(
        Panel(
            f"[bold yellow]Transition Explanation: {prev_state.upper()} ──► {curr_state.upper()}[/bold yellow]",
            border_style="yellow",
        )
    )
    console.print(f"  * [bold]Computed Probability:[/bold] {explanation.probability:.6f}")
    console.print(f"  * [bold]Observed Transition Count:[/bold] {explanation.observed_transition_count}")
    console.print(f"  * [bold]Total Outgoing State Count:[/bold] {explanation.total_outgoing_count}")

    table = Table(title="Alternative Transitions (Expected Targets)")
    table.add_column("Target State", style="cyan")
    table.add_column("Probability", style="magenta")
    table.add_column("Training Count", style="green")

    for target in explanation.expected_transitions:
        table.add_row(target["state"], f"{target['probability']:.6f}", str(target["count"]))


# ============================================================================
# 10.5. Agent & Attack Replay: replay
# ============================================================================


@app.command()
def replay(
    trace_file: str = typer.Argument(..., help="Path to recorded agent trace file (.json, .jsonl)"),
    policy_path: str = typer.Option("examples/policies/default.yaml", "--policy", "-p", help="Policy YAML file path"),
    compare_policy: Optional[str] = typer.Option(
        None, "--compare-policy", "--compare", "--diff", help="Optional candidate policy YAML to evaluate what-if impact"
    ),
    strategy: str = typer.Option(
        "hybrid", "--strategy", "-s", help="Verification strategy: hybrid, rules, semantic, markov, rules_markov"
    ),
    model_path: Optional[str] = typer.Option(None, "--model", "-m", help="Path to trained Markov model JSON"),
    alpha: float = typer.Option(0.05, "--alpha", help="SPRT Type I error limit (false alarm tolerance)"),
    beta: float = typer.Option(0.05, "--beta", help="SPRT Type II error limit (missed attack tolerance)"),
    fail_fast: bool = typer.Option(False, "--fail-fast", help="Halt replay immediately upon first BLOCK decision"),
    only_interventions: bool = typer.Option(
        False, "--only-interventions", "--flagged-only", help="Display only steps resulting in REVIEW or BLOCK"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output replay report as structured JSON"),
    report_file: Optional[str] = typer.Option(None, "--report", "-r", help="Save Markdown audit report to file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode: return exit code only"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose diagnostic output"),
):
    """
    Replays recorded agent traces through multi-layer verification (Policy, Laya, Markov/SPRT).
    Evaluates historical telemetry against security policies and simulates what-if policy changes.
    Exit codes:
      0 = All steps ALLOW
      2 = At least one step was BLOCKED
      3 = At least one step required REVIEW (none BLOCKED)
      1 = Error reading trace or policy
    """
    from runtimeverify.replay import AgentTraceReplayer, ReplayFormatter

    if not os.path.exists(trace_file):
        if json_output:
            console.print(json.dumps({"error": f"Trace file '{trace_file}' not found", "code": 1}))
        else:
            console.print(f"[red]Error: Trace file '{trace_file}' not found.[/red]")
        raise typer.Exit(code=1)

    try:
        replayer = AgentTraceReplayer(
            policy_path=policy_path,
            compare_policy_path=compare_policy,
            strategy=strategy,
            model_path=model_path,
            alpha=alpha,
            beta=beta,
            fail_fast=fail_fast,
        )
    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": f"Failed to initialize replayer: {e}", "code": 1}))
        else:
            console.print(f"[red]Failed to initialize replayer: {e}[/red]")
        raise typer.Exit(code=1)

    try:
        report = replayer.replay(trace_file)
    except Exception as e:
        if json_output:
            console.print(json.dumps({"error": f"Replay execution failed: {e}", "code": 1}))
        else:
            console.print(f"[red]Replay execution failed: {e}[/red]")
        raise typer.Exit(code=1)

    # 1. JSON Output
    if json_output:
        console.print(json.dumps(report.model_dump(mode="json"), indent=2))
    # 2. Terminal Visual Output
    elif not quiet:
        ReplayFormatter.render_terminal(
            report,
            console=console,
            verbose=verbose,
            only_interventions=only_interventions,
        )

    # 3. Optional Markdown Report File
    if report_file:
        try:
            md_content = ReplayFormatter.render_markdown(report)
            with open(report_file, "w", encoding="utf-8") as f:
                f.write(md_content)
            if not quiet and not json_output:
                console.print(f"[green]Audit report written to [bold]{report_file}[/bold][/green]")
        except Exception as e:
            if not quiet and not json_output:
                console.print(f"[yellow]Warning: Failed to save report file: {e}[/yellow]")

    # 4. Exit Code Resolution
    if report.summary.overall_verdict == "BLOCK":
        raise typer.Exit(code=2)
    elif report.summary.overall_verdict == "REVIEW":
        raise typer.Exit(code=3)
    else:
        raise typer.Exit(code=0)


# ============================================================================
# 11. Dynamic Plugin Subcommand Loading
# ============================================================================


def load_plugins():
    """Loads and registers subcommands from third-party verification packages dynamically."""
    try:
        eps = importlib.metadata.entry_points(group="runtimeverify.cli")
    except TypeError:
        eps = importlib.metadata.entry_points().get("runtimeverify.cli", [])

    for ep in eps:
        try:
            plugin_app = ep.load()
            if isinstance(plugin_app, typer.Typer):
                app.add_typer(plugin_app, name=ep.name)
        except Exception as e:
            sys.stderr.write(f"Warning: Failed to load plugin command '{ep.name}': {e}\n")


def main():
    load_plugins()
    app()


if __name__ == "__main__":
    main()

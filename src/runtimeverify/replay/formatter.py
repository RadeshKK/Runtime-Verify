"""
Rich terminal formatting, JSON serialization, and Markdown report generation
for the RuntimeVerify Attack / Agent Replay Engine.
"""

from typing import Any, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from runtimeverify.replay.models import ReplayReport, ReplayStep


class ReplayFormatter:
    """
    Renders replayed agent trace reports to rich terminal UI, JSON, and Markdown documents.
    """

    @classmethod
    def render_terminal(
        cls,
        report: ReplayReport,
        console: Console,
        verbose: bool = False,
        only_interventions: bool = False,
    ) -> None:
        """Prints a comprehensive rich terminal visual representation of the replay report."""

        # 1. Header Panel
        strat_badge = f"[bold cyan]{report.strategy.upper()}[/bold cyan]"
        verdict_color = "green" if report.summary.overall_verdict == "ALLOW" else ("red" if report.summary.overall_verdict == "BLOCK" else "yellow")
        verdict_badge = f"[bold {verdict_color}]{report.summary.overall_verdict}[/bold {verdict_color}]"

        header_text = (
            f"[bold white]Trace Source:[/bold white] {report.trace_source}\n"
            f"[bold white]Session ID:[/bold white] {report.session_id}  |  "
            f"[bold white]Agent ID:[/bold white] {report.agent_id}\n"
            f"[bold white]Policy:[/bold white] {report.policy_path}\n"
            f"[bold white]Strategy:[/bold white] {strat_badge}  |  "
            f"[bold white]Overall Verdict:[/bold white] {verdict_badge}"
        )
        console.print(Panel(header_text, title="[bold]RuntimeVerify Attack & Agent Replay[/bold]", border_style="cyan"))

        # 2. Replay Steps Table
        steps_to_show = report.steps
        if only_interventions:
            steps_to_show = [s for s in report.steps if s.final_verdict in ("REVIEW", "BLOCK")]

        if not steps_to_show and only_interventions:
            console.print("[dim italic]No security interventions recorded (all actions were ALLOWED).[/dim italic]\n")
        else:
            table = Table(
                title=f"Step-by-Step Replay Trace ({len(steps_to_show)} of {len(report.steps)} steps displayed)",
                title_style="bold magenta",
                header_style="bold steel_blue",
                show_lines=True,
            )

            table.add_column("#", justify="right", style="bold dim")
            table.add_column("Action", style="cyan")
            table.add_column("Target", style="white")
            table.add_column("Policy Layer", justify="center")
            table.add_column("Laya Semantic", justify="center")
            table.add_column("Markov/SPRT", justify="center")
            table.add_column("Verdict", justify="center")
            table.add_column("Latency", justify="right", style="dim")

            for s in steps_to_show:
                # Format Policy column
                if s.policy_verdict == "BLOCK":
                    pol_cell = f"[bold red]BLOCK[/bold red]\n[dim]{s.policy_id or ''}[/dim]"
                elif s.policy_verdict == "REVIEW":
                    pol_cell = f"[bold yellow]REVIEW[/bold yellow]\n[dim]{s.policy_id or ''}[/dim]"
                else:
                    pol_cell = "[green]ALLOW[/green]"

                # Format Semantic (Laya) column
                if s.semantic_verdict == "CRITICAL":
                    sem_cell = f"[bold red]CRITICAL[/bold red]\n[dim]{s.semantic_category or ''}[/dim]"
                elif s.semantic_verdict == "SUSPICIOUS":
                    sem_cell = f"[bold yellow]SUSPICIOUS[/bold yellow]\n[dim]{s.semantic_category or ''}[/dim]"
                else:
                    sem_cell = "[green]SAFE[/green]"

                # Format Markov / SPRT column
                if s.sprt_status == "ACCEPT_H1":
                    sprt_cell = f"[bold red]DRIFT (H1)[/bold red]\n[dim]LLR: {s.sprt_llr or 0:.2f}[/dim]"
                elif s.markov_probability is not None and s.markov_probability < 1e-4:
                    sprt_cell = f"[bold yellow]RARE (p<1e-4)[/bold yellow]\n[dim]{s.markov_state or ''}[/dim]"
                else:
                    p_str = f"p={s.markov_probability:.2f}" if s.markov_probability is not None else "p=1.00"
                    sprt_cell = f"[green]NORMAL[/green]\n[dim]{p_str}[/dim]"

                # Format Verdict column
                if s.final_verdict == "BLOCK":
                    verdict_cell = "[bold red reverse] BLOCK [/bold red reverse]"
                elif s.final_verdict == "REVIEW":
                    verdict_cell = "[bold yellow reverse] REVIEW [/bold yellow reverse]"
                else:
                    verdict_cell = "[bold green] ALLOW [/bold green]"

                act_cell = f"{s.action_type}:{s.name}"
                target_cell = s.target
                latency_cell = f"{s.latency_ms:.2f}ms"

                table.add_row(
                    str(s.step_number),
                    act_cell,
                    target_cell,
                    pol_cell,
                    sem_cell,
                    sprt_cell,
                    verdict_cell,
                    latency_cell,
                )

            console.print(table)

        # 3. What-If Policy Comparison Table (if active)
        if report.comparison:
            comp = report.comparison
            comp_table = Table(
                title=f"What-If Policy Comparison: Baseline vs Candidate Policy",
                title_style="bold yellow",
                header_style="bold orange1",
                show_lines=True,
            )
            comp_table.add_column("Step", justify="right", style="bold dim", width=5)
            comp_table.add_column("Target", style="white", min_width=20, max_width=35, overflow="ellipsis")
            comp_table.add_column("Baseline Verdict", justify="center", width=16)
            comp_table.add_column("Candidate Verdict", justify="center", width=16)
            comp_table.add_column("Impact / Delta", style="bold", width=25)

            for s in report.steps:
                if s.verdict_diverged or verbose:
                    b_style = "green" if s.final_verdict == "ALLOW" else ("red" if s.final_verdict == "BLOCK" else "yellow")
                    c_verdict = s.comparison_verdict or "ALLOW"
                    c_style = "green" if c_verdict == "ALLOW" else ("red" if c_verdict == "BLOCK" else "yellow")

                    if s.verdict_diverged:
                        if c_verdict == "BLOCK" and s.final_verdict == "ALLOW":
                            impact = "[bold red]TIGHTENED (Newly Blocked)[/bold red]"
                        elif c_verdict == "ALLOW" and s.final_verdict == "BLOCK":
                            impact = "[bold yellow]LOOSENED (Newly Allowed)[/bold yellow]"
                        else:
                            impact = f"[yellow]{s.final_verdict} -> {c_verdict}[/yellow]"
                    else:
                        impact = "[dim]Identical[/dim]"

                    comp_table.add_row(
                        str(s.step_number),
                        s.target,
                        f"[{b_style}]{s.final_verdict}[/{b_style}]",
                        f"[{c_style}]{c_verdict}[/{c_style}]",
                        impact,
                    )

            console.print(comp_table)
            console.print(Panel(
                f"[bold cyan]What-If Impact Analysis:[/bold cyan] {comp.delta_description}\n"
                f"[dim]Baseline Blocks: {comp.baseline_blocks}  |  Candidate Blocks: {comp.candidate_blocks}  |  Divergent Steps: {comp.divergent_steps}[/dim]",
                title="Policy Change Assessment",
                border_style="yellow",
            ))

        # 4. Summary & Verification Verdict Panel
        s = report.summary
        summary_lines = [
            f"[bold white]Total Evaluated Steps:[/bold white] {s.total_steps}  "
            f"([bold green]{s.allowed_steps} ALLOW[/bold green] | "
            f"[bold yellow]{s.reviewed_steps} REVIEW[/bold yellow] | "
            f"[bold red]{s.blocked_steps} BLOCK[/bold red])",
            f"[bold white]Layer Activations:[/bold white] "
            f"Policy rules: [cyan]{s.policy_triggers_count}[/cyan] | "
            f"Laya semantic flags: [cyan]{s.semantic_flags_count}[/cyan] | "
            f"Markov/SPRT drift: [cyan]{s.sprt_anomalies_count}[/cyan]",
            f"[bold white]Verification Latency:[/bold white] "
            f"Mean: [green]{s.avg_latency_ms:.3f}ms[/green] | Peak: {s.max_latency_ms:.3f}ms | Total Elapsed: {s.total_duration_ms:.2f}ms",
        ]

        if s.first_intervention_step is not None:
            rule_id = ""
            if s.first_intervention_layer == "Policy" and s.first_intervention_step <= len(report.steps):
                step_obj = report.steps[s.first_intervention_step - 1]
                if step_obj.policy_id:
                    rule_id = f" (Rule: {step_obj.policy_id})"

            summary_lines.append(
                f"[bold red]First Security Intervention:[/bold red] Step [bold]{s.first_intervention_step}[/bold] "
                f"triggered by [bold cyan]{s.first_intervention_layer}{rule_id}[/bold cyan]\n"
                f"  [dim italic]Reason: {s.first_intervention_reason}[/dim italic]"
            )
        else:
            summary_lines.append("[bold green]All actions in this trace satisfied active verification constraints.[/bold green]")

        console.print(Panel("\n".join(summary_lines), title="[bold]Replay Summary[/bold]", border_style=verdict_color))

    @classmethod
    def render_markdown(cls, report: ReplayReport) -> str:
        """Generates a complete GitHub Flavored Markdown audit report."""
        lines = [
            f"# Attack & Agent Replay Audit Report",
            f"",
            f"**Trace Source:** `{report.trace_source}`  ",
            f"**Session ID:** `{report.session_id}` | **Agent ID:** `{report.agent_id}`  ",
            f"**Strategy:** `{report.strategy}` | **Policy:** `{report.policy_path}`  ",
            f"**Execution Date:** `{report.timestamp.isoformat()}`  ",
            f"**Overall Verdict:** **`{report.summary.overall_verdict}`**  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary",
            f"",
            f"| Metric | Value |",
            f"| :--- | :--- |",
            f"| **Total Steps** | {report.summary.total_steps} |",
            f"| **Allowed Actions** | {report.summary.allowed_steps} |",
            f"| **Review Required** | {report.summary.reviewed_steps} |",
            f"| **Blocked Actions** | {report.summary.blocked_steps} |",
            f"| **First Intervention** | Step {report.summary.first_intervention_step or 'None'} ({report.summary.first_intervention_layer or 'N/A'}) |",
            f"| **Mean Step Latency** | {report.summary.avg_latency_ms:.3f} ms |",
            f"| **Total Replay Time** | {report.summary.total_duration_ms:.2f} ms |",
            f"",
            f"---",
            f"",
            f"## 2. Multi-Layer Verification Flow",
            f"",
            f"```mermaid",
            f"flowchart TD",
            f"    A[\"Recorded Agent Trace: {report.session_id}\"] --> B[\"Agent Replay Engine\"]",
            f"    B --> C[\"Deterministic Policy\"]",
            f"    B --> D[\"Laya Semantic Analysis\"]",
            f"    B --> E[\"Markov / SPRT Sequential Drift\"]",
            f"    C --> F[\"Synthesized Verification\"]",
            f"    D --> F",
            f"    E --> F",
            f"    F --> G{{\"Final Decision: {report.summary.overall_verdict}\"}}",
            f"```",
            f"",
            f"---",
            f"",
            f"## 3. Step-by-Step Telemetry",
            f"",
            f"| Step | Action | Target | Policy Layer | Laya Semantic | Markov/SPRT | Verdict | Latency |",
            f"| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for s in report.steps:
            pol = f"`{s.policy_verdict}`" if s.policy_verdict == "ALLOW" else f"**`{s.policy_verdict}`** ({s.policy_id})"
            sem = f"`{s.semantic_verdict}`" if s.semantic_verdict == "SAFE" else f"**`{s.semantic_verdict}`** ({s.semantic_category})"
            if s.sprt_status == "ACCEPT_H1":
                llr_str = f"{s.sprt_llr:.2f}" if s.sprt_llr is not None else "0.00"
                sprt = f"**`DRIFT_H1`** (LLR={llr_str})"
            elif s.markov_probability is not None and s.markov_probability < 1e-4:
                sprt = f"**`RARE_TRANSITION`** (p={s.markov_probability:.4f})"
            else:
                p_str = f"p={s.markov_probability:.2f}" if s.markov_probability is not None else "p=1.00"
                sprt = f"`NORMAL` ({p_str})"
            v = f"**`{s.final_verdict}`**"
            lines.append(f"| {s.step_number} | `{s.action_type}:{s.name}` | `{s.target}` | {pol} | {sem} | {sprt} | {v} | {s.latency_ms:.2f}ms |")

        if report.comparison:
            comp = report.comparison
            lines.extend([
                f"",
                f"---",
                f"",
                f"## 4. What-If Policy Change Analysis",
                f"",
                f"**Baseline Policy:** `{comp.baseline_policy}`  ",
                f"**Candidate Policy:** `{comp.candidate_policy}`  ",
                f"**Impact Summary:** {comp.delta_description}  ",
                f"",
                f"| Step | Target | Baseline Verdict | Candidate Verdict | Divergence |",
                f"| :--- | :--- | :--- | :--- | :--- |",
            ])
            for s in report.steps:
                if s.verdict_diverged:
                    lines.append(f"| {s.step_number} | `{s.target}` | `{s.final_verdict}` | **`{s.comparison_verdict}`** | Changed |")

        lines.extend([
            f"",
            f"---",
            f"",
            f"*Generated by RuntimeVerify Attack Replay Engine*",
        ])

        return "\n".join(lines)

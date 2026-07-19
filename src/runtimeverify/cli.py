import os
import sys
import json
import yaml
import typer
import importlib.metadata
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

app = typer.Typer(name="verify", help="AI Runtime Verification Framework CLI")
console = Console()

# Default configuration template
DEFAULT_CONFIG = {
    "version": "1.0",
    "workspace": {
        "model_dir": ".runtimeverify/models",
        "session_db": ".runtimeverify/sessions.db"
    },
    "verification": {
        "alpha": 0.05,
        "beta": 0.05,
        "smoothing": 0.01,
        "default_model": "default.json"
    },
    "policy": {
        "default_action": "ALLOW",
        "threshold": 5.0
    }
}

DEFAULT_RULES = [
    {
        "target_state": "READ_SYSTEM_SECRET",
        "conditions": {
            "action": "read",
            "resource_type": "system_secret"
        }
    },
    {
        "target_state": "WRITE_SOURCE_CODE",
        "conditions": {
            "action": "write",
            "resource_type": "source_code"
        }
    }
]

@app.command()
def init(
    directory: str = typer.Argument(".", help="Target directory for initialization"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing configuration")
):
    """Initializes a new runtime verification workspace."""
    target_dir = os.path.join(directory, ".runtimeverify")
    config_file = os.path.join(target_dir, "config.yaml")
    rules_file = os.path.join(target_dir, "rules.json")
    models_dir = os.path.join(target_dir, "models")

    if os.path.exists(target_dir) and not force:
        console.print("[red]Workspace is already initialized. Use --force to overwrite.[/red]")
        raise typer.Exit(code=2)

    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    with open(config_file, "w") as f:
        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)

    with open(rules_file, "w") as f:
        json.dump(DEFAULT_RULES, f, indent=2)

    console.print(f"[green]Successfully initialized verify workspace at {target_dir}[/green]")


@app.command()
def train(
    traces_path: str = typer.Argument(..., help="Path to telemetry trace file or folder of logs"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Destination path for serialized model"),
    smoothing: float = typer.Option(0.01, help="Laplace smoothing parameter")
):
    """Trains a Markov model from session traces."""
    from runtimeverify.markov.model import MarkovModel
    from runtimeverify.markov.metrics import MarkovMetrics

    # Load traces from file/directory
    if not os.path.exists(traces_path):
        console.print(f"[red]Traces path '{traces_path}' does not exist.[/red]")
        raise typer.Exit(code=2)

    corpus = []
    if os.path.isdir(traces_path):
        files = [os.path.join(traces_path, f) for f in os.listdir(traces_path) if f.endswith(".json") or f.endswith(".jsonl")]
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
                    # Check if it's a list of lists (multiple sessions) or single list
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

    # Train model
    model = MarkovModel(smoothing=smoothing)
    model.train(corpus)

    # Resolve output path
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
    model_path: str = typer.Argument(".runtimeverify/models/default.json", help="Path to trained model checkpoint")
):
    """Inspects metrics and states of a trained model."""
    from runtimeverify.markov.model import MarkovModel
    from runtimeverify.markov.metrics import MarkovMetrics

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
    model_path: str = typer.Option(".runtimeverify/models/default.json", "--model", "-m", help="Path to trained model")
):
    """Explains calculated transition probability between two states."""
    from runtimeverify.markov.model import MarkovModel

    if not os.path.exists(model_path):
        console.print(f"[red]Model file '{model_path}' not found. Run 'verify train' first.[/red]")
        raise typer.Exit(code=4)

    model = MarkovModel()
    model.load(model_path)

    explanation = model.explain(prev_state, curr_state)

    console.print(Panel(
        f"[bold yellow]Transition Explanation: {prev_state.upper()} ──► {curr_state.upper()}[/bold yellow]",
        border_style="yellow"
    ))
    console.print(f"  * [bold]Computed Probability:[/bold] {explanation.probability:.6f}")
    console.print(f"  * [bold]Observed Transition Count:[/bold] {explanation.observed_transition_count}")
    console.print(f"  * [bold]Total Outgoing State Count:[/bold] {explanation.total_outgoing_count}")

    table = Table(title="Alternative Transitions (Expected Targets)")
    table.add_column("Target State", style="cyan")
    table.add_column("Probability", style="magenta")
    table.add_column("Training Count", style="green")

    for target in explanation.expected_transitions:
        table.add_row(target["state"], f"{target['probability']:.6f}", str(target["count"]))

    console.print(table)


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

    if all_pass:
        console.print("\n[bold green]Doctor checks completed successfully! Workspace is healthy.[/bold green]")
    else:
        console.print("\n[bold yellow]Doctor identified warning markers. Follow recommendations to resolve.[/bold yellow]")


@app.command()
def version():
    """Prints framework version information."""
    console.print("AI Runtime Verification Framework (verify) [bold cyan]v0.1.0[/bold cyan]")


def load_plugins():
    """Loads and registers subcommands from third-party verification packages dynamically."""
    try:
        eps = importlib.metadata.entry_points(group="runtimeverify.cli")
    except TypeError:
        # Fallback for older python
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

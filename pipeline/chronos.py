import json
import typer
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from pipeline.ingest import (
    detect_evidence_type,
    hash_file_sha256,
    format_size,
    show_evidence_info,
    write_manifest,
    generate_results,
    ingest_evidence,
)

# Import parser functions directly
from pipeline.parsers import (
    parse_registry,
    parse_mft,
    parse_prefetch,
    parse_memory,
    parse_disk,
)

app = typer.Typer(name="chronos", add_completion=False)
console = Console()


def write_events(case_id: str, output_dir: Path, events: list):
    """Helper to normalize and write events to JSONL."""
    from pipeline.normalize import normalize_events
    normalized = [normalize_events(ev) for ev in events]
    events_file = output_dir / f"{case_id}_events.jsonl"
    with events_file.open("w", encoding="utf-8") as f:
        for ev in normalized:
            f.write(json.dumps(ev) + "\n")
    return events_file


@app.command()
def analyze(
    evidence: Path = typer.Argument(..., help="Path to evidence (disk image, memory dump, registry hive, etc.)"),
    case_id: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for results"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, html, csv"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    console.print(f"\n[bold blue]Chronos - Forensic Analysis Pipeline[/bold blue]")
    console.print(f"Case ID: [bold]{case_id}[/bold]")

    # Normalize and validate evidence path
    evidence = evidence.resolve()
    console.print(f"Evidence: [bold]{evidence}[/bold]")
    if not evidence.exists():
        console.print(f"[red]Error: Evidence path does not exist: {evidence}[/red]")
        raise typer.Exit(1)

    # Set default output directory
    output_dir = (output_dir or Path(f"./chronos_output/{case_id}")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Show evidence info
    show_evidence_info(evidence)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Analyzing evidence...", total=None)

        try:
            # 1. Ingest evidence (hash, manifest, metadata)
            metadata = ingest_evidence(case_id, evidence, output_dir)
            evidence_type = metadata["evidence_type"]

            # 2. Parser dispatch
            events = []
            if evidence_type == "Disk":
                events.extend(parse_disk(evidence))
            elif evidence_type == "Memory":
                events.extend(parse_memory(evidence))
            elif evidence_type == "Hive":
                events.extend(parse_registry(evidence))
            elif evidence_type == "MFT":
                events.extend(parse_mft(evidence))
            elif evidence_type == "Prefetch":
                events.extend(parse_prefetch(evidence))
            else:
                console.print(f"[yellow]No parser available for {evidence_type}[/yellow]")

            if not events:
                console.print("[yellow]No events extracted from this evidence[/yellow]")
                return

            # 3. Write normalized events
            events_file = write_events(case_id, output_dir, events)
            progress.update(task, description=f"Analysis complete! Results saved: {events_file}")

        except Exception as e:
            console.print(f"[red]Analysis failed: {e}[/red]")
            raise typer.Exit(1)

    # Final case results
    generate_results(case_id, evidence, output_dir, format, verbose)


@app.command()
def timeline(
    case_id: str = typer.Argument(..., help="Case identifier"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: html, json, csv"),
    start_time: Optional[str] = typer.Option(None, "--start", help="Start time (ISO format)"),
    end_time: Optional[str] = typer.Option(None, "--end", help="End time (ISO format)"),
    event_types: Optional[List[str]] = typer.Option(None, "--types", help="Filter by event types"),
    severity: Optional[List[str]] = typer.Option(None, "--severity", help="Filter by severity levels"),
):
    console.print(f"\n[bold blue]Generating Timeline[/bold blue]")
    console.print(f"Case ID: [bold]{case_id}[/bold]")
    console.print("[yellow]Timeline generation not yet implemented[/yellow]")


@app.command()
def status(
    case_id: Optional[str] = typer.Option(None, "--case", "-c", help="Case identifier"),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all cases"),
):
    if list_all:
        console.print("[yellow]Case listing not yet implemented[/yellow]")
    elif case_id:
        console.print(f"[yellow]Case status for {case_id} not yet implemented[/yellow]")
    else:
        console.print("[yellow]Please specify --case or --list[/yellow]")


@app.command()
def export(
    case_id: str = typer.Argument(..., help="Case identifier"),
    format: str = typer.Option("json", "--format", "-f", help="Export format: json, csv, parquet"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    filter_types: Optional[List[str]] = typer.Option(None, "--types", help="Filter by event types"),
):
    console.print(f"\n[bold blue]Exporting Results[/bold blue]")
    console.print(f"Case ID: [bold]{case_id}[/bold]")
    console.print(f"Format: [bold]{format}[/bold]")
    console.print("[yellow]Export functionality not yet implemented[/yellow]")


if __name__ == "__main__":
    app()

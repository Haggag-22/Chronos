import typer
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
import json

# Import utils
from pipeline.parsers import disk, registry_ttest
from pipeline.utils.hashing import hash_file_sha256
from pipeline.utils.manifest import write_manifest
from pipeline.utils.detect import detect_evidence_type
from pipeline.utils.evidence import show_evidence_info, generate_results

app = typer.Typer(name="chronos", add_completion=False)
console = Console()

@app.command()
def analyze(
    evidence: Path = typer.Argument(..., help="Path to evidence (disk image, memory dump, or directory)"),
    case_id: str = typer.Option(..., "--case", "-c", help="Case identifier"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for results"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, html, csv"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    console.print(f"\n[bold blue]Chronos - Forensic Analysis Pipeline[/bold blue]")
    console.print(f"Case ID: [bold]{case_id}[/bold]")
    console.print(f"Evidence: [bold]{evidence}[/bold]")

    # Validate evidence path
    if not evidence.exists():
        console.print(f"[red]Error: Evidence path does not exist: {evidence}[/red]")
        raise typer.Exit(1)

    # Set default output directory
    if not output_dir:
        output_dir = Path(f"./chronos_output/{case_id}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Show evidence info
    show_evidence_info(evidence)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Analyzing evidence...", total=None)

        try:
            # 1. Ingest: hash + manifest
            
            size_bytes = evidence.stat().st_size
            evidence_type = detect_evidence_type(evidence)
            sha256_hex = hash_file_sha256(evidence)
            write_manifest(case_id, output_dir, evidence, evidence_type, size_bytes, sha256_hex)
            

            # 2. Call parsers (depending on evidence type)
            
            events = []
            if evidence_type == "Disk Image":
                from pipeline.parsers import mft, prefetch
                events.extend(mft.parse(evidence))
                events.extend(registry_ttest.parse(evidence))
                events.extend(prefetch.parse(evidence))
                events.extend(disk.parse(evidence))
            elif evidence_type == "Memory Dump":
                from pipeline.parsers import memory
                events.extend(memory.parse(evidence))
                

            # 3. Normalize and write raw events
            
            from pipeline.normalize import normalize_events
            normalized = [normalize_events(ev) for ev in events]

            events_file = output_dir / f"{case_id}_events.jsonl"
            with events_file.open("w") as f:
                for ev in normalized:
                    f.write(json.dumps(ev) + "\n")

            progress.update(task, description="Analysis complete!")

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

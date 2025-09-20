from pathlib import Path
from datetime import datetime
import json
from rich.table import Table
from rich.console import Console

from pipeline.utils.size import format_size
from pipeline.utils.detect import detect_evidence_type

console = Console()

def show_evidence_info(evidence: Path):
    """Print metadata about evidence file in a Rich table."""
    info_table = Table(title="Evidence Information")
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")

    info_table.add_row("Path", str(evidence))
    info_table.add_row("Type", "File" if evidence.is_file() else "Directory")
    info_table.add_row("Size", f"{format_size(evidence.stat().st_size)}")
    info_table.add_row("Modified", datetime.fromtimestamp(evidence.stat().st_mtime).isoformat())
    info_table.add_row("Detected Type", detect_evidence_type(evidence))

    console.print(info_table)


def generate_results(case_id: str, evidence: Path, output_dir: Path,
                     format: str, verbose: bool):
    """Save case results summary JSON file and print summary."""
    results = {
        "case_id": case_id,
        "evidence_path": str(evidence),
        "analysis_timestamp": datetime.utcnow().isoformat(),
        "output_directory": str(output_dir),
        "format": format,
        "status": "completed"
    }
    results_file = output_dir / f"{case_id}_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)

    console.print(f"\n[green]Analysis completed![/green]")
    console.print(f"Results saved to: [bold]{results_file}[/bold]")

    if verbose:
        console.print(json.dumps(results, indent=2))
 
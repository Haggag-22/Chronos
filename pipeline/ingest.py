import json
import hashlib
from pathlib import Path
from datetime import datetime
from rich.table import Table
from rich.console import Console

console = Console()

# ------------------------------
# Evidence Type Detection
# ------------------------------
def detect_evidence_type(evidence: Path) -> str:
    """Detect the type of forensic evidence based on file extension."""
    if evidence.is_file():
        suffix = evidence.suffix.lower()
        if suffix in ['.img', '.dd', '.raw', '.e01', '.vmdk', '.vhd', '.vhdx']:
            return "Disk"
        elif suffix in ['.dmp', '.mem', '.vmem', '.hiberfil.sys']:
            return "Memory"
        elif suffix in ['.dat', '.hiv', '.hive']:
            return "Hive"
        elif suffix == '.mft':
            return "MFT"
        elif suffix == '.pf':
            return "Prefetch"
        else:
            return "Unknown File"
    elif evidence.is_dir():
        return "Evidence Directory"
    return "Unknown"

# ------------------------------
# Hashing
# ------------------------------
def hash_file_sha256(file_path: Path, chunk_size: int = 8192) -> str:
    """Return the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# ------------------------------
# File Size Formatting
# ------------------------------
def format_size(size_bytes: int) -> str:
    """Convert bytes into human readable string (KB, MB, GB)."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"

# ------------------------------
# Evidence Metadata Display
# ------------------------------
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

# ------------------------------
# Manifest Writing
# ------------------------------
def write_manifest(case_id: str, output_dir: Path, evidence: Path,
                   evidence_type: str, size_bytes: int, sha256: str) -> Path:
    """Write a simple case manifest with evidence metadata."""
    manifest = {
        "Case Id": case_id,
        "Evidence": str(evidence),
        "Evidence Type": evidence_type,
        "Size Bytes": size_bytes,
        "Sha256": sha256,
        "Timestamp": datetime.utcnow().isoformat()
    }
    manifest_path = output_dir / f"{case_id}_manifest.json"
    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2)
    return manifest_path

# ------------------------------
# Results Writer
# ------------------------------
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

# ------------------------------
# Ingest Evidence (main entry)
# ------------------------------
def ingest_evidence(case_id: str, evidence: Path, output_dir: Path) -> dict:
    """Ingest evidence: hash, detect type, write manifest, return metadata."""
    size_bytes = evidence.stat().st_size
    evidence_type = detect_evidence_type(evidence)
    sha256 = hash_file_sha256(evidence)
    manifest_path = write_manifest(case_id, output_dir, evidence, evidence_type, size_bytes, sha256)

    return {
        "case_id": case_id,
        "evidence": str(evidence),
        "evidence_type": evidence_type,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "manifest_path": str(manifest_path)
    }

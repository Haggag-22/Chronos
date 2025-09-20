import json
from pathlib import Path
from datetime import datetime

def write_manifest(case_id: str, output_dir: Path, evidence: Path, evidence_type: str, size_bytes: int, sha256: str) -> Path:
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

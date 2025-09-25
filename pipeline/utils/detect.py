from pathlib import Path

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

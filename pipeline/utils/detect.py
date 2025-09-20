from pathlib import Path

def detect_evidence_type(evidence: Path) -> str:
    """Detect the type of forensic evidence based on file extension."""
    if evidence.is_file():
        suffix = evidence.suffix.lower()
        if suffix in ['.img', '.dd', '.raw', '.e01', '.vmdk', '.vhd', '.vhdx']:
            return "Disk Image"
        elif suffix in ['.dmp', '.mem', '.vmem', '.hiberfil.sys']:
            return "Memory Dump"
        elif suffix in ['.dat', '.hiv', '.hive']:
            return "Registry Hive"
        elif suffix == '.mft':
            return "MFT File"
        elif suffix == '.pf':
            return "Prefetch File"
        else:
            return "Unknown File"
    elif evidence.is_dir():
        return "Evidence Directory"
    return "Unknown"

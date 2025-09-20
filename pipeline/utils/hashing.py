import hashlib
from pathlib import Path

def hash_file_sha256(file_path: Path, chunk_size: int = 8192) -> str:
    """Return the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

"""Content-addressed evidence storage helpers.

Large/raw evidence is intentionally separated from the relational observation
metadata. Only hashes and small metadata need to live in SQLite.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True, slots=True)
class EvidenceBlob:
    digest: str
    path: Path
    size: int


class EvidenceStore:
    def __init__(self, root: str | Path = "reconforge-evidence") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes) -> EvidenceBlob:
        digest = sha256(data).hexdigest()
        destination = self.root / digest[:2] / digest[2:4] / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            destination.write_bytes(data)
        return EvidenceBlob(digest, destination, len(data))

    def get(self, digest: str) -> bytes | None:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError("invalid evidence digest")
        path = self.root / digest[:2] / digest[2:4] / digest
        return path.read_bytes() if path.exists() else None

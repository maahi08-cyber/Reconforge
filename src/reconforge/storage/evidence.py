"""Content-addressed evidence storage helpers.

Large/raw evidence is intentionally separated from relational observation
metadata. Only hashes and small metadata need to live in SQLite. Content is
immutable: a digest always maps to the same bytes.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import json


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

    def put_json(self, value: object) -> EvidenceBlob:
        return self.put(json.dumps(value, sort_keys=True, default=str).encode("utf-8"))

    def get(self, digest: str) -> bytes | None:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError("invalid evidence digest")
        path = self.root / digest[:2] / digest[2:4] / digest
        return path.read_bytes() if path.exists() else None

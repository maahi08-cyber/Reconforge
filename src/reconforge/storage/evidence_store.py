"""Content-addressed evidence storage.

Large evidence payloads live outside the relational metadata tables. The store
uses SHA-256 content identity so identical evidence is only persisted once.
Secrets should be redacted by callers before writing sensitive material.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    digest: str
    size: int
    path: Path


class ContentAddressedEvidenceStore:
    def __init__(self, root: str | Path = "reconforge-evidence") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, content: bytes) -> EvidenceRef:
        digest = sha256(content).hexdigest()
        directory = self.root / digest[:2]
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / digest
        if not path.exists():
            path.write_bytes(content)
        return EvidenceRef(digest, len(content), path)

    def get(self, digest: str) -> bytes:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError("invalid evidence digest")
        return (self.root / digest[:2] / digest).read_bytes()

    def exists(self, digest: str) -> bool:
        return (self.root / digest[:2] / digest).is_file()

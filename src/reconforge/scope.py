"""Strict target-scope checks for ReconForge."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """Allow-list policy. Exact hosts and wildcard subdomains are supported."""
    allowed: tuple[str, ...]
    denied: tuple[str, ...] = ()

    def allows(self, value: str) -> bool:
        host = (urlsplit(value).hostname or value).lower().rstrip(".")
        if any(self._matches(host, pattern.lower().rstrip(".")) for pattern in self.denied):
            return False
        return any(self._matches(host, pattern.lower().rstrip(".")) for pattern in self.allowed)

    @staticmethod
    def _matches(host: str, pattern: str) -> bool:
        if fnmatch(host, pattern):
            return True
        # *.example.com intentionally includes only subdomains, not sibling domains.
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return host.endswith(suffix) and host != suffix[1:]
        return host == pattern

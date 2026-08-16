"""Explicit authorization scope checks for active collection."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    allowed_hosts: tuple[str, ...] = ()
    denied_hosts: tuple[str, ...] = ()

    def allows(self, value: str) -> bool:
        host = (urlsplit(value).hostname or value).lower().rstrip(".")
        if any(fnmatch(host, pattern.lower()) for pattern in self.denied_hosts):
            return False
        if not self.allowed_hosts:
            return False
        return any(fnmatch(host, pattern.lower()) for pattern in self.allowed_hosts)

"""Adapter interfaces for reconnaissance sensors."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping, Protocol

from reconforge.models import Observation, Target


@dataclass(frozen=True, slots=True)
class AdapterContext:
    run_id: str
    timeout_seconds: float = 60.0
    rate_limit_per_second: float = 5.0
    max_concurrency: int = 4
    environment: Mapping[str, str] = field(default_factory=dict)


class Adapter(Protocol):
    name: str
    capabilities: frozenset[str]

    def collect(self, target: Target, context: AdapterContext) -> Iterable[Observation]: ...


@dataclass(frozen=True, slots=True)
class AdapterSpec:
    name: str
    binary: str
    capabilities: frozenset[str]
    passive: bool = True
    requires_scope: bool = True
    safe_default: bool = True


DEFAULT_ADAPTERS = (
    AdapterSpec("subfinder", "subfinder", frozenset({"subdomain", "passive"})),
    AdapterSpec("amass", "amass", frozenset({"asset_graph", "subdomain", "passive"})),
    AdapterSpec("dnsx", "dnsx", frozenset({"dns", "resolution"}), passive=False, safe_default=False),
    AdapterSpec("httpx", "httpx", frozenset({"http", "fingerprint"}), passive=False, safe_default=False),
    AdapterSpec("katana", "katana", frozenset({"crawl", "javascript", "endpoint"}), passive=False, safe_default=False),
    AdapterSpec("gau", "gau", frozenset({"historical_url", "passive"})),
    AdapterSpec("waybackurls", "waybackurls", frozenset({"historical_url", "passive"})),
    AdapterSpec("naabu", "naabu", frozenset({"port"}), passive=False, safe_default=False),
    AdapterSpec("nmap", "nmap", frozenset({"service", "version"}), passive=False, safe_default=False),
    AdapterSpec("nuclei", "nuclei", frozenset({"template_signal", "detection"}), passive=False, safe_default=False),
)

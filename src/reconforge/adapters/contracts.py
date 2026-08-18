"""Canonical adapter metadata and runtime contract for ReconForge sensors."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from reconforge.models import Observation, Target


class Adapter(Protocol):
    """Runtime contract implemented by every concrete reconnaissance adapter."""

    name: str

    def collect(self, target: Target, run_id: str) -> tuple[Sequence[Observation], str | None]: ...


@dataclass(frozen=True, slots=True)
class AdapterSpec:
    name: str
    binary: str
    capabilities: frozenset[str]
    passive: bool = True
    requires_scope: bool = True
    safe_default: bool = True
    cost: str = "low"
    risk: str = "low"


DEFAULT_ADAPTERS = (
    AdapterSpec("subfinder", "subfinder", frozenset({"subdomain", "passive", "asset_identity"})),
    AdapterSpec("amass", "amass", frozenset({"asset_graph", "subdomain", "passive", "relationship"})),
    AdapterSpec("dnsx", "dnsx", frozenset({"dns", "resolution", "service_identity"}), passive=False, safe_default=False),
    AdapterSpec("httpx", "httpx", frozenset({"http", "fingerprint", "technology"}), passive=False, safe_default=False),
    AdapterSpec("katana", "katana", frozenset({"crawl", "javascript", "endpoint", "workflow"}), passive=False, safe_default=False, cost="medium"),
    AdapterSpec("gau", "gau", frozenset({"historical_url", "passive", "temporal"})),
    AdapterSpec("waybackurls", "waybackurls", frozenset({"historical_url", "passive", "temporal"})),
    AdapterSpec("naabu", "naabu", frozenset({"port", "service"}), passive=False, safe_default=False, risk="medium"),
    AdapterSpec("nmap", "nmap", frozenset({"service", "version", "technology"}), passive=False, safe_default=False, cost="high", risk="medium"),
    AdapterSpec("nuclei", "nuclei", frozenset({"template_signal", "detection", "misconfiguration"}), passive=False, safe_default=False, cost="medium"),
    AdapterSpec("ffuf", "ffuf", frozenset({"content_discovery", "endpoint"}), passive=False, safe_default=False, cost="medium", risk="medium"),
    AdapterSpec("arjun", "arjun", frozenset({"parameter_discovery", "endpoint"}), passive=False, safe_default=False, cost="medium", risk="medium"),
)

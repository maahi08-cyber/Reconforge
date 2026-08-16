"""Enterprise reconnaissance policy and execution configuration."""
from __future__ import annotations

from dataclasses import dataclass, field

from reconforge.scope import ScopePolicy


@dataclass(frozen=True, slots=True)
class ReconPolicy:
    """Conservative-by-default execution policy for authorized engagements."""

    scope: ScopePolicy
    active_enabled: bool = False
    max_requests_per_second: float = 5.0
    max_concurrency: int = 4
    max_tool_runtime_seconds: float = 180.0
    enabled_capabilities: frozenset[str] = field(default_factory=lambda: frozenset({
        "subdomain", "passive", "historical_url", "asset_graph",
    }))
    disabled_tools: frozenset[str] = frozenset()

    def allows_tool(self, name: str, capabilities: frozenset[str], passive: bool) -> bool:
        if name in self.disabled_tools:
            return False
        if not passive and not self.active_enabled:
            return False
        return bool(capabilities & self.enabled_capabilities)

    def allows_target(self, target: str) -> bool:
        return self.scope.allows(target)

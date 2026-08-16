import pytest

from reconforge.runtime.scope import ScopePolicy


def test_scope_denies_outside_host():
    policy = ScopePolicy(allowed_hosts=("*.example.com",))
    assert policy.allows("https://api.example.com/x")
    assert not policy.allows("https://example.org/x")


def test_scope_deny_overrides_allow():
    policy = ScopePolicy(allowed_hosts=("*.example.com",), denied_hosts=("admin.example.com",))
    assert not policy.allows("https://admin.example.com")

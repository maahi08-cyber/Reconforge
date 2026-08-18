from reconforge.scope import ScopePolicy


def test_scope_denies_outside_host():
    policy = ScopePolicy(allowed=("*.example.com",))
    assert policy.allows("https://api.example.com/x")
    assert not policy.allows("https://example.org/x")


def test_scope_deny_overrides_allow():
    policy = ScopePolicy(allowed=("*.example.com",), denied=("admin.example.com",))
    assert not policy.allows("https://admin.example.com")


def test_exact_scope_is_supported():
    policy = ScopePolicy(allowed=("example.com",))
    assert policy.allows("https://example.com")
    assert not policy.allows("https://api.example.com")

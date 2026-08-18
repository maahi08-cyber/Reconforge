from reconforge.intelligence.history import compare_urls
from reconforge.intelligence.jsintel import extract_routes
from reconforge.intelligence.ownership import infer_ownership
from reconforge.intelligence.secretintel import scan_javascript
from reconforge.intelligence.workflow import extract_workflows


def test_js_routes_deduplicate_and_preserve_method():
    routes = extract_routes('const x = fetch("/api/users");\naxios.post("/api/users");')
    assert {(route.value, route.method) for route in routes} == {('/api/users', 'GET'), ('/api/users', 'POST')}


def test_stripe_test_secret_is_detected():
    findings = scan_javascript('const key = "sk_test_abcdefghijklmnop";')
    assert any(item.kind == "stripe_secret_key" for item in findings)


def test_public_example_jwt_is_downweighted():
    # Synthetic JWT payload: {"example":true}
    token = "eyJhbGciOiJub25lIn0.eyJleGFtcGxlIjp0cnVlfQ.signaturepayload"
    findings = scan_javascript(f'const token = "{token}";')
    jwt = next(item for item in findings if item.kind == "jwt")
    assert jwt.confidence < 0.93


def test_history_normalization_prevents_false_new_delta():
    current = {"https://EXAMPLE.com/api/users/"}
    historical = {"https://example.com/api/users"}
    deltas = compare_urls(current, historical)
    assert [item.status for item in deltas] == ["persistent"]


def test_bare_uuid_does_not_get_strong_ownership_signal():
    signals = infer_ownership("https://example.com/objects/550e8400-e29b-41d4-a716-446655440000")
    assert signals
    assert max(item.confidence for item in signals) <= 0.30


def test_static_asset_hash_is_not_an_ownership_reference():
    assert infer_ownership("https://example.com/static/app.12345678.js") == []


def test_workflow_supports_plural_invites_and_content_publish():
    workflows = extract_workflows([
        ("https://example.com/api/invitations", "POST"),
        ("https://example.com/api/invitations/123/accept", "POST"),
        ("https://example.com/api/drafts/123", "PATCH"),
        ("https://example.com/api/drafts/123/publish", "POST"),
    ])
    families = {workflow.key: workflow for workflow in workflows}
    assert "invitation" in families
    assert "content" in families
    assert any(step.action == "invite" for step in families["invitation"].steps)
    assert any(step.action == "publish" for step in families["content"].steps)

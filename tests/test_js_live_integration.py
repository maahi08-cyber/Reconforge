from reconforge.models import Observation, ObservationKind
from reconforge.runtime import orchestrator
from reconforge.scope import ScopePolicy


class _Response:
    def __init__(self, body: bytes, content_type: str = "application/javascript"):
        self._body = body
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit: int):
        return self._body


def test_js_pipeline_emits_routes_and_secret_metadata(monkeypatch):
    body = b'''const x = fetch("/api/v1/projects/123");\nconst key = "sk_test_abcdefghijklmnop";'''
    calls = []

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, timeout))
        return _Response(body)

    monkeypatch.setattr(orchestrator, "urlopen", fake_urlopen)
    source = Observation(ObservationKind.HTTP, "https://example.com/app.js", "httpx", "run")
    results, warnings = orchestrator._analyze_discovered_javascript(
        [source], ScopePolicy(("example.com",), ()), "run"
    )
    assert not warnings
    assert calls == [("https://example.com/app.js", 10)]
    assert any(item.kind == ObservationKind.JAVASCRIPT for item in results)
    assert any(item.kind == ObservationKind.ENDPOINT and "/api/v1/projects/123" in item.subject for item in results)
    secret = next(item for item in results if item.kind == ObservationKind.SECRET_LEAK)
    assert secret.attributes["kind"] == "stripe_secret_key"
    assert "abcdefghijklmnop" not in secret.attributes["redacted"]


def test_js_pipeline_never_fetches_out_of_scope_script(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request.full_url)
        raise AssertionError("out-of-scope script should never be fetched")

    monkeypatch.setattr(orchestrator, "urlopen", fake_urlopen)
    source = Observation(ObservationKind.HTTP, "https://cdn.example.net/app.js", "httpx", "run")
    results, warnings = orchestrator._analyze_discovered_javascript(
        [source], ScopePolicy(("example.com",), ()), "run"
    )
    assert results == []
    assert warnings == []
    assert calls == []

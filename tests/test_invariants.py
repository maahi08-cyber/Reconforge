from reconforge.intelligence.ownership import infer_ownership, ownership_signals
from reconforge.intelligence.workflow import extract_workflows


def test_owner_fields_strengthen_but_do_not_confirm_ownership():
    url = "https://example.com/api/projects/123"
    bare = ownership_signals(url)
    contextual = ownership_signals(url, response_fields={"owner_id", "tenant_id"})
    assert contextual["confidence"] > bare["confidence"]
    assert set(contextual["matched_owner_fields"]) >= {"owner_id", "tenant_id"}
    assert all("ownership" in reason or "reference" in reason for signal in infer_ownership(url, response_fields={"owner_id"}) for reason in signal.rationale)


def test_share_without_revoke_is_a_research_hypothesis():
    workflows = extract_workflows([
        ("https://example.com/api/documents/123", "GET"),
        ("https://example.com/api/documents/123/share", "POST"),
    ])
    workflow = next(item for item in workflows if item.key == "file")
    assert ("share", "revoke_or_remove") in workflow.transition_hypotheses()


def test_publish_without_create_or_update_is_a_research_hypothesis():
    workflows = extract_workflows([
        ("https://example.com/api/posts/123/publish", "POST"),
        ("https://example.com/api/posts/123", "GET"),
    ])
    workflow = next(item for item in workflows if item.key == "content")
    assert ("publish", "create_or_update") in workflow.transition_hypotheses()

from reconforge.intelligence.classify import classify_observations, classify_url


def test_live_classifier_marks_high_value_api_object_endpoint():
    features = classify_url("https://example.com/api/v3/projects/123/members", "GET")
    assert features.is_api
    assert features.is_account_or_team
    assert features.has_object_reference
    assert not features.is_state_changing


def test_live_classifier_emits_observation_without_slotted_dataclass_crash():
    observations = classify_observations(
        "https://example.com/api/v3/projects/123",
        method="DELETE",
        source="test",
        run_id="run-1",
    )
    assert len(observations) == 1
    assert observations[0].attributes["method"] == "DELETE"
    assert observations[0].attributes["features"]["is_api"]
    assert observations[0].attributes["features"]["is_state_changing"]

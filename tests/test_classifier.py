from reconforge.intelligence.classify import classify_observations, classify_url


def test_high_value_api_object_endpoint_is_classified():
    features = classify_url("https://example.com/api/v3/projects/123/members", "GET")
    assert features.is_api
    assert features.is_account_or_team
    assert features.has_object_reference


def test_state_changing_file_endpoint_scores_as_state_changing():
    read = classify_url("https://example.com/files/123/download", "GET")
    write = classify_url("https://example.com/files/123", "DELETE")
    assert not read.is_state_changing
    assert write.is_state_changing


def test_live_observation_classifier_serializes_slotted_features():
    observations = classify_observations(
        "https://example.com/api/v3/projects/123/members",
        method="GET",
        source="test",
        run_id="run-1",
    )
    assert len(observations) == 1
    assert observations[0].attributes["method"] == "GET"
    assert observations[0].attributes["features"]["is_api"] is True

from reconforge.intelligence.classifier import classify_endpoint


def test_high_value_api_object_endpoint_is_classified():
    profile = classify_endpoint("https://example.com/api/v3/projects/123/members", "GET")
    assert "api" in profile.categories
    assert "invitation" in profile.categories or profile.identifiers
    assert profile.score > 0


def test_state_changing_file_endpoint_scores_higher():
    read = classify_endpoint("https://example.com/files/123/download", "GET")
    write = classify_endpoint("https://example.com/files/123", "DELETE")
    assert write.state_changing
    assert write.score >= read.score

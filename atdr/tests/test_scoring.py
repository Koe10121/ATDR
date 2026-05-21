from atdr.app.detection.scoring import severity_from_score


def test_severity_boundaries():
    assert severity_from_score(0) == "Low"
    assert severity_from_score(30) == "Low"
    assert severity_from_score(31) == "Medium"
    assert severity_from_score(60) == "Medium"
    assert severity_from_score(61) == "High"
    assert severity_from_score(80) == "High"
    assert severity_from_score(81) == "Critical"
    assert severity_from_score(1000) == "Critical"

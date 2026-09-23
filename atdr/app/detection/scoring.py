SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_CRITICAL = "Critical"


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def severity_from_score(score: int) -> str:
    score = clamp_score(score)
    if score <= 30:
        return SEVERITY_LOW
    if score <= 60:
        return SEVERITY_MEDIUM
    if score <= 80:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL

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


def recommended_response(severity: str, src_ip: str | None) -> str:
    if severity in {SEVERITY_CRITICAL, SEVERITY_HIGH} and src_ip:
        return f"Investigate source {src_ip}, preserve raw evidence, and use simulated block if activity is unauthorized."
    if severity == SEVERITY_MEDIUM:
        return "Review related logs, validate the business context, and monitor the source for repeated behavior."
    return "Monitor the event and mark as false positive if expected for this environment."

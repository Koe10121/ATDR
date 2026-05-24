def _clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    return max(minimum, min(maximum, value))


def isolation_score_to_risk(anomaly_score: float | None, *, is_anomaly: bool = False) -> float:
    if not is_anomaly:
        return 0.0
    if anomaly_score is None:
        return 60.0
    return _clamp(50.0 + min(50.0, abs(float(anomaly_score)) * 200.0))


def hybrid_risk_score(
    *,
    rule_score: int | float = 0,
    isolation_anomaly_score: float | None = None,
    isolation_is_anomaly: bool = False,
    supervised_malicious_probability: float | None = None,
    asset_context_weight: int | float = 0,
) -> dict:
    rule_component = _clamp(float(rule_score))
    isolation_component = isolation_score_to_risk(isolation_anomaly_score, is_anomaly=isolation_is_anomaly)
    supervised_component = _clamp(float(supervised_malicious_probability or 0) * 100.0)
    asset_component = _clamp(float(asset_context_weight))
    final_score = round(
        rule_component * 0.55
        + isolation_component * 0.20
        + supervised_component * 0.20
        + asset_component * 0.05,
        2,
    )
    return {
        "final_risk_score": final_score,
        "components": {
            "rule_score": rule_component,
            "isolation_score": isolation_component,
            "supervised_score": supervised_component,
            "asset_context_score": asset_component,
        },
        "weights": {
            "rule_score": 0.55,
            "isolation_score": 0.20,
            "supervised_score": 0.20,
            "asset_context_score": 0.05,
        },
        "decision_support_only": True,
    }

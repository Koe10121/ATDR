from typing import Any


THREAT_LABELS = {"suspicious", "malicious"}
BENIGN_LABELS = {"benign", "benign_unusual"}

COST_MATRIX: dict[tuple[str, str], float] = {
    ("malicious", "benign"): 10.0,
    ("malicious", "benign_unusual"): 8.0,
    ("malicious", "needs_context"): 3.0,
    ("malicious", "suspicious"): 2.0,
    ("suspicious", "benign"): 6.0,
    ("suspicious", "benign_unusual"): 4.0,
    ("suspicious", "needs_context"): 2.0,
    ("benign", "malicious"): 4.0,
    ("benign", "suspicious"): 2.0,
    ("benign", "needs_context"): 1.0,
    ("benign_unusual", "malicious"): 3.0,
    ("benign_unusual", "suspicious"): 1.5,
    ("benign_unusual", "needs_context"): 0.8,
    ("needs_context", "benign"): 2.0,
    ("needs_context", "benign_unusual"): 1.0,
    ("needs_context", "malicious"): 1.0,
    ("needs_context", "suspicious"): 0.8,
}


def classification_cost(actual: str, predicted: str) -> float:
    if actual == predicted:
        return 0.0
    return COST_MATRIX.get((actual, predicted), 1.0)


def cost_sensitive_report(y_true: list[str], predictions: list[str]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    total_cost = 0.0
    high_cost_errors = 0
    threat_false_negatives = 0
    benign_to_malicious = 0
    for actual, predicted in zip(y_true, predictions, strict=False):
        cost = classification_cost(str(actual), str(predicted))
        total_cost += cost
        if cost >= 6:
            high_cost_errors += 1
        if actual in THREAT_LABELS and predicted in BENIGN_LABELS:
            threat_false_negatives += 1
        if actual in BENIGN_LABELS and predicted == "malicious":
            benign_to_malicious += 1
        rows.append({"actual": actual, "predicted": predicted, "cost": cost})
    count = len(rows)
    by_pair: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = f"{row['actual']}->{row['predicted']}"
        entry = by_pair.setdefault(key, {"count": 0, "total_cost": 0.0})
        entry["count"] += 1
        entry["total_cost"] = round(float(entry["total_cost"]) + float(row["cost"]), 4)
    return {
        "total_cost": round(total_cost, 4),
        "average_cost": round(total_cost / count, 4) if count else 0.0,
        "high_cost_errors": high_cost_errors,
        "threat_false_negatives": threat_false_negatives,
        "benign_predicted_malicious": benign_to_malicious,
        "by_pair": by_pair,
        "interpretation": "Lower cost is safer for SOC triage; malicious/suspicious false negatives are penalized most heavily.",
    }

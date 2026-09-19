"""Single-source supervised development evaluation.

This is deliberately NOT the official supervised qualification decision.
That decision is governed by `v562_supervised_qualification_campaign.py` /
`v563_fresh_evidence_expansion.py` and their fixed gates, one of which
(`minimum_real_source_identities: 2`) this project currently has only one
physical source for and cannot pass. See `FIXED_PROMOTION_GATES` in
`v530_supervised_evidence_closure.py`.

What this module honestly answers instead: once some real, independently
human-reviewed rows exist (via the same protected v5.62/v5.63 workspaces),
does a simple supervised classifier show any genuine signal on THIS ONE
SOURCE, using a proper chronological development-only split? This is a
legitimate, narrower research question. It is explicitly NOT evidence of
cross-device generalization, and every output row says so structurally, not
just in prose.

Hard safety invariants, enforced in code, not just by convention:

- Never reads, counts, or reports anything from the "untouched_future_evaluation"
  role. That role exists for the *official* campaign's own eventual holdout
  evaluation and must never be touched by this or any other exploratory work.
- Never writes to the configured database. Never creates an MLModelRun,
  MLLabel, Alert, or ResponseAction row. Never installs a model artifact.
- Every result payload unconditionally sets `qualification_decision: False`,
  `single_source_only: True`, and `cross_device_generalization_established: False`
  -- these are not flags a caller can override.
- Refuses to run (fails closed) until a minimum amount of genuine review
  exists, and that minimum is far below the official campaign's fixed gates
  so it can never be mistaken for satisfying them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.detection import v563_fresh_evidence_expansion as v563
from atdr.app.detection import v565_extended_evidence_expansion as v565
from atdr.app.detection import v567_signal_concentrated_evidence_expansion as v567
from atdr.app.detection.rules import is_internal_to_external, is_outside_to_inside
from atdr.app.detection.supervised_detector import (
    _feature_importances,
    _metrics_from_predictions,
    _model_for_type,
    _optional_imports,
)


VERSION = "single-source-development-evaluation-v1"

# The official campaign's sealed role. Never read by this module.
SEALED_EVALUATION_ROLE = "untouched_future_evaluation"

# Far below FIXED_PROMOTION_GATES' minimums (1,000 rows, 100/class, 2
# sources) by design -- this only checks "is there enough to fit anything at
# all", never "is this qualified".
MINIMUM_REVIEWED_ROWS_TOTAL = 20
MINIMUM_REVIEWED_ROWS_PER_CLASS = 5

BENIGN_DECISIONS = {"benign", "benign_unusual"}
THREAT_DECISIONS = {"suspicious", "malicious"}
# "needs_context" rows are real reviews but an ambiguous label by design;
# they are reported but excluded from the binary training target.
EXCLUDED_DECISIONS = {"needs_context"}

NUMERIC_EVIDENCE_FEATURES = (
    "source_port",
    "destination_port",
    "bytes",
    "packets",
    "elapsed_time",
    "application_risk",
    "parser_warning_count",
    "required_missing_count",
    "group_size",
    "source_event_count",
    "source_deny_count",
    "source_unique_destinations",
    "source_unique_ports",
    "source_unknown_app_count",
    "source_high_risk_app_count",
    "destination_repeat_count",
)
CATEGORICAL_EVIDENCE_FEATURES = (
    "log_type",
    "subtype",
    "application",
    "action",
    "protocol",
    "source_zone",
    "destination_zone",
    "threat_severity",
    "session_end_reason",
    "schema_bucket",
)
DERIVED_FLAG_FEATURES = ("outside_to_inside_flag", "internal_to_external_flag")
FEATURE_COLUMNS = NUMERIC_EVIDENCE_FEATURES + CATEGORICAL_EVIDENCE_FEATURES + DERIVED_FLAG_FEATURES


class SingleSourceDevelopmentEvaluationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _safety_projection() -> dict[str, Any]:
    return {
        "qualification_decision": False,
        "single_source_only": True,
        "cross_device_generalization_established": False,
        "official_qualification_gates_apply_separately": True,
        "sealed_evaluation_role_accessed": False,
        "database_writes": 0,
        "model_artifact_written": False,
        "model_activated": False,
        "alerts_created": 0,
        "response_actions_created": 0,
        "raw_paths_exposed": False,
        "reviewer_identities_exposed": False,
    }


def _to_number(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _row_features(row: dict[str, Any]) -> dict[str, Any]:
    zone_like = SimpleNamespace(src_zone=row.get("source_zone"), dst_zone=row.get("destination_zone"))
    features: dict[str, Any] = {name: _to_number(row.get(name)) for name in NUMERIC_EVIDENCE_FEATURES}
    features.update({name: str(row.get(name) or "").strip().lower() or "missing" for name in CATEGORICAL_EVIDENCE_FEATURES})
    features["outside_to_inside_flag"] = int(is_outside_to_inside(zone_like))
    features["internal_to_external_flag"] = int(is_internal_to_external(zone_like))
    return features


def _binary_label(decision: str) -> str | None:
    normalized = (decision or "").strip().lower()
    if normalized in BENIGN_DECISIONS:
        return "benign_like"
    if normalized in THREAT_DECISIONS:
        return "threat_positive"
    return None


@dataclass(frozen=True)
class ReviewedRow:
    evidence_role: str
    event_time_utc: str
    decision: str
    binary_label: str | None
    features: dict[str, Any]


def _load_reviewed_development_rows(
    *,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v565_output_dir: Path = v565.V565_OUTPUT_DIR,
    v567_output_dir: Path = v567.V567_OUTPUT_DIR,
) -> tuple[list[ReviewedRow], dict[str, int]]:
    rows: list[ReviewedRow] = []
    excluded_needs_context = 0
    excluded_unreviewed = 0

    workspaces = (
        ("v562", v562_output_dir, v562, v562.V562CampaignError, lambda: v562.validate_campaign_protocol(v562_output_dir)),
        (
            "v563",
            v563_output_dir,
            v563,
            v563.V563ExpansionError,
            lambda: v563.validate_expansion_protocol(v563_output_dir, v562_output_dir=v562_output_dir),
        ),
        (
            "v565",
            v565_output_dir,
            v565,
            v565.V565ExpansionError,
            lambda: v565.validate_extended_protocol(
                v565_output_dir, v563_output_dir=v563_output_dir, v562_output_dir=v562_output_dir
            ),
        ),
        (
            "v567",
            v567_output_dir,
            v567,
            v567.V567ExpansionError,
            lambda: v567.validate_signal_protocol(
                v567_output_dir,
                v565_output_dir=v565_output_dir,
                v563_output_dir=v563_output_dir,
                v562_output_dir=v562_output_dir,
            ),
        ),
    )
    for label, output_dir, module, workspace_error, validate in workspaces:
        paths_fn = getattr(module, "_workspace_paths", None) or module._paths
        paths = paths_fn(output_dir)
        working_path = paths["working"]
        if not working_path.is_file():
            continue
        try:
            # Same integrity gate the official review services apply before
            # trusting this workspace, for defense in depth (this module is
            # read-only, but a tampered or inconsistent working file should
            # still be refused, not silently analyzed).
            validate()
            # v563 has no _read_csv of its own; it reuses v562's, and so do we.
            raw_rows, _columns = v562._read_csv(working_path)
        except (OSError, workspace_error) as exc:
            raise SingleSourceDevelopmentEvaluationError(
                "review_workspace_unreadable",
                f"The {label} protected review workspace failed integrity validation.",
            ) from exc
        for row in raw_rows:
            role = str(row.get("evidence_role") or "")
            if role == SEALED_EVALUATION_ROLE:
                # Hard invariant: never even inspect the sealed role's
                # contents beyond its role name, which is required to skip it.
                continue
            reviewed = str(row.get("human_reviewed") or "").strip().lower() in {"true", "1", "yes"}
            if not reviewed:
                excluded_unreviewed += 1
                continue
            decision = str(row.get("human_decision") or "").strip().lower()
            binary = _binary_label(decision)
            if binary is None:
                excluded_needs_context += 1
            rows.append(
                ReviewedRow(
                    evidence_role=role,
                    event_time_utc=str(row.get("event_time_utc") or ""),
                    decision=decision,
                    binary_label=binary,
                    features=_row_features(row),
                )
            )

    rows.sort(key=lambda item: item.event_time_utc)
    counts = {
        "total_reviewed_development_rows": len(rows),
        "excluded_needs_context": excluded_needs_context,
        "excluded_unreviewed": excluded_unreviewed,
        "benign_like": sum(1 for row in rows if row.binary_label == "benign_like"),
        "threat_positive": sum(1 for row in rows if row.binary_label == "threat_positive"),
    }
    return rows, counts


def _readiness(counts: dict[str, int]) -> dict[str, Any]:
    total_labeled = counts["benign_like"] + counts["threat_positive"]
    gates = {
        "minimum_reviewed_rows_total": {
            "observed": counts["total_reviewed_development_rows"],
            "threshold": MINIMUM_REVIEWED_ROWS_TOTAL,
            "status": "pass" if counts["total_reviewed_development_rows"] >= MINIMUM_REVIEWED_ROWS_TOTAL else "fail",
        },
        "minimum_benign_like_rows": {
            "observed": counts["benign_like"],
            "threshold": MINIMUM_REVIEWED_ROWS_PER_CLASS,
            "status": "pass" if counts["benign_like"] >= MINIMUM_REVIEWED_ROWS_PER_CLASS else "fail",
        },
        "minimum_threat_positive_rows": {
            "observed": counts["threat_positive"],
            "threshold": MINIMUM_REVIEWED_ROWS_PER_CLASS,
            "status": "pass" if counts["threat_positive"] >= MINIMUM_REVIEWED_ROWS_PER_CLASS else "fail",
        },
    }
    return {
        "ready": all(gate["status"] == "pass" for gate in gates.values()),
        "gates": gates,
        "labeled_rows_available_for_training": total_labeled,
        "note": (
            "These thresholds only check whether anything can be fit at all. "
            "They are far below, and do not substitute for, the official "
            "qualification campaign's fixed gates (1,000 reviewed rows, "
            "100+ per class, 2 independent physical sources)."
        ),
    }


def evaluation_status(
    *,
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v565_output_dir: Path = v565.V565_OUTPUT_DIR,
    v567_output_dir: Path = v567.V567_OUTPUT_DIR,
) -> dict[str, Any]:
    """Read-only, no-imports-required status check: how much genuinely
    reviewed development-role data exists right now, and is it enough to run
    a development-only evaluation. Safe to call at any time."""
    _rows, counts = _load_reviewed_development_rows(
        v562_output_dir=v562_output_dir,
        v563_output_dir=v563_output_dir,
        v565_output_dir=v565_output_dir,
        v567_output_dir=v567_output_dir,
    )
    return {
        "version": VERSION,
        "status": "status_only",
        "counts": counts,
        "readiness": _readiness(counts),
        **_safety_projection(),
    }


def _build_development_pipeline(imports, *, model_type: str = "logistic_regression"):
    # Matches supervised_detector._optional_imports()'s exact 11-element
    # return shape: (joblib, pd, ColumnTransformer, RandomForestClassifier,
    # SimpleImputer, accuracy_score, confusion_matrix,
    # precision_recall_fscore_support, train_test_split, Pipeline, OneHotEncoder).
    (
        _joblib,
        _pd,
        ColumnTransformer,
        RandomForestClassifier,
        SimpleImputer,
        _accuracy_score,
        _confusion_matrix,
        _precision_recall_fscore_support,
        _train_test_split,
        Pipeline,
        OneHotEncoder,
    ) = imports
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median"), list(NUMERIC_EVIDENCE_FEATURES + DERIVED_FLAG_FEATURES)),
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("onehot", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                list(CATEGORICAL_EVIDENCE_FEATURES),
            ),
        ]
    )
    return Pipeline(
        steps=[
            ("preprocess", preprocessor),
            ("model", _model_for_type(model_type, RandomForestClassifier, class_weight="balanced")),
        ]
    )


def run_single_source_development_evaluation(
    *,
    use_temp_db: bool,
    model_type: str = "logistic_regression",
    v562_output_dir: Path = v562.V562_OUTPUT_DIR,
    v563_output_dir: Path = v563.V563_OUTPUT_DIR,
    v565_output_dir: Path = v565.V565_OUTPUT_DIR,
    v567_output_dir: Path = v567.V567_OUTPUT_DIR,
) -> dict[str, Any]:
    if not use_temp_db:
        raise SingleSourceDevelopmentEvaluationError(
            "disposable_acknowledgement_required",
            "Disposable-processing acknowledgement is required (--use-temp-db).",
        )

    rows, counts = _load_reviewed_development_rows(
        v562_output_dir=v562_output_dir,
        v563_output_dir=v563_output_dir,
        v565_output_dir=v565_output_dir,
        v567_output_dir=v567_output_dir,
    )
    readiness = _readiness(counts)
    if not readiness["ready"]:
        return {
            "version": VERSION,
            "status": "insufficient_reviewed_data",
            "executed": False,
            "counts": counts,
            "readiness": readiness,
            **_safety_projection(),
        }

    labeled = [row for row in rows if row.binary_label is not None]
    # Chronological split within development roles only: fit on
    # "development_fit" rows, evaluate on the remaining development rows
    # ("calibration" and "threshold_selection"). The sealed role was never
    # loaded in the first place, so it cannot leak in here even by accident.
    train_rows = [row for row in labeled if row.evidence_role == "development_fit"]
    test_rows = [row for row in labeled if row.evidence_role != "development_fit"]
    if len(train_rows) < MINIMUM_REVIEWED_ROWS_PER_CLASS or not test_rows:
        return {
            "version": VERSION,
            "status": "insufficient_role_split",
            "executed": False,
            "counts": counts,
            "readiness": readiness,
            "reason": "Reviewed rows exist but are not yet spread across development_fit and a development test role.",
            **_safety_projection(),
        }

    imports = _optional_imports()
    if imports is None:
        return {
            "version": VERSION,
            "status": "ml_dependencies_unavailable",
            "executed": False,
            **_safety_projection(),
        }
    _joblib, pd, _ct, _rfc, _imputer, accuracy_score, confusion_matrix, precision_recall_fscore_support, _tts, _pipeline_cls, _ohe = imports

    pipeline = _build_development_pipeline(imports, model_type=model_type)
    x_train = [row.features for row in train_rows]
    y_train = [row.binary_label for row in train_rows]
    x_test = [row.features for row in test_rows]
    y_test = [row.binary_label for row in test_rows]

    pipeline.fit(pd.DataFrame(x_train), y_train)
    predictions = list(pipeline.predict(pd.DataFrame(x_test)))
    labels_order = sorted(set(y_train) | set(y_test))
    metrics = _metrics_from_predictions(
        accuracy_score=accuracy_score,
        confusion_matrix=confusion_matrix,
        precision_recall_fscore_support=precision_recall_fscore_support,
        y_true=y_test,
        predictions=predictions,
        labels_order=labels_order,
    )

    return {
        "version": VERSION,
        "status": "development_signal_measured",
        "executed": True,
        "model_type": model_type,
        "feature_columns": list(FEATURE_COLUMNS),
        "counts": counts,
        "readiness": readiness,
        "split": {
            "train_role": "development_fit",
            "train_rows": len(train_rows),
            "test_roles": sorted({row.evidence_role for row in test_rows}),
            "test_rows": len(test_rows),
        },
        "development_metrics": metrics,
        "feature_importances": _feature_importances(pipeline),
        "interpretation": (
            "This measures whether a simple classifier shows any signal on "
            "development-role rows from this one reviewed source, using a "
            "proper chronological split. It is not a qualification decision, "
            "it does not touch the sealed untouched_future_evaluation role, "
            "and it says nothing about performance on a second device or "
            "network. Sample sizes this small also make these numbers "
            "high-variance; report them with that caveat, not as a point "
            "estimate of real-world accuracy."
        ),
        **_safety_projection(),
    }

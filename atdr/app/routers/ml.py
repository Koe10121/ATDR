from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from atdr.app.benchmarks.review import (
    import_benchmark_review_csv_text,
    is_benchmark_review_csv,
)
from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.detection.supervised_detector import (
    predict_supervised_log,
    supervised_model_report,
    supervised_report_markdown,
    train_supervised_classifier,
)
from atdr.app.detection.supervised_workflow import (
    activate_supervised_model,
    list_supervised_models,
    rollback_supervised_model,
)
from atdr.app.detection.boundary_analysis import build_boundary_analysis, render_boundary_report
from atdr.app.detection.suspicious_recall_analysis import (
    build_suspicious_recall_error_report,
    render_suspicious_recall_error_report,
)
from atdr.app.detection.supervised_recovery import build_soc_triage_final_recommendation, render_soc_triage_final_recommendation
from atdr.app.schemas.ml import (
    MLDatasetProfileRead,
    MLEvaluationReportRead,
    MLLabelCreate,
    MLLabelImportResult,
    MLLabelRead,
    MLLabelUpdate,
    MLModelRunRead,
    MLReviewQueueItem,
    MLRunRequest,
    MLStatusRead,
)
from atdr.app.services.active_learning_service import (
    export_benign_needs_context_final_gap_sample_csv,
    export_active_learning_review_sample_csv,
    export_final_small_label_gap_sample_csv,
    export_stage1_threat_recall_review_sample_csv,
    export_suspicious_recall_review_sample_csv,
    export_training_window_threat_review_sample_csv,
)
from atdr.app.services.assisted_label_service import export_label_review_sample
from atdr.app.services.class_temporal_coverage_service import build_class_temporal_coverage, render_class_temporal_coverage_markdown
from atdr.app.services.label_quality_service import export_label_quality_issues_csv
from atdr.app.services.job_service import build_result_summary, complete_job, fail_job, start_job
from atdr.app.services.ml_label_service import (
    build_label_review_queue,
    create_ml_label,
    export_ml_labels_csv,
    export_review_queue_csv,
    import_ml_labels_csv,
    label_to_dict,
    list_ml_labels,
    ml_label_csv_template,
    update_ml_label,
)
from atdr.app.services.ml_service import (
    apply_anomaly_scoring,
    dataset_profile,
    evaluation_report,
    list_model_runs,
    model_status,
    run_to_dict,
    train_anomaly_model,
)

router = APIRouter(prefix="/api/ml", tags=["ml"])


@router.get("/labels", response_model=list[MLLabelRead])
def get_ml_labels(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    label: str | None = None,
    attack_type: str | None = None,
    log_id: int | None = Query(default=None, ge=1),
    reviewer: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    return [
        label_to_dict(item)
        for item in list_ml_labels(
            db,
            label=label,
            attack_type=attack_type,
            log_id=log_id,
            reviewer=reviewer,
            limit=limit,
            offset=offset,
        )
    ]


@router.post("/labels", response_model=MLLabelRead)
def post_ml_label(
    request: MLLabelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    label = create_ml_label(db, request, reviewer=current_user.username)
    if label is None:
        raise HTTPException(status_code=404, detail="Normalized log not found.")
    return label_to_dict(label)


@router.get("/labels/template")
def get_ml_label_template(
    current_user: User = Depends(require_analyst_or_admin),
) -> Response:
    return Response(
        content=ml_label_csv_template(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ml-label-template.csv"'},
    )


@router.post("/labels/import", response_model=MLLabelImportResult)
async def import_ml_labels(
    upload: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    mark_reviewed: bool = Query(default=True),
    overwrite_manual: bool = Query(default=False),
    overwrite_reviewed: bool = Query(default=False),
    correction_mode: bool = Query(default=False),
    preserve_label_source: bool = Query(default=True),
) -> dict:
    content = await upload.read()
    decoded = content.decode("utf-8-sig", errors="replace")
    if is_benchmark_review_csv(decoded):
        raise HTTPException(
            status_code=400,
            detail=(
                "This file contains benchmark_row_id and must be imported "
                "through Benchmark Review Import, not Reviewed Label Import."
            ),
        )
    return import_ml_labels_csv(
        db,
        decoded,
        reviewer=current_user.username,
        mark_reviewed=mark_reviewed,
        overwrite_manual=overwrite_manual,
        overwrite_reviewed=overwrite_reviewed,
        correction_mode=correction_mode,
        preserve_label_source=preserve_label_source,
    )


@router.post("/benchmark-reviews/import")
async def import_benchmark_reviews(
    upload: UploadFile = File(...),
    current_user: User = Depends(require_analyst_or_admin),
    benchmark_kind: str = Query(
        default="external_holdout",
        pattern="^[a-z0-9_-]{1,64}$",
    ),
) -> dict:
    content = await upload.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="Benchmark review CSV exceeds the 10 MB upload limit.",
        )
    decoded = content.decode("utf-8-sig", errors="replace")
    result = import_benchmark_review_csv_text(
        decoded,
        benchmark_kind=benchmark_kind,
        input_name=upload.filename or "benchmark-review.csv",
        reviewer=current_user.username,
    )
    if not result.get("reviews"):
        raise HTTPException(
            status_code=400,
            detail={
                "message": (
                    "No valid benchmark review rows were found. The file must "
                    "contain benchmark_row_id and completed "
                    "human_review_decision values."
                ),
                "errors": result.get("errors") or [],
            },
        )
    response = {
        key: value
        for key, value in result.items()
        if key not in {"reviews", "artifact_path"}
    }
    artifact_path = str(result.get("artifact_path") or "")
    response["artifact_name"] = artifact_path.replace("\\", "/").split("/")[-1]
    return response


@router.get("/labels/export")
def export_ml_labels(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    label: str | None = None,
    attack_type: str | None = None,
    limit: int = Query(default=5000, ge=1, le=50000),
) -> Response:
    labels = list_ml_labels(db, label=label, attack_type=attack_type, limit=limit)
    return Response(
        content=export_ml_labels_csv(labels),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ml-labels.csv"'},
    )


@router.get("/labels/review-sample/export")
def export_ml_label_review_sample(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> Response:
    return Response(
        content=export_label_review_sample(db),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="assisted-label-human-review-sample.csv"'},
    )


@router.get("/active-learning/review-sample/export")
def export_active_learning_review_sample(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=100, ge=1, le=1000),
    focus: str | None = Query(default=None),
    strategy: str = Query(default="general", pattern="^(general|boundary|threat_boundary)$"),
) -> Response:
    filename = "active-learning-review-sample.csv"
    if strategy == "threat_boundary":
        filename = "active-learning-round5-suspicious-malicious-boundary.csv"
    elif strategy == "boundary":
        filename = "active-learning-round4-boundary-cases.csv"
    elif focus:
        filename = "active-learning-focused-review-sample.csv"
    return Response(
        content=export_active_learning_review_sample_csv(db, limit=limit, focus=focus, strategy=strategy),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/training-window-threat-review/export")
def export_training_window_threat_review_sample(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=150, ge=1, le=1000),
) -> Response:
    return Response(
        content=export_training_window_threat_review_sample_csv(db, limit=limit),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="training-window-threat-review-sample.csv"'},
    )


@router.get("/boundary-report/export")
def export_boundary_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    split: str = Query(default="time", pattern="^(random|time)$"),
    test_size: float = Query(default=0.3, ge=0.1, le=0.5),
) -> Response:
    return Response(
        content=render_boundary_report(build_boundary_analysis(db, split=split, test_size=test_size)),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="suspicious-malicious-boundary-report.md"'},
    )


@router.get("/suspicious-recall-review/export")
def export_suspicious_recall_review_sample(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=150, ge=1, le=1000),
) -> Response:
    return Response(
        content=export_suspicious_recall_review_sample_csv(db, limit=limit),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="suspicious-recall-review-sample.csv"'},
    )


@router.get("/stage1-threat-recall-review/export")
def export_stage1_threat_recall_review_sample(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=300, ge=1, le=1000),
) -> Response:
    return Response(
        content=export_stage1_threat_recall_review_sample_csv(db, limit=limit),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="stage1-threat-recall-review-sample.csv"'},
    )


@router.get("/benign-final-gap-review/export")
def export_benign_final_gap_review_sample(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=100, ge=1, le=1000),
) -> Response:
    return Response(
        content=export_benign_needs_context_final_gap_sample_csv(db, limit=limit),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="benign-needs-context-final-gap-sample.csv"'},
    )


@router.get("/final-small-label-gap/export")
def export_final_small_label_gap_sample(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=64, ge=1, le=1000),
) -> Response:
    return Response(
        content=export_final_small_label_gap_sample_csv(db, limit=limit),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="final-small-label-gap-sample.csv"'},
    )


@router.get("/soc-triage-final-recommendation/export")
def export_soc_triage_final_recommendation(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    split: str = Query(default="time", pattern="^(random|time)$"),
    test_size: float = Query(default=0.3, ge=0.1, le=0.5),
) -> Response:
    report = build_soc_triage_final_recommendation(db, split=split, test_size=test_size)
    return Response(
        content=render_soc_triage_final_recommendation(report),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="soc-triage-final-recommendation.md"'},
    )


@router.get("/suspicious-recall-report/export")
def export_suspicious_recall_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    split: str = Query(default="time", pattern="^(random|time)$"),
    test_size: float = Query(default=0.3, ge=0.1, le=0.5),
) -> Response:
    report = build_suspicious_recall_error_report(db, split=split, test_size=test_size)
    return Response(
        content=render_suspicious_recall_error_report(report),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="suspicious-recall-error-report.md"'},
    )


@router.get("/labels/quality-issues/export")
def export_label_quality_issues(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=500, ge=1, le=5000),
) -> Response:
    return Response(
        content=export_label_quality_issues_csv(db, limit=limit),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="label-quality-issues.csv"'},
    )


@router.get("/class-temporal-coverage")
def get_class_temporal_coverage(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    test_size: float = Query(default=0.3, ge=0.1, le=0.5),
) -> dict:
    return build_class_temporal_coverage(db, test_size=test_size)


@router.get("/class-temporal-coverage/export")
def export_class_temporal_coverage(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    test_size: float = Query(default=0.3, ge=0.1, le=0.5),
) -> Response:
    report = build_class_temporal_coverage(db, test_size=test_size)
    return Response(
        content=render_class_temporal_coverage_markdown(report),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="class-temporal-coverage-report.md"'},
    )


@router.put("/labels/{label_id}", response_model=MLLabelRead)
def put_ml_label(
    label_id: int,
    request: MLLabelUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    label = update_ml_label(db, label_id, request, reviewer=current_user.username)
    if label is None:
        raise HTTPException(status_code=404, detail="ML label not found.")
    return label_to_dict(label)


@router.get("/review-queue", response_model=list[MLReviewQueueItem])
def get_ml_review_queue(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=100, ge=1, le=1000),
    include_labeled: bool = False,
) -> list[dict]:
    return build_label_review_queue(db, limit=limit, include_labeled=include_labeled)


@router.get("/review-queue/export")
def export_ml_review_queue(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=1000, ge=1, le=50000),
    include_labeled: bool = False,
) -> Response:
    queue = build_label_review_queue(db, limit=limit, include_labeled=include_labeled)
    return Response(
        content=export_review_queue_csv(queue),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="ml-review-queue.csv"'},
    )


@router.get("/status", response_model=MLStatusRead)
def get_ml_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return model_status(db)


@router.get("/runs", response_model=list[MLModelRunRead])
def get_ml_runs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[dict]:
    return [run_to_dict(run) for run in list_model_runs(db, limit=limit)]


@router.get("/profile", response_model=MLDatasetProfileRead)
def get_ml_dataset_profile(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    baseline_max_app_risk: int = Query(default=3, ge=1, le=5),
) -> dict:
    return dataset_profile(db, baseline_max_app_risk=baseline_max_app_risk)


@router.get("/report", response_model=MLEvaluationReportRead)
def get_ml_evaluation_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return evaluation_report(db)


@router.post("/train")
def train_ml_model(
    request: MLRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    job = start_job(
        db,
        job_type="train_ml",
        requested_by=current_user.username,
        details={
            "limit": request.limit,
            "baseline_only": request.baseline_only,
            "max_app_risk": request.max_app_risk,
        },
    )
    try:
        result = train_anomaly_model(
            db,
            limit=request.limit,
            actor=current_user.username,
            baseline_only=request.baseline_only,
            max_app_risk=request.max_app_risk,
            exclude_unknown_apps=request.exclude_unknown_apps,
            exclude_existing_anomalies=request.exclude_existing_anomalies,
        )
        complete_job(
            db,
            job,
            result_summary=build_result_summary("train_ml", result),
            related_ml_model_run_id=result.get("run_id"),
        )
        result["job_id"] = job.id
        return result
    except Exception as exc:
        fail_job(db, job, exc)
        raise


@router.post("/score")
def score_logs_with_ml(
    request: MLRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    job = start_job(
        db,
        job_type="apply_ml_scoring",
        requested_by=current_user.username,
        details={"limit": request.limit},
    )
    try:
        result = apply_anomaly_scoring(db, limit=request.limit, actor=current_user.username)
        complete_job(
            db,
            job,
            result_summary=build_result_summary("apply_ml_scoring", result),
            related_ml_model_run_id=result.get("run_id"),
        )
        result["job_id"] = job.id
        return result
    except Exception as exc:
        fail_job(db, job, exc)
        raise


@router.get("/supervised/report")
def get_supervised_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return supervised_model_report(db)


@router.get("/supervised/models")
def get_supervised_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    limit: int = Query(default=25, ge=1, le=100),
) -> dict:
    return list_supervised_models(db, limit=limit)


@router.get("/supervised/report/export")
def export_supervised_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> Response:
    return Response(
        content=supervised_report_markdown(db),
        media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="atdr-supervised-model-report.md"'},
    )


@router.post("/supervised/train")
def train_supervised_model(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
    test_size: float = Query(default=0.3, ge=0.1, le=0.5),
    min_samples: int = Query(default=6, ge=2, le=100000),
    split: str = Query(default="random", pattern="^(random|time)$"),
    model: str = Query(default="random_forest", pattern="^(random_forest|hist_gradient_boosting|logistic_regression|extra_trees)$"),
    threshold_profile: str = Query(
        default="balanced",
        pattern="^(conservative|balanced|aggressive|suspicious_recall|malicious_recall|threat_positive)$",
    ),
) -> dict:
    job = start_job(
        db,
        job_type="train_ml",
        requested_by=current_user.username,
        details={
            "operation": "train_supervised",
            "test_size": test_size,
            "min_samples": min_samples,
            "split": split,
            "model_type": model,
            "threshold_profile": threshold_profile,
        },
    )
    try:
        result = train_supervised_classifier(
            db,
            actor=current_user.username,
            test_size=test_size,
            min_samples=min_samples,
            split=split,
            model_type=model,
            threshold_profile=threshold_profile,
        )
        complete_job(db, job, result_summary=build_result_summary("train_ml", result))
        result["job_id"] = job.id
        return result
    except Exception as exc:
        fail_job(db, job, exc)
        raise


@router.post("/supervised/models/{model_id}/activate")
def activate_supervised_model_api(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return activate_supervised_model(db, model_id=model_id, actor=current_user.username)


@router.post("/supervised/models/rollback")
def rollback_supervised_model_api(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return rollback_supervised_model(db, actor=current_user.username)


@router.get("/supervised/predict/{log_id}")
def predict_supervised(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    rule_score: int = Query(default=0, ge=0, le=100),
    asset_context_weight: int = Query(default=0, ge=0, le=100),
) -> dict:
    return predict_supervised_log(db, log_id, rule_score=rule_score, asset_context_weight=asset_context_weight)

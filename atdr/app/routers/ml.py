from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from atdr.app.core.security import require_admin, require_analyst_or_admin
from atdr.app.db.database import get_db
from atdr.app.db.models import User
from atdr.app.detection.supervised_detector import (
    predict_supervised_log,
    supervised_model_report,
    supervised_report_markdown,
    train_supervised_classifier,
)
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
from atdr.app.services.assisted_label_service import export_label_review_sample
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
    preserve_label_source: bool = Query(default=True),
) -> dict:
    content = await upload.read()
    decoded = content.decode("utf-8-sig", errors="replace")
    return import_ml_labels_csv(
        db,
        decoded,
        reviewer=current_user.username,
        mark_reviewed=mark_reviewed,
        overwrite_manual=overwrite_manual,
        preserve_label_source=preserve_label_source,
    )


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
    return train_anomaly_model(
        db,
        limit=request.limit,
        actor=current_user.username,
        baseline_only=request.baseline_only,
        max_app_risk=request.max_app_risk,
        exclude_unknown_apps=request.exclude_unknown_apps,
        exclude_existing_anomalies=request.exclude_existing_anomalies,
    )


@router.post("/score")
def score_logs_with_ml(
    request: MLRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> dict:
    return apply_anomaly_scoring(db, limit=request.limit, actor=current_user.username)


@router.get("/supervised/report")
def get_supervised_report(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
) -> dict:
    return supervised_model_report(db)


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
) -> dict:
    return train_supervised_classifier(db, actor=current_user.username, test_size=test_size, min_samples=min_samples)


@router.get("/supervised/predict/{log_id}")
def predict_supervised(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin),
    rule_score: int = Query(default=0, ge=0, le=100),
    asset_context_weight: int = Query(default=0, ge=0, le=100),
) -> dict:
    return predict_supervised_log(db, log_id, rule_score=rule_score, asset_context_weight=asset_context_weight)

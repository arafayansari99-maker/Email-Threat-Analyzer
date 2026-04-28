"""
Model feedback router for continuous learning.
Users can flag false positives/negatives to improve the ML model.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from database import get_db, ModelFeedback, ScanRecord, User
from routers.auth import get_current_user

router = APIRouter(prefix="/feedback", tags=["model-feedback"])


class FeedbackCreate(BaseModel):
    scan_id: str
    actual_verdict: str  # "phishing", "suspicious", "legitimate"
    reason: Optional[str] = None


class FeedbackResponse(BaseModel):
    id: int
    scan_id: str
    actual_verdict: str
    reason: Optional[str]
    original_prob: Optional[float]
    reviewed: bool
    created_at: str

    class Config:
        from_attributes = True


@router.post("", response_model=FeedbackResponse, status_code=201)
def submit_feedback(
    feedback: FeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Submit user feedback on a scan verdict."""
    # Verify scan exists
    scan = db.query(ScanRecord).filter(
        ScanRecord.scan_id == feedback.scan_id,
        ScanRecord.user_id == current_user.id
    ).first()

    if not scan:
        raise HTTPException(404, "Scan not found")

    # Validate verdict
    if feedback.actual_verdict not in ["phishing", "suspicious", "legitimate"]:
        raise HTTPException(400, "Invalid verdict")

    # Create feedback record
    fb = ModelFeedback(
        scan_id=feedback.scan_id,
        user_id=current_user.id,
        actual_verdict=feedback.actual_verdict,
        reason=feedback.reason,
        original_prob=scan.risk_score / 100.0 if scan.risk_score else 0,
    )
    db.add(fb)
    db.commit()
    db.refresh(fb)

    return FeedbackResponse(
        id=fb.id,
        scan_id=fb.scan_id,
        actual_verdict=fb.actual_verdict,
        reason=fb.reason,
        original_prob=fb.original_prob,
        reviewed=fb.reviewed,
        created_at=fb.created_at.isoformat(),
    )


@router.get("/my-feedback")
def get_my_feedback(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current user's feedback submissions."""
    feedbacks = db.query(ModelFeedback).filter(
        ModelFeedback.user_id == current_user.id
    ).order_by(ModelFeedback.created_at.desc()).all()

    return [
        FeedbackResponse(
            id=f.id,
            scan_id=f.scan_id,
            actual_verdict=f.actual_verdict,
            reason=f.reason,
            original_prob=f.original_prob,
            reviewed=f.reviewed,
            created_at=f.created_at.isoformat(),
        )
        for f in feedbacks
    ]


# Admin-only endpoints
@router.get("/pending-review")
def get_pending_feedback(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get feedback pending admin review (admin only)."""
    if current_user.role not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin only")

    feedbacks = db.query(ModelFeedback).filter(
        ModelFeedback.reviewed == False
    ).order_by(ModelFeedback.created_at.desc()).all()

    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "actual_verdict": f.actual_verdict,
            "reason": f.reason,
            "original_prob": f.original_prob,
            "submitted_by": f.user_id,
            "created_at": f.created_at.isoformat(),
        }
        for f in feedbacks
    ]


@router.post("/{feedback_id}/review")
def review_feedback(
    feedback_id: int,
    approve: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark feedback as reviewed (admin only)."""
    if current_user.role not in ("admin", "superadmin"):
        raise HTTPException(403, "Admin only")

    fb = db.query(ModelFeedback).filter(ModelFeedback.id == feedback_id).first()
    if not fb:
        raise HTTPException(404, "Feedback not found")

    fb.reviewed = True
    fb.reviewed_by = current_user.id
    db.commit()

    return {"status": "approved" if approve else "rejected", "feedback_id": feedback_id}
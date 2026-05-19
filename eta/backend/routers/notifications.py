"""
Per-user in-app notification endpoints.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db, Notification, User
from routers.auth import get_current_user

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("")
def get_notifications(
    limit: int = Query(30, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (
        db.query(Notification)
        .filter(Notification.user_id == current_user.id)
        .order_by(Notification.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": n.id, "type": n.type, "title": n.title,
            "body": n.body, "link": n.link,
            "is_read": n.is_read, "created_at": n.created_at.isoformat(),
        }
        for n in rows
    ]


@router.get("/unread-count")
def get_unread_count(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    count = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False,
    ).count()
    return {"count": count}


@router.post("/mark-read")
def mark_all_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False,
    ).update({"is_read": True})
    db.commit()
    return {"ok": True}


@router.patch("/{notification_id}/read")
def mark_one_read(
    notification_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    n = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id,
    ).first()
    if n:
        n.is_read = True
        db.commit()
    return {"ok": True}

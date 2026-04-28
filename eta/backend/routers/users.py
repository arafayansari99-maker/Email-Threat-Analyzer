"""
User management router - Admin only operations.
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

import sys
from pathlib import Path as PathLib
sys.path.insert(0, str(PathLib(__file__).resolve().parent.parent))

from database import get_db, User, AuditLog
from routers.auth import get_current_user

router = APIRouter(prefix="/users", tags=["users"])


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    is_approved: Optional[bool] = None


class UserDetail(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    is_approved: bool
    created_at: datetime

    class Config:
        from_attributes = True


def check_admin(current_user: User = Depends(get_current_user)) -> User:
    """Ensure user is an admin."""
    if current_user.role not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


@router.get("/", response_model=list[UserDetail])
def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    role: Optional[str] = Query(None),
    approved: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    admin: User = Depends(check_admin),
):
    """List all users (admin only)."""
    q = db.query(User).order_by(User.created_at.desc())

    if role:
        q = q.filter(User.role == role)
    if approved is not None:
        q = q.filter(User.is_approved == approved)

    total = q.count()
    users = q.offset((page - 1) * limit).limit(limit).all()

    return users


@router.get("/pending", response_model=list[UserDetail])
def list_pending_users(
    db: Session = Depends(get_db),
    admin: User = Depends(check_admin),
):
    """List pending users waiting for approval."""
    users = db.query(User).filter(User.is_approved == False).order_by(User.created_at.desc()).all()
    return users


@router.get("/{user_id}", response_model=UserDetail)
def get_user(
    user_id: int = Path(...),
    db: Session = Depends(get_db),
    admin: User = Depends(check_admin),
):
    """Get user by ID (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserDetail)
def update_user(
    user_id: int = Path(...),
    updates: UserUpdate = ...,
    db: Session = Depends(get_db),
    admin: User = Depends(check_admin),
):
    """Update user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent demoting superadmin
    if user.role == "superadmin" and admin.role != "superadmin":
        raise HTTPException(status_code=403, detail="Cannot modify superadmin")

    if updates.username is not None:
        user.username = updates.username
    if updates.email is not None:
        user.email = updates.email
    if updates.role is not None:
        user.role = updates.role
    if updates.is_active is not None:
        user.is_active = updates.is_active
    if updates.is_approved is not None:
        user.is_approved = updates.is_approved
        if updates.is_approved:
            user.approved_by = admin.id
            user.approved_at = datetime.utcnow()

    db.commit()
    db.refresh(user)
    return user


@router.post("/{user_id}/approve", response_model=UserDetail)
def approve_user(
    user_id: int = Path(...),
    db: Session = Depends(get_db),
    admin: User = Depends(check_admin),
):
    """Approve a pending user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_approved:
        raise HTTPException(status_code=400, detail="User already approved")

    user.is_approved = True
    user.approved_by = admin.id
    user.approved_at = datetime.utcnow()

    db.commit()
    db.refresh(user)
    # Audit log
    log = AuditLog(user_id=admin.id, action="user_approve", target_type="user",
                   target_id=str(user.id), details={"username": user.username})
    db.add(log); db.commit()
    return user


@router.delete("/{user_id}")
def delete_user(
    user_id: int = Path(...),
    db: Session = Depends(get_db),
    admin: User = Depends(check_admin),
):
    """Delete a user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent self-deletion and superadmin deletion
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    if user.role == "superadmin":
        raise HTTPException(status_code=403, detail="Cannot delete superadmin")

    db.delete(user)
    db.commit()
    return {"ok": True, "message": f"User {user_id} deleted"}
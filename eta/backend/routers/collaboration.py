from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database import get_db, User, Workspace, WorkspaceMember, ReportComment, ActivityLog, ScanRecord
from routers.auth import get_current_user

router = APIRouter(prefix="/collaboration", tags=["collaboration"])


# ─── Pydantic Models ────────────────────────────────────────────────────────

class WorkspaceCreate(BaseModel):
    name: str
    description: Optional[str] = None

class WorkspaceResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class MemberAdd(BaseModel):
    user_id: int
    role: str = "member"

class CommentCreate(BaseModel):
    scan_id: str
    content: str
    is_flag: bool = False
    parent_id: Optional[int] = None

class CommentResponse(BaseModel):
    id: int
    scan_id: str
    user_id: int
    content: str
    is_flag: bool
    parent_id: Optional[int]
    created_at: datetime
    username: Optional[str] = None

    class Config:
        from_attributes = True

class ActivityResponse(BaseModel):
    id: int
    user_id: int
    workspace_id: Optional[int]
    action: str
    target_type: Optional[str]
    target_id: Optional[int]
    details: Optional[dict]
    created_at: datetime
    username: Optional[str] = None

    class Config:
        from_attributes = True


# ─── Helper: Log Activity ───────────────────────────────────────────────────

def log_activity(db: Session, user_id: int, action: str, target_type: Optional[str] = None,
                  target_id: Optional[int] = None, workspace_id: Optional[int] = None, details: Optional[dict] = None):
    log = ActivityLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        workspace_id=workspace_id,
        details=details
    )
    db.add(log)
    db.commit()


# ─── Workspace Routes ─────────────────────────────────────────────────────────

@router.post("/workspaces", response_model=WorkspaceResponse)
def create_workspace(workspace: WorkspaceCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ws = Workspace(name=workspace.name, description=workspace.description, owner_id=current_user.id)
    db.add(ws)
    db.commit()
    db.refresh(ws)

    # Add owner as admin member
    member = WorkspaceMember(workspace_id=ws.id, user_id=current_user.id, role="owner")
    db.add(member)
    db.commit()

    log_activity(db, current_user.id, "workspace_created", "workspace", ws.id, ws.id, {"name": ws.name})
    return ws


@router.get("/workspaces", response_model=List[WorkspaceResponse])
def list_workspaces(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Get workspaces where user is a member
    member_ws = db.query(WorkspaceMember).filter(WorkspaceMember.user_id == current_user.id).all()
    ws_ids = [m.workspace_id for m in member_ws]
    workspaces = db.query(Workspace).filter(Workspace.id.in_(ws_ids)).all() if ws_ids else []
    return workspaces


@router.get("/workspaces/{ws_id}/members")
def list_workspace_members(ws_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check membership
    membership = db.query(WorkspaceMember).filter(
        WorkspaceMember.workspace_id == ws_id,
        WorkspaceMember.user_id == current_user.id
    ).first()
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member")

    # Get members properly
    ws_members = db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == ws_id).all()
    result = []
    for m in ws_members:
        user = db.query(User).filter(User.id == m.user_id).first()
        if user:
            result.append({"user_id": user.id, "username": user.username, "email": user.email, "role": m.role})
    return result


@router.post("/workspaces/{ws_id}/members")
def add_workspace_member(ws_id: int, member: MemberAdd, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check owner/admin
    membership = db.query(WorkspaceMember).filter(
        WorkspaceMember.workspace_id == ws_id,
        WorkspaceMember.user_id == current_user.id,
        WorkspaceMember.role.in_(["owner", "admin"])
    ).first()
    if not membership:
        raise HTTPException(status_code=403, detail="Only owners/admins can add members")

    # Check user exists
    target_user = db.query(User).filter(User.id == member.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check not already member
    existing = db.query(WorkspaceMember).filter(
        WorkspaceMember.workspace_id == ws_id,
        WorkspaceMember.user_id == member.user_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already a member")

    new_member = WorkspaceMember(workspace_id=ws_id, user_id=member.user_id, role=member.role)
    db.add(new_member)
    db.commit()

    log_activity(db, current_user.id, "member_added", "user", member.user_id, ws_id, {"added_username": target_user.username})
    return {"status": "success", "message": f"Added {target_user.username}"}


@router.get("/workspaces/{ws_id}/scans")
def get_workspace_scans(ws_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check membership
    membership = db.query(WorkspaceMember).filter(
        WorkspaceMember.workspace_id == ws_id,
        WorkspaceMember.user_id == current_user.id
    ).first()
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member")

    # Get all scans from workspace members
    member_ids = [m.user_id for m in db.query(WorkspaceMember).filter(WorkspaceMember.workspace_id == ws_id).all()]
    scans = db.query(ScanRecord).filter(ScanRecord.user_id.in_(member_ids)).order_by(ScanRecord.created_at.desc()).limit(50).all()

    return [{"scan_id": s.scan_id, "filename": s.filename, "verdict": s.verdict, "risk_score": s.risk_score, "created_at": s.created_at, "user_id": s.user_id} for s in scans]


# ─── Report Comments Routes ────────────────────────────────────────────────────

@router.get("/comments/{scan_id}", response_model=List[CommentResponse])
def get_scan_comments(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    comments = db.query(ReportComment, User).join(User, ReportComment.user_id == User.id).filter(
        ReportComment.scan_id == scan_id
    ).order_by(ReportComment.created_at.desc()).all()

    return [{"id": c.id, "scan_id": c.scan_id, "user_id": c.user_id,
             "content": c.content, "is_flag": c.is_flag,
             "parent_id": c.parent_id, "created_at": c.created_at,
             "username": u.username} for c, u in comments]


@router.post("/comments", response_model=CommentResponse)
def create_comment(comment: CommentCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Check scan exists
    scan = db.query(ScanRecord).filter(ScanRecord.scan_id == comment.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_comment = ReportComment(
        scan_id=comment.scan_id,
        user_id=current_user.id,
        content=comment.content,
        is_flag=comment.is_flag,
        parent_id=comment.parent_id
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)

    log_activity(db, current_user.id, "comment_added", "scan", scan.id, None, {"scan_id": comment.scan_id, "is_flag": comment.is_flag})
    return {**new_comment.__dict__, "username": current_user.username}


@router.delete("/comments/{comment_id}")
def delete_comment(comment_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    comment = db.query(ReportComment).filter(ReportComment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    # Only author or scan owner can delete
    if comment.user_id != current_user.id:
        scan = db.query(ScanRecord).filter(ScanRecord.scan_id == comment.scan_id).first()
        if not scan or scan.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Cannot delete this comment")

    db.delete(comment)
    db.commit()
    return {"status": "success", "message": "Comment deleted"}


# ─── Activity Feed Routes ───────────────────────────────────────────────────────

@router.get("/activity", response_model=List[ActivityResponse])
def get_activity_feed(workspace_id: Optional[int] = None, limit: int = 50, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Get user's workspace IDs
    member_ws = db.query(WorkspaceMember).filter(WorkspaceMember.user_id == current_user.id).all()
    member_ws_ids = [m.workspace_id for m in member_ws]

    if workspace_id:
        if workspace_id not in member_ws_ids:
            raise HTTPException(status_code=403, detail="Not a member")
        logs = db.query(ActivityLog).filter(ActivityLog.workspace_id == workspace_id).order_by(ActivityLog.created_at.desc()).limit(limit).all()
    else:
        query = db.query(ActivityLog).filter((ActivityLog.workspace_id.in_(member_ws_ids)) | (ActivityLog.workspace_id == None))
        logs = query.order_by(ActivityLog.created_at.desc()).limit(limit).all()

    # Get usernames
    result = []
    for log in logs:
        user = db.query(User).filter(User.id == log.user_id).first()
        result.append({
            "id": log.id, "user_id": log.user_id, "workspace_id": log.workspace_id,
            "action": log.action, "target_type": log.target_type,
            "target_id": log.target_id, "details": log.details,
            "created_at": log.created_at, "username": user.username if user else "Unknown"
        })
    return result


@router.get("/activity/user/{user_id}", response_model=List[ActivityResponse])
def get_user_activity(user_id: int, limit: int = 20, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    logs = db.query(ActivityLog, User).join(User, ActivityLog.user_id == User.id).filter(
        ActivityLog.user_id == user_id
    ).order_by(ActivityLog.created_at.desc()).limit(limit).all()

    return [{"id": l.id, "user_id": l.user_id, "workspace_id": l.workspace_id,
             "action": l.action, "target_type": l.target_type,
             "target_id": l.target_id, "details": l.details,
             "created_at": l.created_at, "username": u.username} for l, u in logs]
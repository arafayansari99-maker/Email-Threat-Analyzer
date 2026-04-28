from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from datetime import datetime, timedelta
import json, os, psutil, time

from database import get_db, engine as _db_engine, User, ScanRecord, AuditLog, APIUsage, AppConfig, ActivityLog
from routers.auth import get_current_user

START_TIME = time.time()
APP_VERSION = "2.0.0"

router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(user: User = Depends(get_current_user)):
    if user.role not in ('admin', 'superadmin'):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def log_audit(db, user_id, action, target_type, target_id=None, details=None, ip=None):
    """Helper to create audit log entries."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=json.dumps(details) if details else None,
        ip_address=ip,
    )
    db.add(entry)
    db.commit()


# ── Audit Log ───────────────────────────────────────────────────────────────
@router.get("/audit-logs")
def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    action: str = None,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    query = db.query(AuditLog).order_by(desc(AuditLog.created_at))
    if action:
        query = query.filter(AuditLog.action == action)
    total = query.count()
    logs = query.offset((page-1)*limit).limit(limit).all()
    return {
        "logs": [{
            "id": l.id,
            "user_id": l.user_id,
            "action": l.action,
            "target_type": l.target_type,
            "target_id": l.target_id,
            "details": json.loads(l.details) if l.details else None,
            "ip_address": l.ip_address,
            "created_at": l.created_at.isoformat(),
        } for l in logs],
        "total": total,
        "page": page,
        "limit": limit,
    }


# ── Usage Statistics (Admin) ─────────────────────────────────────────────────
@router.get("/admin-stats")
def get_admin_stats(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    # Total scans
    total_scans = db.query(ScanRecord).count()

    # Scans this month
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    scans_this_month = db.query(ScanRecord).filter(ScanRecord.created_at >= month_start).count()

    # Verdicts breakdown
    verdicts = db.query(
        ScanRecord.verdict,
        func.count(ScanRecord.id)
    ).group_by(ScanRecord.verdict).all()
    verdict_counts = {v: c for v, c in verdicts}

    # Top threats (most common indicator types)
    from database import ThreatReport
    top_threats = []
    reports = db.query(ThreatReport).limit(100).all()
    type_counts = {}
    for r in reports:
        try:
            data = json.loads(r.report_json) if isinstance(r.report_json, str) else r.report_json
            for ioc in data.get("iocs", [])[:5]:
                t = ioc.get("type", "unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
        except: pass
    top_threats = sorted(type_counts.items(), key=lambda x: -x[1])[:10]

    # Active users (last 30 days)
    days_30 = datetime.utcnow() - timedelta(days=30)
    active_users = db.query(func.count(func.distinct(ScanRecord.user_id))).filter(
        ScanRecord.created_at >= days_30
    ).scalar() or 0

    # Total users
    total_users = db.query(User).count()

    # Average risk score
    avg_score = db.query(func.avg(ScanRecord.risk_score)).scalar() or 0

    # Daily trend (last 14 days)
    trend = []
    for i in range(13, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        day_scans = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end
        ).count()
        day_mal = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end,
            ScanRecord.verdict == "malicious"
        ).count()
        trend.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "total": day_scans,
            "malicious": day_mal,
        })

    return {
        "total_scans": total_scans,
        "scans_this_month": scans_this_month,
        "verdict_counts": verdict_counts,
        "top_threats": [{"type": t, "count": c} for t, c in top_threats],
        "active_users_30d": active_users,
        "total_users": total_users,
        "avg_risk_score": round(float(avg_score), 1),
        "trend": trend,
    }


# ── API Rate Monitoring ───────────────────────────────────────────────────────
@router.get("/api-usage")
def get_api_usage(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get API usage per user per service."""
    # Aggregate usage per user-service
    usage_rows = db.query(
        APIUsage.user_id,
        APIUsage.api_key_id,
        func.sum(APIUsage.requests).label("total_requests"),
    ).group_by(APIUsage.user_id, APIUsage.api_key_id).all()

    # Get user info
    user_ids = list(set(r[0] for r in usage_rows))
    users = {u.id: u.username for u in db.query(User).filter(User.id.in_(user_ids)).all()}

    result = []
    for uid, svc, reqs in usage_rows:
        result.append({
            "user_id": uid,
            "username": users.get(uid, "Unknown"),
            "service": svc,
            "requests": reqs,
        })

    # Also return API key limits config
    from routers.settings import get_api_key_limits
    limits = get_api_key_limits()

    return {"usage": result, "limits": limits}


# ── Environment Config UI ──────────────────────────────────────────────────
@router.get("/admin-config")
def get_admin_config(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get all app configuration."""
    configs = db.query(AppConfig).all()
    return {"config": {c.key: c.value for c in configs}}


@router.put("/admin-config/{key}")
def update_admin_config(
    key: str,
    value: str = None,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Update an app configuration key."""
    cfg = db.query(AppConfig).filter(AppConfig.key == key).first()
    if not cfg:
        cfg = AppConfig(key=key, value=value, updated_by=admin.id)
        db.add(cfg)
    else:
        cfg.value = value
        cfg.updated_by = admin.id
    db.commit()
    log_audit(db, admin.id, "config_update", "config", key, {"value": value})
    return {"message": "Config updated"}


# ── Health Check ────────────────────────────────────────────────────────────
@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Health check with DB status, disk usage, uptime."""
    from sqlalchemy import text
    # DB check - use engine directly to avoid session issues
    db_ok = False
    db_message = "OK"
    try:
        with _db_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_message = str(e)

    # Disk usage
    try:
        disk = psutil.disk_usage('/')
        disk_usage = {
            "total_gb": round(disk.total / (1024**3), 1),
            "used_gb": round(disk.used / (1024**3), 1),
            "free_gb": round(disk.free / (1024**3), 1),
            "percent": disk.percent,
        }
    except:
        disk_usage = {"error": "Unable to get disk info"}

    # Uptime
    import time
    uptime_seconds = time.time() - START_TIME
    uptime_hours = round(uptime_seconds / 3600, 1)

    return {
        "status": "healthy" if db_ok else "degraded",
        "database": {"ok": db_ok, "message": db_message},
        "disk": disk_usage,
        "uptime_hours": uptime_hours,
        "version": APP_VERSION,
    }


# ── Dashboard: Recent Activity Feed ─────────────────────────────────────────
@router.get("/dashboard/recent-activity")
def get_dashboard_activity(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get recent activity for admin dashboard."""
    activities = db.query(ActivityLog).order_by(desc(ActivityLog.created_at)).limit(limit).all()
    result = []
    for a in activities:
        user = db.query(User).filter(User.id == a.user_id).first()
        result.append({
            "id": a.id,
            "user_id": a.user_id,
            "username": user.username if user else "Unknown",
            "action": a.action,
            "target_type": a.target_type,
            "target_id": a.target_id,
            "details": a.details,
            "created_at": a.created_at.isoformat(),
        })
    return result


# ── Dashboard: Recent Users ─────────────────────────────────────────────────
@router.get("/dashboard/recent-users")
def get_dashboard_users(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get recently registered users."""
    users = db.query(User).order_by(desc(User.created_at)).limit(limit).all()
    return [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "is_approved": u.is_approved,
        "created_at": u.created_at.isoformat(),
    } for u in users]


# ── Dashboard: Pending Approvals ────────────────────────────────────────────────────
@router.get("/dashboard/pending-users")
def get_pending_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get users awaiting approval."""
    users = db.query(User).filter(User.is_approved == False).order_by(desc(User.created_at)).all()
    return [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "created_at": u.created_at.isoformat(),
    } for u in users]


# ── Dashboard: Scan Trends ────────────────────────────────────────────────────
@router.get("/dashboard/trends")
def get_dashboard_trends(
    days: int = Query(14, ge=7, le=30),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get scan trends for dashboard charts."""
    trend = []
    for i in range(days - 1, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)

        day_scans = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end
        ).count()

        day_mal = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end,
            ScanRecord.verdict == "malicious"
        ).count()

        day_safe = db.query(ScanRecord).filter(
            ScanRecord.created_at >= day_start,
            ScanRecord.created_at < day_end,
            ScanRecord.verdict == "safe"
        ).count()

        trend.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "total": day_scans,
            "malicious": day_mal,
            "safe": day_safe,
            "suspicious": day_scans - day_mal - day_safe,
        })

    return trend


# ── Admin User Management (scoped under /admin prefix) ────────────────────
# Note: The /users/... endpoints are also available under /api/users/... from users.py
# These admin-scoped versions are used by the frontend admin dashboard

@router.post("/users/{user_id}/approve")
def approve_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Approve a pending user."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_approved = True
    user.approved_by = admin.id
    user.approved_at = datetime.utcnow()
    db.commit()

    log_audit(db, admin.id, "user_approve", "user", user_id, {"username": user.username})
    return {"message": f"User {user.username} approved"}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete a user account."""
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    username = user.username
    db.delete(user)
    db.commit()

    log_audit(db, admin.id, "user_delete", "user", user_id, {"username": username})
    return {"message": f"User {username} deleted"}


@router.patch("/users/{user_id}/role")
def update_user_role(
    user_id: int,
    role: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Update user role."""
    if role not in ("user", "analyst", "admin", "superadmin"):
        raise HTTPException(status_code=400, detail="Invalid role")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role
    user.role = role
    db.commit()

    log_audit(db, admin.id, "role_change", "user", user_id, {"old_role": old_role, "new_role": role})
    return {"message": f"User role updated to {role}"}


# ── Admin: Bulk Delete Scans ──────────────────────────────────────────────
@router.delete("/scans/bulk")
def bulk_delete_scans(
    older_than_days: int = Query(30, ge=1, le=365),
    verdict: str = Query(None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Bulk delete scans older than specified days."""
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(days=older_than_days)

    query = db.query(ScanRecord).filter(ScanRecord.created_at < cutoff)
    if verdict:
        query = query.filter(ScanRecord.verdict == verdict)

    count = query.count()
    query.delete()
    db.commit()

    log_audit(db, admin.id, "scan_delete", "config", None, {"count": count, "older_than_days": older_than_days, "verdict": verdict})
    return {"message": f"Deleted {count} scans"}


# ── Admin: Export Data ──────────────────────────────────────────────────────
@router.get("/export/{data_type}")
def export_admin_data(
    data_type: str,
    format: str = Query("json"),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Export admin data (users, scans, audit logs)."""
    import csv
    import io

    if data_type == "users":
        users = db.query(User).all()
        data = [{"id": u.id, "username": u.username, "email": u.email, "role": u.role,
                "is_active": u.is_active, "is_approved": u.is_approved, "created_at": u.created_at.isoformat()} for u in users]
    elif data_type == "scans":
        scans = db.query(ScanRecord).order_by(desc(ScanRecord.created_at)).limit(1000).all()
        data = [{"id": s.id, "scan_id": s.scan_id, "user_id": s.user_id, "verdict": s.verdict,
                "risk_score": s.risk_score, "created_at": s.created_at.isoformat()} for s in scans]
    elif data_type == "audit_logs":
        logs = db.query(AuditLog).order_by(desc(AuditLog.created_at)).limit(1000).all()
        data = [{"id": l.id, "user_id": l.user_id, "action": l.action, "target_type": l.target_type,
                "target_id": l.target_id, "created_at": l.created_at.isoformat()} for l in logs]
    else:
        raise HTTPException(400, "Invalid data type")

    return {"data": data, "count": len(data)}
"""
Privacy & Data Management Router
Handles user data deletion, export, and retention policies
GDPR/privacy-compliant data handling
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from database import get_db, User, ScanRecord, ThreatReport, PrivacySettings
from routers.auth import get_current_user

router = APIRouter(prefix="/privacy", tags=["privacy"])


@router.post("/user/privacy-settings")
def update_privacy_settings(
    data_retention_days: int = Query(30, ge=1, le=365),
    allow_analytics: bool = Query(False),
    auto_delete: bool = Query(True),
    tier2_consent: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update user privacy settings"""
    ps = db.query(PrivacySettings).filter(PrivacySettings.user_id == current_user.id).first()

    if not ps:
        ps = PrivacySettings(user_id=current_user.id)
        db.add(ps)

    ps.data_retention_days = data_retention_days
    ps.allow_analytics = allow_analytics
    ps.auto_delete = auto_delete
    ps.tier2_consent = tier2_consent
    ps.updated_at = datetime.utcnow()
    db.commit()

    return {
        "ok": True,
        "message": "Privacy settings updated",
        "settings": {
            "data_retention_days": ps.data_retention_days,
            "allow_analytics": ps.allow_analytics,
            "auto_delete": ps.auto_delete,
            "tier2_consent": ps.tier2_consent,
        }
    }


@router.get("/user/privacy-settings")
def get_privacy_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get user privacy settings"""
    ps = db.query(PrivacySettings).filter(PrivacySettings.user_id == current_user.id).first()
    
    if not ps:
        ps = PrivacySettings(user_id=current_user.id)
        db.add(ps)
        db.commit()
    
    return {
        "data_retention_days": ps.data_retention_days,
        "allow_analytics": ps.allow_analytics,
        "auto_delete": ps.auto_delete,
        "tier2_consent": ps.tier2_consent,
        "last_cleanup": ps.last_cleanup.isoformat() if ps.last_cleanup else None,
    }


@router.get("/user/export-data")
def export_user_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Export all user data in JSON format (GDPR right to data portability)
    Includes: account info, all scans, analysis reports
    """
    scans = db.query(ScanRecord).filter(ScanRecord.user_id == current_user.id).all()
    reports = {s.scan_id: db.query(ThreatReport).filter(ThreatReport.scan_id == s.scan_id).first() 
               for s in scans}
    
    data = {
        "export_date": datetime.utcnow().isoformat(),
        "user": {
            "username": current_user.username,
            "email": current_user.email,
            "account_created": current_user.created_at.isoformat() if current_user.created_at else None,
        },
        "scans": [
            {
                "scan_id": s.scan_id,
                "filename": s.filename,
                "sender": s.sender,
                "subject": s.subject,
                "recipient": s.recipient,
                "risk_score": s.risk_score,
                "verdict": s.verdict,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "report": reports[s.scan_id].report_json if reports.get(s.scan_id) else None,
            }
            for s in scans
        ],
        "summary": {
            "total_scans": len(scans),
            "malicious_count": sum(1 for s in scans if s.verdict == "malicious"),
            "suspicious_count": sum(1 for s in scans if s.verdict == "suspicious"),
            "safe_count": sum(1 for s in scans if s.verdict == "safe"),
        }
    }
    
    return JSONResponse(content=data)


@router.delete("/user/scans-older-than")
def delete_old_scans(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete all scans older than specified days for current user
    Returns count of deleted scans
    """
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Get scan IDs to delete
    old_scans = db.query(ScanRecord).filter(
        (ScanRecord.user_id == current_user.id) & 
        (ScanRecord.created_at < cutoff)
    ).all()
    
    scan_ids = [s.scan_id for s in old_scans]
    
    # Delete threat reports
    deleted_reports = 0
    for scan_id in scan_ids:
        n = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).delete()
        deleted_reports += n
    
    # Delete scan records
    deleted_scans = db.query(ScanRecord).filter(
        (ScanRecord.user_id == current_user.id) & 
        (ScanRecord.created_at < cutoff)
    ).delete()
    
    # Update last cleanup time
    ps = db.query(PrivacySettings).filter(PrivacySettings.user_id == current_user.id).first()
    if ps:
        ps.last_cleanup = datetime.utcnow()
    
    db.commit()
    
    return {
        "ok": True,
        "message": f"Deleted {deleted_scans} scans older than {days} days",
        "deleted_scans": deleted_scans,
        "deleted_reports": deleted_reports,
    }


@router.delete("/user/all-scans")
def delete_all_scans(
    confirm: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete ALL scans for current user (irreversible)
    Requires confirm=true as safety check
    """
    if not confirm:
        raise HTTPException(400, "Confirmation required: add ?confirm=true")
    
    # Get all scan IDs
    scans = db.query(ScanRecord).filter(ScanRecord.user_id == current_user.id).all()
    scan_ids = [s.scan_id for s in scans]
    
    # Delete threat reports
    deleted_reports = 0
    for scan_id in scan_ids:
        n = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).delete()
        deleted_reports += n
    
    # Delete scan records
    deleted_scans = db.query(ScanRecord).filter(
        ScanRecord.user_id == current_user.id
    ).delete()
    
    db.commit()
    
    return {
        "ok": True,
        "message": f"Deleted all {deleted_scans} scans for user {current_user.username}",
        "deleted_scans": deleted_scans,
        "deleted_reports": deleted_reports,
    }


@router.delete("/user/account")
def delete_account(
    confirm: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Permanently delete user account and all associated data
    GDPR right to be forgotten - irreversible
    Requires confirm=true as safety check
    """
    if not confirm:
        raise HTTPException(400, "Confirmation required: add ?confirm=true")
    
    user_id = current_user.id
    
    # Get all scan IDs
    scans = db.query(ScanRecord).filter(ScanRecord.user_id == user_id).all()
    scan_ids = [s.scan_id for s in scans]
    
    # Delete threat reports
    deleted_reports = 0
    for scan_id in scan_ids:
        n = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).delete()
        deleted_reports += n
    
    # Delete scan records
    deleted_scans = db.query(ScanRecord).filter(
        ScanRecord.user_id == user_id
    ).delete()
    
    # Delete privacy settings
    db.query(PrivacySettings).filter(PrivacySettings.user_id == user_id).delete()
    
    # Delete user
    db.query(User).filter(User.id == user_id).delete()
    
    db.commit()
    
    return {
        "ok": True,
        "message": "Account permanently deleted",
        "deleted_scans": deleted_scans,
        "deleted_reports": deleted_reports,
    }


@router.post("/auto-cleanup")
def trigger_auto_cleanup(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger automatic cleanup based on user's retention settings
    Run this periodically (cronjob) or on user request
    """
    ps = db.query(PrivacySettings).filter(PrivacySettings.user_id == current_user.id).first()
    
    if not ps or not ps.auto_delete:
        return {"ok": True, "message": "Auto-cleanup disabled for this user"}
    
    # Delete old scans
    cutoff = datetime.utcnow() - timedelta(days=ps.data_retention_days)
    old_scans = db.query(ScanRecord).filter(
        (ScanRecord.user_id == current_user.id) & 
        (ScanRecord.created_at < cutoff)
    ).all()
    
    scan_ids = [s.scan_id for s in old_scans]
    deleted_reports = 0
    for scan_id in scan_ids:
        n = db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).delete()
        deleted_reports += n
    
    deleted_scans = db.query(ScanRecord).filter(
        (ScanRecord.user_id == current_user.id) & 
        (ScanRecord.created_at < cutoff)
    ).delete()
    
    ps.last_cleanup = datetime.utcnow()
    db.commit()
    
    return {
        "ok": True,
        "message": f"Auto-cleanup complete for {current_user.username}",
        "deleted_scans": deleted_scans,
        "deleted_reports": deleted_reports,
        "retention_days": ps.data_retention_days,
    }


@router.get("/privacy-policy")
def privacy_policy():
    """Return privacy policy information"""
    return {
        "version": "1.0",
        "last_updated": "2026-04-07",
        "data_collected": [
            "Account credentials (username, email, hashed password)",
            "Email metadata (sender, recipient, subject)",
            "Analysis results and threat indicators",
            "Scan history and timestamps",
        ],
        "data_NOT_collected": [
            "Email body content",
            "Attachment files",
            "IP addresses (server logs may be separate)",
            "Browser cookies (monitoring disabled)",
        ],
        "retention_policy": {
            "default_days": 30,
            "user_configurable": True,
            "auto_deletion": True,
        },
        "user_rights": [
            "Export all data (GDPR right to data portability)",
            "Delete individual scans",
            "Delete all scans at once",
            "Delete account (right to be forgotten)",
            "Control data retention period",
            "Disable analytics tracking",
        ],
        "contact": "privacy@eta-analyzer.local",
    }

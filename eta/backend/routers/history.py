from fastapi import APIRouter, Depends, HTTPException, Query, Path
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from typing import Optional

from database import get_db, ScanRecord, ThreatReport, User, Favourite, AuditLog
from routers.auth import optional_user, get_current_user

router = APIRouter(prefix="/history", tags=["history"])


@router.get("/scan-history")
def scan_history(
    page:    int = Query(1, ge=1),
    limit:   int = Query(20, ge=1, le=100),
    verdict: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(optional_user),
):
    q = db.query(ScanRecord).order_by(ScanRecord.created_at.desc())
    if current_user:
        q = q.filter((ScanRecord.user_id == current_user.id) | (ScanRecord.user_id == None))
    if verdict in ("safe","suspicious","malicious"):
        q = q.filter(ScanRecord.verdict == verdict)

    total = q.count()
    recs  = q.offset((page-1)*limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "pages": max(1, (total+limit-1)//limit),
        "records": [_fmt(r) for r in recs],
    }


@router.delete("/scan/{scan_id}")
def delete_scan(
    scan_id: str = Path(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a single scan - user can only delete their own scans"""
    record = db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).first()
    if not record:
        raise HTTPException(404, "Scan not found")
    
    # Authorization: user can only delete their own scans
    if record.user_id != current_user.id:
        raise HTTPException(403, "Not authorized to delete this scan")
    
    db.query(ThreatReport).filter(ThreatReport.scan_id == scan_id).delete()
    db.query(ScanRecord).filter(ScanRecord.scan_id == scan_id).delete()
    audit = AuditLog(user_id=current_user.id, action="scan_delete", target_type="scan",
                      target_id=scan_id, details={"filename": record.filename})
    db.add(audit)
    db.commit()

    return {"ok": True, "message": f"Scan {scan_id} deleted"}


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    # Single query instead of 5 separate count/avg queries
    row = db.query(
        func.count(ScanRecord.id).label("total"),
        func.sum(case((ScanRecord.verdict == "malicious", 1), else_=0)).label("malicious"),
        func.sum(case((ScanRecord.verdict == "suspicious", 1), else_=0)).label("suspicious"),
        func.sum(case((ScanRecord.verdict == "safe", 1), else_=0)).label("safe"),
        func.avg(ScanRecord.risk_score).label("avg_score"),
    ).one()

    total  = row.total or 0
    mal    = int(row.malicious or 0)
    sus    = int(row.suspicious or 0)
    safe   = int(row.safe or 0)
    avg_sc = row.avg_score or 0

    recent = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(20).all()
    trend  = [{"date": r.created_at.strftime("%m/%d"), "score": round(r.risk_score, 1), "verdict": r.verdict}
              for r in reversed(recent)]

    return {
        "total": total, "malicious": mal, "suspicious": sus, "safe": safe,
        "avg_score": round(float(avg_sc), 1),
        "malicious_rate": round((mal / max(1, total)) * 100, 1),
        "trend": trend,
    }


def _fmt(r: ScanRecord) -> dict:
    return {
        "scan_id":    r.scan_id,
        "filename":   r.filename,
        "sender":     r.sender,
        "subject":    r.subject,
        "risk_score": round(r.risk_score, 1),
        "verdict":    r.verdict,
        "url_count":  r.url_count,
        "attach_count": r.attach_count,
        "source":     r.source,
        "duration":   r.duration_s,
        "created_at": r.created_at.isoformat(),
    }


# ── Favourites / Bookmarks ─────────────────────────────────────────────────────
@router.get("/favourites")
def list_favourites(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return all bookmarked scans for the current user."""
    favs = db.query(Favourite).filter(Favourite.user_id == user.id).order_by(Favourite.created_at.desc()).all()
    results = []
    for f in favs:
        rec = db.query(ScanRecord).filter(ScanRecord.scan_id == f.scan_id).first()
        if rec:
            results.append({**_fmt(rec), "favourite_id": f.id, "fav_note": f.note})
    return {"favourites": results}


@router.post("/favourites/{scan_id}", status_code=201)
def add_favourite(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    existing = db.query(Favourite).filter(Favourite.user_id == user.id, Favourite.scan_id == scan_id).first()
    if existing:
        return {"message": "Already favourited", "favourite_id": existing.id}
    fav = Favourite(user_id=user.id, scan_id=scan_id)
    db.add(fav)
    db.commit()
    db.refresh(fav)
    return {"message": "Added to favourites", "favourite_id": fav.id}


@router.delete("/favourites/{scan_id}", status_code=204)
def remove_favourite(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    db.query(Favourite).filter(Favourite.user_id == user.id, Favourite.scan_id == scan_id).delete(synchronize_session=False)
    db.commit()
    return None

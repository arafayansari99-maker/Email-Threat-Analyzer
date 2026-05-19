"""
Analytics router — scan trends, IOC statistics, risk distribution, time analysis.
All endpoints are scoped to the current authenticated user's own scans.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, text
from datetime import datetime, timedelta
from collections import defaultdict

from database import get_db, ScanRecord, ThreatReport
from routers.auth import get_current_user

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/trends")
def scan_trends(
    days: int = Query(14, ge=7, le=90),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Daily scan counts + verdict breakdown for the last N days."""
    now = datetime.utcnow()
    start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    # Single GROUP BY query — works on both SQLite and PostgreSQL
    date_col = func.strftime("%Y-%m-%d", ScanRecord.created_at)
    rows = (
        db.query(
            date_col.label("day"),
            func.count(ScanRecord.id).label("total"),
            func.sum(case((ScanRecord.verdict == "malicious", 1), else_=0)).label("malicious"),
            func.sum(case((ScanRecord.verdict == "suspicious", 1), else_=0)).label("suspicious"),
            func.sum(case((ScanRecord.verdict == "safe", 1), else_=0)).label("safe"),
        )
        .filter(
            ScanRecord.user_id == current_user.id,
            ScanRecord.created_at >= start,
        )
        .group_by(date_col)
        .all()
    )

    row_map = {r.day: r for r in rows}
    trend = []
    for i in range(days):
        d = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        r = row_map.get(d)
        trend.append({
            "date":       d,
            "total":      r.total      if r else 0,
            "malicious":  r.malicious  if r else 0,
            "suspicious": r.suspicious if r else 0,
            "safe":       r.safe       if r else 0,
        })
    return trend


@router.get("/ioc-stats")
def ioc_stats(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Top IOCs: sender domains, senders, and subject patterns for the user's scans."""
    scans = (
        db.query(ScanRecord)
        .filter(ScanRecord.user_id == current_user.id, ScanRecord.verdict.in_(["malicious", "suspicious"]))
        .order_by(ScanRecord.created_at.desc())
        .limit(500)
        .all()
    )

    domain_counts:  dict = defaultdict(int)
    sender_counts:  dict = defaultdict(int)
    subject_counts: dict = defaultdict(int)

    for s in scans:
        if s.sender:
            parts = s.sender.split("@")
            if len(parts) == 2:
                domain_counts[parts[1].lower()] += 1
            sender_counts[s.sender.lower()] += 1
        if s.subject:
            # Truncate subject to first 60 chars for grouping
            key = s.subject[:60].strip()
            if key:
                subject_counts[key] += 1

    def top(d: dict, n: int):
        return [{"value": k, "count": v}
                for k, v in sorted(d.items(), key=lambda x: x[1], reverse=True)[:n]]

    return {
        "top_domains":  top(domain_counts,  limit),
        "top_senders":  top(sender_counts,  limit),
        "top_subjects": top(subject_counts, limit),
    }


@router.get("/risk-distribution")
def risk_distribution(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Histogram of risk scores in 10-point buckets (0-10, 10-20, …, 90-100)."""
    scans = (
        db.query(ScanRecord.risk_score)
        .filter(ScanRecord.user_id == current_user.id)
        .all()
    )

    buckets = [{"range": f"{i}-{i+10}", "min": i, "max": i + 10, "count": 0} for i in range(0, 100, 10)]
    total = 0
    score_sum = 0.0

    for (score,) in scans:
        if score is None:
            continue
        total += 1
        score_sum += score
        idx = min(int(score // 10), 9)
        buckets[idx]["count"] += 1

    return {
        "buckets": buckets,
        "total":   total,
        "average": round(score_sum / total, 1) if total else 0.0,
    }


@router.get("/time-analysis")
def time_analysis(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Hourly and day-of-week scan counts for the user's scan history."""
    scans = (
        db.query(ScanRecord.created_at)
        .filter(ScanRecord.user_id == current_user.id)
        .all()
    )

    hourly = [{"hour": h, "label": f"{h:02d}:00", "count": 0} for h in range(24)]
    daily  = [
        {"day": d, "label": label, "count": 0}
        for d, label in enumerate(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
    ]

    for (ts,) in scans:
        if ts is None:
            continue
        hourly[ts.hour]["count"] += 1
        # weekday(): 0=Monday … 6=Sunday
        daily[ts.weekday()]["count"] += 1

    return {"hourly": hourly, "daily": daily}

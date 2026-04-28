from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case
from typing import Optional, List
from datetime import datetime, timedelta
import logging
import json

from database import get_db, ScanRecord, ThreatReport
from analysis_engine import run_analysis
from routers.auth import optional_user

router = APIRouter()

# Setup logging for file processing tracking
logger = logging.getLogger(__name__)

ALLOWED = {".eml", ".msg", ".txt", ".mbox", ".csv", ".pdf", ".json", ".xml", ".html", ".htm", ".log", ".md"}
MAX_SIZE = 300 * 1024 * 1024  # 300 MB
MIN_SIZE = 10  # 10 bytes minimum


@router.post("/analyze-email")
async def analyze_email(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(optional_user),
):
    """Analyze a single email file for threats."""
    if not file.filename:
        logger.warning("Upload attempted with no filename")
        raise HTTPException(400, "No file provided")

    # Extract and validate extension
    ext = ("." + file.filename.rsplit(".", 1)[-1].lower()) if "." in file.filename else ""
    if ext not in ALLOWED:
        logger.warning(f"Unsupported file type: {ext} in file {file.filename}")
        raise HTTPException(400, f"Unsupported type '{ext}'. Use: {', '.join(sorted(ALLOWED))}")

    content = await file.read()

    # Validate file size
    if len(content) > MAX_SIZE:
        logger.warning(f"File too large: {file.filename} ({len(content)} bytes)")
        raise HTTPException(413, f"File too large (max {MAX_SIZE / (1024*1024):.0f} MB)")

    if len(content) < MIN_SIZE:
        logger.warning(f"File too small: {file.filename} ({len(content)} bytes)")
        raise HTTPException(400, "File is too small or empty")

    logger.info(f"Analyzing single file: {file.filename} ({len(content)} bytes)")

    try:
        result = run_analysis(content, file.filename)
        uid = current_user.id if current_user else None
        _save(db, result, uid, "upload")
        logger.info(f"Successfully analyzed: {file.filename}, Verdict: {result.get('verdict')}")
        return result
    except Exception as e:
        logger.error(f"Analysis error for {file.filename}: {str(e)}", exc_info=True)
        raise HTTPException(500, f"Analysis error: {str(e)}")


@router.post("/analyze-batch")
async def analyze_batch(
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(optional_user),
):
    """Analyze multiple email files in batch."""
    if not files:
        logger.warning("Batch upload with no files")
        raise HTTPException(400, "No files provided")

    logger.info(f"Starting batch analysis with {len(files)} files")

    processed_count = 0
    skipped_count = 0
    results = []
    errors = []

    for idx, file in enumerate(files, 1):
        if not file.filename:
            logger.warning(f"Skipping file {idx}: no filename")
            skipped_count += 1
            continue

        # Extract and validate extension
        ext = ("." + file.filename.rsplit(".", 1)[-1].lower()) if "." in file.filename else ""
        if ext not in ALLOWED:
            error_msg = f"Unsupported type '{ext}' in file '{file.filename}'. Use: {', '.join(sorted(ALLOWED))}"
            logger.warning(f"Batch file {idx} skipped: {error_msg}")
            errors.append({"file": file.filename, "error": error_msg})
            skipped_count += 1
            continue

        content = await file.read()
        file_size = len(content)

        # Validate individual file size
        if file_size > MAX_SIZE:
            error_msg = f"File too large ({file_size / (1024*1024):.1f} MB, max {MAX_SIZE / (1024*1024):.0f} MB)"
            logger.warning(f"Batch file {idx} skipped: {error_msg}")
            errors.append({"file": file.filename, "error": error_msg})
            skipped_count += 1
            continue

        # Skip empty files but log them
        if file_size < MIN_SIZE:
            logger.warning(f"Batch file {idx} skipped: File too small ({file_size} bytes)")
            errors.append({"file": file.filename, "error": f"File too small ({file_size} bytes)"})
            skipped_count += 1
            continue

        try:
            logger.info(f"Processing batch file {idx}/{len(files)}: {file.filename} ({file_size} bytes)")
            result = run_analysis(content, file.filename)
            uid = current_user.id if current_user else None
            _save(db, result, uid, "batch_upload")
            results.append(result)
            logger.info(f"✓ Processed: {file.filename}, Verdict: {result.get('verdict')}, Score: {result.get('risk_score')}")
            processed_count += 1
        except Exception as e:
            error_msg = f"Analysis error: {str(e)}"
            logger.error(f"Batch file {idx} failed: {file.filename} - {error_msg}", exc_info=True)
            errors.append({"file": file.filename, "error": error_msg})
            skipped_count += 1

    logger.info(f"Batch analysis complete: {processed_count} processed, {skipped_count} skipped")

    if not results:
        logger.error(f"Batch analysis: No files successfully processed")
        raise HTTPException(400, f"No files could be processed. Errors: {errors}")

    # Count verdicts for frontend compatibility
    malicious = sum(1 for r in results if r.get("verdict") == "malicious")
    suspicious = sum(1 for r in results if r.get("verdict") == "suspicious")
    safe = sum(1 for r in results if r.get("verdict") == "safe")
    
    return {
        "total": processed_count,
        "malicious": malicious,
        "suspicious": suspicious,
        "safe": safe,
        "results": results,
        "errors": errors if errors else [],
        "skipped": skipped_count
    }


class ExtensionPayload(BaseModel):
    email_content: str
    subject: Optional[str] = ""
    sender: Optional[str] = ""
    recipient: Optional[str] = ""
    gmail_message_id: Optional[str] = None


# Debug test endpoint
@router.post("/test-scan")
async def test_scan(
    body: ExtensionPayload,
    db: Session = Depends(get_db),
):
    """Test endpoint - returns what was sent."""
    return {
        "received": {
            "email_content": body.email_content[:50],
            "subject": body.subject,
            "sender": body.sender,
        },
    }


@router.post("/extension-scan")
async def extension_scan(
    body: ExtensionPayload,
    db: Session = Depends(get_db),
):
    """Analyze email content from browser extension - no auth required."""
    """Analyze email content from browser extension."""
    if not body.email_content and not body.subject and not body.sender:
        raise HTTPException(400, "No content provided")

    # Build minimal RFC2822-like content for the engine
    raw = f"From: {body.sender}\nTo: {body.recipient}\nSubject: {body.subject}\n\n{body.email_content}"
    result = run_analysis(raw.encode(), f"gmail_{(body.gmail_message_id or 'ext')[:8]}.txt")
    if body.gmail_message_id:
        result["scan_id"] = body.gmail_message_id

    # Try to save, but don't fail if it doesn't work
    try:
        _save(db, result, None, "extension")
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Could not save scan: {e}")

    return {
        "scan_id":         result["scan_id"],
        "risk_score":      result["risk_score"],
        "verdict":         result["verdict"],
        "color":           result["color"],
        "phishing_prob":   result["ml_analysis"]["phishing_probability"],
        "malicious_urls":  result["url_analysis"]["high_risk"][:5],
        "url_count":       result["url_analysis"]["total"],
        "mal_url_count":   result["url_analysis"]["malicious"],
        "indicators":      result["header_analysis"]["indicators"][:5],
        "recommendations": result["recommendations"][:3],
        "auth": {
            "spf":  result["header_analysis"]["spf"],
            "dkim": result["header_analysis"]["dkim"],
            "dmarc":result["header_analysis"]["dmarc"],
        },
        "duration": result["duration"],
    }


def _save(db: Session, result: dict, user_id: Optional[int], source: str):
    """Save analysis result to database."""
    try:
        rec = ScanRecord(
            scan_id=result["scan_id"],
            user_id=user_id,
            filename=result.get("filename", ""),
            sender=result.get("meta", {}).get("sender_email", "")[:255] if result.get("meta") else "",
            subject=result.get("meta", {}).get("subject", "")[:500] if result.get("meta") else "",
            recipient=result.get("meta", {}).get("recipient", "")[:255] if result.get("meta") else "",
            risk_score=result.get("risk_score", 0),
            verdict=result.get("verdict", "unknown"),
            phishing_prob=result.get("ml_analysis", {}).get("phishing_probability", 0),
            url_count=result.get("url_count", 0),
            attach_count=result.get("attach_count", 0),
            duration_s=result.get("duration", 0),
            source=source,
        )
        db.add(rec)
        rep = ThreatReport(scan_id=result["scan_id"], report_json=result)
        db.add(rep)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to save result: {e}")
        db.rollback()


# ── Analytics Endpoints ─────────────────────────────────────────────────────

@router.get("/analytics/trends")
def get_scan_trends(
    days: int = Query(14, ge=7, le=90),
    db: Session = Depends(get_db),
    current_user=Depends(optional_user),
):
    """Get scan trends over time — single query with conditional aggregation."""
    start_date = datetime.utcnow() - timedelta(days=days)
    end_date = datetime.utcnow()

    q = db.query(
        func.date(ScanRecord.created_at).label("date"),
        func.count(ScanRecord.id).label("total"),
        func.sum(case((ScanRecord.verdict == "malicious", 1), else_=0)).label("malicious"),
        func.sum(case((ScanRecord.verdict == "safe", 1), else_=0)).label("safe"),
        func.sum(case((ScanRecord.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    ).filter(ScanRecord.created_at >= start_date, ScanRecord.created_at < end_date)

    if current_user and current_user.role not in ('admin', 'superadmin'):
        q = q.filter(ScanRecord.user_id == current_user.id)

    results = q.group_by(func.date(ScanRecord.created_at)).all()
    trend_dict = {
        str(r.date): {
            "total": r.total,
            "malicious": int(r.malicious or 0),
            "safe": int(r.safe or 0),
            "suspicious": int(r.suspicious or 0),
        }
        for r in results
    }

    trend = []
    for i in range(days - 1, -1, -1):
        day_str = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        d = trend_dict.get(day_str, {"total": 0, "malicious": 0, "safe": 0, "suspicious": 0})
        trend.append({"date": day_str, **d})
    return trend


@router.get("/analytics/ioc-stats")
def get_ioc_analytics(
    limit: int = Query(10, ge=5, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(optional_user),
):
    """Get IOC analytics - top domains, IPs, etc."""
    # Fetch recent scan records (verdict + sender) in one query — avoids N+1 later
    scan_q = db.query(ScanRecord.scan_id, ScanRecord.verdict, ScanRecord.sender).order_by(desc(ScanRecord.created_at))
    if current_user and current_user.role not in ('admin', 'superadmin'):
        scan_q = scan_q.filter(ScanRecord.user_id == current_user.id)
    scan_rows = scan_q.limit(200).all()

    if not scan_rows:
        return {"top_domains": [], "top_ips": [], "top_senders": []}

    scan_ids = [r.scan_id for r in scan_rows]
    scan_map = {r.scan_id: r for r in scan_rows}

    reports = db.query(ThreatReport).filter(ThreatReport.scan_id.in_(scan_ids)).all()

    domain_counts: dict = {}
    ip_counts: dict = {}
    sender_counts: dict = {}

    for report in reports:
        try:
            data = report.report_json if isinstance(report.report_json, dict) else json.loads(report.report_json)

            for ioc in data.get("iocs", []):
                if ioc.get("verdict") == "malicious":
                    val = ioc.get("value", "")
                    if ioc.get("type") == "domain":
                        domain_counts[val] = domain_counts.get(val, 0) + 1
                    elif ioc.get("type") == "ip":
                        ip_counts[val] = ip_counts.get(val, 0) + 1

            sr = scan_map.get(report.scan_id)
            if sr and sr.verdict in ("suspicious", "malicious"):
                sender_email = (data.get("sender") or {}).get("email") or (data.get("meta") or {}).get("sender_email") or sr.sender
                if sender_email:
                    sender_counts[sender_email] = sender_counts.get(sender_email, 0) + 1
        except Exception:
            pass

    # Top domains
    top_domains = sorted(domain_counts.items(), key=lambda x: -x[1])[:limit]
    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:limit]
    top_senders = sorted(sender_counts.items(), key=lambda x: -x[1])[:limit]

    return {
        "top_domains": [{"domain": d, "count": c} for d, c in top_domains],
        "top_ips": [{"ip": i, "count": c} for i, c in top_ips],
        "top_senders": [{"email": e, "count": c} for e, c in top_senders],
    }


@router.get("/analytics/risk-distribution")
def get_risk_distribution(
    db: Session = Depends(get_db),
    current_user=Depends(optional_user),
):
    """Get risk score distribution histogram — aggregated in SQL."""
    q = db.query(ScanRecord.risk_score, func.avg(ScanRecord.risk_score).over().label("avg"))
    if current_user and current_user.role not in ('admin', 'superadmin'):
        q = q.filter(ScanRecord.user_id == current_user.id)

    rows = q.all()
    if not rows:
        return {"buckets": [], "average": 0}

    buckets = [0] * 10
    avg_score = 0.0
    for score, avg in rows:
        if score is not None:
            buckets[min(int(score // 10), 9)] += 1
        avg_score = float(avg or 0)

    return {
        "buckets": [{"range": f"{i*10}-{i*10+10}", "count": buckets[i]} for i in range(10)],
        "average": round(avg_score, 1),
    }


@router.get("/analytics/time-analysis")
def get_time_analysis(
    db: Session = Depends(get_db),
    current_user=Depends(optional_user),
):
    """Analyze peak hours and days — 2 queries with conditional aggregation instead of 8."""
    day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    def _user_filter(q):
        if current_user and current_user.role not in ('admin', 'superadmin'):
            return q.filter(ScanRecord.user_id == current_user.id)
        return q

    agg = [
        func.count(ScanRecord.id).label('total'),
        func.sum(case((ScanRecord.verdict == "malicious", 1), else_=0)).label('malicious'),
        func.sum(case((ScanRecord.verdict == "safe", 1), else_=0)).label('safe'),
        func.sum(case((ScanRecord.verdict == "suspicious", 1), else_=0)).label('suspicious'),
    ]

    hourly_results = _user_filter(
        db.query(func.extract('hour', ScanRecord.created_at).label('hour'), *agg)
    ).group_by(func.extract('hour', ScanRecord.created_at)).all()

    daily_results = _user_filter(
        db.query(func.extract('dow', ScanRecord.created_at).label('dow'), *agg)
    ).group_by(func.extract('dow', ScanRecord.created_at)).all()

    hour_data = {
        int(r.hour): {"total": r.total, "malicious": int(r.malicious or 0), "safe": int(r.safe or 0), "suspicious": int(r.suspicious or 0)}
        for r in hourly_results
    }
    day_data = {
        int(r.dow): {"total": r.total, "malicious": int(r.malicious or 0), "safe": int(r.safe or 0), "suspicious": int(r.suspicious or 0)}
        for r in daily_results
    }

    empty = {"total": 0, "malicious": 0, "safe": 0, "suspicious": 0}
    # DOW: 0=Sunday, 1=Monday … 6=Saturday — output Mon→Sun via dow_order
    dow_order = [1, 2, 3, 4, 5, 6, 0]

    return {
        "hourly": [{"hour": h, **hour_data.get(h, empty)} for h in range(24)],
        "daily": [{"day": day_names[i], **day_data.get(dow_order[i], empty)} for i in range(7)],
    }

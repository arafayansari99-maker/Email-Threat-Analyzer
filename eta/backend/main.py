"""
ETA Email Threat Analyzer - Main Application
"""

import os
import sys
import time
import asyncio
import psutil
import logging
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from sqlalchemy import text
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import engine, Base, SessionLocal, User, PrivacySettings, ScanRecord, ThreatReport, run_migrations
from routers.auth import router as auth_router, get_password_hash, limiter, check_admin
from routers.analysis import router as analysis_router
from routers.history import router as history_router
from routers.reports import router as reports_router
from routers.privacy import router as privacy_router
from routers.users import router as users_router
from routers.settings import router as settings_router
from routers.collaboration import router as collaboration_router
from routers.threat_intel import router as threat_intel_router
from routers.admin import router as admin_router
from routers.team_roles import router as team_roles_router
from routers.feedback import router as feedback_router
from routers.analytics import router as analytics_router
from routers.chat import router as chat_router
from routers.notifications import router as notifications_router
from routers.imap import router as imap_router

# Import new modular components
from ml_classifier import get_model_metrics, train_tfidf_model
from security_middleware import (
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    IPBlocklistMiddleware,
)
from health_monitor import health_monitor, alert_service

START_TIME = time.time()
APP_VERSION = "2.0.0"

# Configure logging — use utf-8 with replacement to avoid UnicodeEncodeError on Windows cp1252
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('eta_pdf_errors.log', mode='a', encoding='utf-8', errors='replace'),
    ]
)


def create_default_admin():
    """Create default superadmin from env vars on first run only."""
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip()
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()

    if not admin_email or not admin_password:
        logging.warning(
            "[STARTUP] ADMIN_EMAIL / ADMIN_PASSWORD not set — skipping default admin creation. "
            "Set both env vars before first run."
        )
        return

    from sqlalchemy.exc import IntegrityError
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == admin_email).first()
        if not existing:
            admin = User(
                username=admin_email.split("@")[0],
                email=admin_email,
                hashed_pw=get_password_hash(admin_password),
                role="superadmin",
                is_active=True,
                is_approved=True,
            )
            db.add(admin)
            db.commit()
            logging.info("[STARTUP] Created superadmin: %s", admin_email)
        else:
            logging.info("[STARTUP] Superadmin already exists: %s", admin_email)
    except IntegrityError:
        db.rollback()
        logging.info("[STARTUP] Superadmin already created by another worker: %s", admin_email)
    finally:
        db.close()


async def _retention_cleanup_loop():
    """Background task: enforce each user's data retention policy every hour."""
    while True:
        await asyncio.sleep(3600)
        db = SessionLocal()
        try:
            policies = db.query(PrivacySettings).filter(PrivacySettings.auto_delete).all()
            for ps in policies:
                cutoff = datetime.utcnow() - timedelta(days=ps.data_retention_days)
                old_ids = [
                    r.scan_id for r in db.query(ScanRecord.scan_id)
                    .filter(ScanRecord.user_id == ps.user_id, ScanRecord.created_at < cutoff)
                    .all()
                ]
                if not old_ids:
                    continue
                db.query(ThreatReport).filter(ThreatReport.scan_id.in_(old_ids)).delete(synchronize_session=False)
                db.query(ScanRecord).filter(ScanRecord.scan_id.in_(old_ids)).delete(synchronize_session=False)
                ps.last_cleanup = datetime.utcnow()
                logging.info("[retention] Deleted %d scans for user %d", len(old_ids), ps.user_id)
            db.commit()
        except Exception as exc:
            logging.error("[retention] Cleanup failed: %s", exc)
            db.rollback()
        finally:
            db.close()


def _check_ml_models():
    """Verify ML model files are present and loadable at startup. Log warnings if not."""
    from pathlib import Path
    ml_dir = Path(__file__).resolve().parent / "ml"
    required = {
        "phishing_model.pkl": "XGBoost phishing model",
        "feature_scaler.pkl": "Feature scaler",
        "model_meta.json":    "Model metadata",
    }
    semantic_dir = ml_dir / "semantic_model"
    if not semantic_dir.exists():
        logging.error(
            "[ML] Missing semantic_model directory — DistilBERT is required. "
            "Place fine-tuned model files in ml/semantic_model/"
        )
    all_ok = semantic_dir.exists()
    if semantic_dir.exists():
        try:
            from ml.semantic_classifier import classify_semantic
            sem_check = classify_semantic("Startup test", "Enable semantic analysis for email inference.")
            if sem_check.get("method") == "unavailable":
                logging.error("[ML] Semantic model unavailable at startup: %s", sem_check)
                all_ok = False
            else:
                logging.info("[ML] Semantic model enabled: %s", sem_check.get("method"))
        except Exception as exc:
            logging.error("[ML] Semantic model startup check failed: %s", exc, exc_info=True)
            all_ok = False
    for filename, label in required.items():
        path = ml_dir / filename
        if not path.exists():
            logging.error("[ML] Missing model file: %s (%s) — analysis will fall back to heuristics", filename, label)
            all_ok = False
        else:
            try:
                import joblib
                import json
                if filename.endswith(".pkl"):
                    joblib.load(path)
                else:
                    json.loads(path.read_text())
                logging.info("[ML] OK: %s", filename)
            except Exception as exc:
                logging.error("[ML] Corrupt model file %s: %s — analysis will fall back to heuristics", filename, exc)
                all_ok = False
    if all_ok:
        logging.info("[ML] All model files verified successfully")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables, apply schema migrations, create default admin
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    create_default_admin()
    _check_ml_models()

    # Start health monitoring
    health_monitor.register_callback(alert_service.send_health_alert)
    health_monitor.start()

    # Start background retention cleanup (runs every hour)
    cleanup_task = asyncio.create_task(_retention_cleanup_loop())

    yield
    # Shutdown: cleanup
    cleanup_task.cancel()
    health_monitor.stop()


_is_dev = os.environ.get("ENVIRONMENT", "development") != "production"

app = FastAPI(
    title="ETA Email Threat Analyzer API",
    description="Email threat analysis with ML-powered phishing detection",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if _is_dev else None,
    redoc_url="/redoc" if _is_dev else None,
    openapi_url="/openapi.json" if _is_dev else None,
)

# CORS middleware
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://localhost:3001,http://127.0.0.1:5173,http://127.0.0.1:3000,http://127.0.0.1:3001"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "Accept", "X-Requested-With"],
)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Enhanced security middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(IPBlocklistMiddleware)

# Static files caching middleware
@app.middleware("http")
async def add_cache_control(request, call_next):
    response = await call_next(request)
    # Cache static assets
    if request.url.path.startswith("/static/") or ".js" in request.url.path or ".css" in request.url.path:
        response.headers["Cache-Control"] = "public, max-age=31536000"
    return response

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Include routers with /api prefix
app.include_router(auth_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(privacy_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(settings_router, prefix="/api")
app.include_router(collaboration_router, prefix="/api")
app.include_router(threat_intel_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.include_router(team_roles_router, prefix="/api")
app.include_router(feedback_router, prefix="/api")
app.include_router(analytics_router, prefix="/api")
app.include_router(chat_router, prefix="/api")
app.include_router(notifications_router, prefix="/api")
app.include_router(imap_router, prefix="/api")


@app.get("/")
def root():
    return {"status": "online", "service": "ETA Email Threat Analyzer"}


def _build_uptime_string(uptime_seconds: int) -> str:
    if uptime_seconds >= 86400:
        return f"{uptime_seconds // 86400}d {(uptime_seconds % 86400) // 3600}h"
    if uptime_seconds >= 3600:
        return f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"
    if uptime_seconds >= 60:
        return f"{uptime_seconds // 60}m {uptime_seconds % 60}s"
    return f"{uptime_seconds}s"


def _db_status() -> tuple[str, str | None]:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "connected", None
    except Exception as exc:
        return "disconnected", str(exc)


@app.get("/health", summary="Public liveness probe")
def health():
    """Minimal public health check — safe to expose to load-balancers."""
    status, _ = _db_status()
    return JSONResponse({
        "status": "healthy" if status == "connected" else "degraded",
        "service": "ETA Email Threat Analyzer",
        "version": APP_VERSION,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    })


@app.get("/health/detailed", summary="Detailed system metrics (admin only)")
def health_detailed(_admin: User = Depends(check_admin)):
    """Full health check including disk, memory, CPU and ML metrics. Requires admin token."""
    db_status, db_error = _db_status()

    try:
        disk = psutil.disk_usage('/')
        disk_info = {
            "total_gb": round(disk.total / (1024**3), 1),
            "used_gb": round(disk.used / (1024**3), 1),
            "free_gb": round(disk.free / (1024**3), 1),
            "percent": disk.percent,
        }
    except Exception:
        disk_info = None

    try:
        mem = psutil.virtual_memory()
        memory_info = {
            "total_gb": round(mem.total / (1024**3), 1),
            "used_gb": round(mem.used / (1024**3), 1),
            "percent": mem.percent,
        }
    except Exception:
        memory_info = None

    uptime_seconds = int(time.time() - START_TIME)

    return JSONResponse({
        "status": "healthy" if db_status == "connected" else "degraded",
        "service": "ETA Email Threat Analyzer",
        "version": APP_VERSION,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "uptime_seconds": uptime_seconds,
        "uptime_formatted": _build_uptime_string(uptime_seconds),
        "database": {"status": db_status, "error": db_error},
        "memory": memory_info,
        "disk": disk_info,
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "cpu_count": psutil.cpu_count(),
        "ml_metrics": get_model_metrics(),
    })


@app.get("/ml/metrics", summary="ML model metrics (admin only)")
def get_ml_metrics(_admin: User = Depends(check_admin)):
    """Get ML model metrics. Requires admin token."""
    return get_model_metrics()


@app.get("/health-monitor", summary="Health monitor status (admin only)")
def get_health_monitor(_admin: User = Depends(check_admin)):
    """Get health monitor status. Requires admin token."""
    return health_monitor.get_status()


@app.post("/health-monitor/check", summary="Trigger health check (admin only)")
def trigger_health_check(_admin: User = Depends(check_admin)):
    """Trigger an immediate health check. Requires admin token."""
    result = health_monitor.check_now()
    return {"healthy": result}


@app.post("/ml/train", summary="Retrain ML model (superadmin only)")
def train_ml(_admin: User = Depends(check_admin)):
    """Retrain the TF-IDF phishing model. Requires admin token."""
    metrics = train_tfidf_model(n_samples=10000)
    return {"status": "trained", "metrics": metrics}


if __name__ == "__main__":
    import uvicorn
    from database import _is_sqlite
    # SQLite supports only one writer at a time — use 1 worker in dev.
    # Switch to PostgreSQL + workers=4 for production.
    workers = 1 if _is_sqlite else 4
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=workers,
        limit_concurrency=1000,
        limit_max_requests=10000,
        timeout_keep_alive=30,
        access_log=False,
    )

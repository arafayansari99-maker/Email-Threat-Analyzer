"""
ETA Email Threat Analyzer - Main Application
"""
import os
import sys
import time
import psutil
import logging
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
from sqlalchemy import text

START_TIME = time.time()
APP_VERSION = "2.0.0"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('eta_pdf_errors.log', mode='a')
    ]
)

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import engine, Base, SessionLocal, User
from routers.auth import router as auth_router, get_password_hash, limiter
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

# Import new modular components
from ml_classifier import classify_text_tfidf, get_model_metrics, train_tfidf_model
from url_analysis import analyze_urls, extract_urls
from header_analysis import analyze_headers
from risk_scoring import calculate_risk
from security_middleware import (
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    IPBlocklistMiddleware,
    get_client_ip,
    metrics,
    rate_limiter,
)
from health_monitor import health_monitor, alert_service


def create_default_admin():
    """Create default superadmin user on startup."""
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == "admin@eta.local").first()
        if not existing:
            admin = User(
                username="admin",
                email="admin@eta.local",
                hashed_pw=get_password_hash("Eta@2026!SecureAdmin"),
                role="superadmin",
                is_active=True,
                is_approved=True,
            )
            db.add(admin)
            db.commit()
            print("[OK] Created default superadmin user")
        else:
            print("[INFO] Superadmin already exists")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables and default admin
    Base.metadata.create_all(bind=engine)
    create_default_admin()

    # Start health monitoring
    health_monitor.register_callback(alert_service.send_health_alert)
    health_monitor.start()

    yield
    # Shutdown: cleanup
    health_monitor.stop()


app = FastAPI(
    title="ETA Email Threat Analyzer API",
    description="Email threat analysis with ML-powered phishing detection",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


@app.get("/")
def root():
    return {"status": "online", "service": "ETA Email Threat Analyzer"}


@app.get("/health")
def health():
    """Full health check with DB status, disk usage, memory, uptime."""
    from database import engine
    db_status = "connected"
    db_error = None
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = "disconnected"
        db_error = str(e)

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
    uptime_formatted = f"{uptime_seconds}s"
    if uptime_seconds >= 86400:
        uptime_formatted = f"{uptime_seconds // 86400}d {(uptime_seconds % 86400) // 3600}h"
    elif uptime_seconds >= 3600:
        uptime_formatted = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"
    elif uptime_seconds >= 60:
        uptime_formatted = f"{uptime_seconds // 60}m {uptime_seconds % 60}s"

    return JSONResponse({
        "status": "healthy" if db_status == "connected" else "degraded",
        "service": "ETA Email Threat Analyzer",
        "version": APP_VERSION,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "uptime_seconds": uptime_seconds,
        "uptime_formatted": uptime_formatted,
        "database": {
            "status": db_status,
            "error": db_error,
        },
        "memory": memory_info,
        "disk": disk_info,
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "cpu_count": psutil.cpu_count(),
        "ml_metrics": get_model_metrics(),
    })


@app.get("/ml/metrics")
def get_ml_metrics():
    """Get ML model metrics."""
    return get_model_metrics()


@app.get("/health-monitor")
def get_health_monitor():
    """Get health monitor status."""
    return health_monitor.get_status()


@app.post("/health-monitor/check")
def trigger_health_check():
    """Trigger an immediate health check."""
    result = health_monitor.check_now()
    return {"healthy": result}


@app.post("/ml/train")
def train_ml():
    """Train the TF-IDF model."""
    metrics = train_tfidf_model(n_samples=10000)
    return {"status": "trained", "metrics": metrics}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=4,
        limit_concurrency=1000,
        limit_max_requests=10000,
        timeout_keep_alive=30,
        access_log=False,
    )

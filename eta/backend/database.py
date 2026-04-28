from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Boolean, JSON, Text, Index
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "eta.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}")

# Neon/PostgreSQL fix: replace postgres:// with postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

# Connection pool settings for better scalability
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=10,           # Max connections
    max_overflow=20,         # Extra connections under load
    pool_timeout=30,          # Connection timeout
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id           = Column(Integer, primary_key=True, index=True)
    username     = Column(String(50), unique=True, index=True, nullable=False)
    email        = Column(String(120), unique=True, index=True, nullable=False)
    hashed_pw    = Column(String(200), nullable=False)
    is_active    = Column(Boolean, default=True)
    role         = Column(String(20), default="user", nullable=False)  # superadmin, admin, analyst, viewer, user
    is_approved  = Column(Boolean, default=False)  # Awaiting admin approval
    created_at   = Column(DateTime, default=datetime.utcnow)
    approved_by  = Column(Integer, nullable=True)  # Admin ID who approved
    approved_at  = Column(DateTime, nullable=True)


class ScanRecord(Base):
    __tablename__ = "scan_records"
    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(String(36), unique=True, index=True)
    user_id      = Column(Integer, nullable=True, index=True)
    filename     = Column(String(255), nullable=True)
    sender       = Column(String(255), nullable=True)
    subject      = Column(String(500), nullable=True)
    recipient    = Column(String(255), nullable=True)
    risk_score   = Column(Float, default=0.0)
    verdict      = Column(String(20), default="unknown", index=True)
    phishing_prob= Column(Float, default=0.0)
    url_count    = Column(Integer, default=0)
    attach_count = Column(Integer, default=0)
    duration_s   = Column(Float, default=0.0)
    source       = Column(String(20), default="upload")
    created_at   = Column(DateTime, default=datetime.utcnow, index=True)

    # Composite indexes for analytics queries
    __table_args__ = (
        Index('idx_scan_user_created', 'user_id', 'created_at'),
        Index('idx_scan_verdict_created', 'verdict', 'created_at'),
    )


class ThreatReport(Base):
    __tablename__ = "threat_reports"
    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(String(36), unique=True, index=True)
    report_json  = Column(JSON, nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow)


class DataSharing(Base):
    __tablename__ = "data_sharing"
    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(String(36), nullable=False, index=True)
    owner_id     = Column(Integer, nullable=False, index=True)
    shared_with_id = Column(Integer, nullable=False, index=True)
    permission   = Column(String(20), default="view")  # view, edit, delete
    created_at   = Column(DateTime, default=datetime.utcnow)


class PrivacySettings(Base):
    __tablename__ = "privacy_settings"
    id               = Column(Integer, primary_key=True, index=True)
    user_id          = Column(Integer, unique=True, nullable=False, index=True)
    data_retention_days = Column(Integer, default=30)  # Auto-delete scans older than X days
    allow_analytics  = Column(Boolean, default=False)  # Opt-in analytics tracking
    auto_delete      = Column(Boolean, default=True)   # Enable auto-deletion
    last_cleanup     = Column(DateTime, default=datetime.utcnow)
    created_at       = Column(DateTime, default=datetime.utcnow)
    updated_at       = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Workspace(Base):
    __tablename__ = "workspaces"
    id           = Column(Integer, primary_key=True, index=True)
    name         = Column(String(100), nullable=False)
    description  = Column(Text, nullable=True)
    owner_id     = Column(Integer, nullable=False, index=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkspaceMember(Base):
    __tablename__ = "workspace_members"
    id           = Column(Integer, primary_key=True, index=True)
    workspace_id = Column(Integer, nullable=False, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    role         = Column(String(20), default="member")  # owner, admin, analyst, viewer
    joined_at    = Column(DateTime, default=datetime.utcnow)


class ReportComment(Base):
    __tablename__ = "report_comments"
    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(String(36), nullable=False, index=True)
    user_id     = Column(Integer, nullable=False, index=True)
    content     = Column(Text, nullable=False)
    is_flag     = Column(Boolean, default=False)  # True = flagged for review
    parent_id   = Column(Integer, nullable=True)  # For nested replies
    created_at  = Column(DateTime, default=datetime.utcnow)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    workspace_id = Column(Integer, nullable=True, index=True)
    action      = Column(String(50), nullable=False)  # scan_created, user_approved, comment_added, etc.
    target_type = Column(String(30), nullable=True)  # user, scan, report, workspace
    target_id   = Column(Integer, nullable=True)
    details     = Column(JSON, nullable=True)  # Extra metadata
    created_at  = Column(DateTime, default=datetime.utcnow)


class User2FA(Base):
    __tablename__ = "user_2fa"
    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, unique=True, nullable=False, index=True)
    secret         = Column(String(32), nullable=True)   # encrypted TOTP secret, null until 2FA enabled
    is_enabled     = Column(Boolean, default=False)
    backup_codes   = Column(JSON, nullable=True)         # list of hashed backup codes
    created_at     = Column(DateTime, default=datetime.utcnow)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LoginAttempt(Base):
    """Tracks failed login attempts per IP + email for brute-force protection."""
    __tablename__ = "login_attempts"
    id           = Column(Integer, primary_key=True, index=True)
    email        = Column(String(120), nullable=False, index=True)
    ip_address   = Column(String(45), nullable=False, index=True)
    user_agent   = Column(String(255), nullable=True)
    success      = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=datetime.utcnow, index=True)


class RefreshToken(Base):
    """Refresh tokens for long-lived sessions."""
    __tablename__ = "refresh_tokens"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    token_hash   = Column(String(64), unique=True, nullable=False)  # SHA-256 of the raw token
    device_info  = Column(String(255), nullable=True)
    ip_address   = Column(String(45), nullable=True)
    user_agent   = Column(String(255), nullable=True)
    is_active    = Column(Boolean, default=True)
    expires_at   = Column(DateTime, nullable=False)
    created_at   = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)


class PasswordResetToken(Base):
    """Password reset tokens."""
    __tablename__ = "password_reset_tokens"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    token_hash   = Column(String(64), unique=True, nullable=False)
    expires_at   = Column(DateTime, nullable=False)
    used_at     = Column(DateTime, nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow)


class Favourite(Base):
    """Bookmarked / starred reports."""
    __tablename__ = "favourites"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    scan_id      = Column(String(36), nullable=False, index=True)
    note         = Column(String(255), nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow)


class ScheduledReport(Base):
    """Scheduled PDF report exports."""
    __tablename__ = "scheduled_reports"
    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, nullable=False, index=True)
    email          = Column(String(255), nullable=False)
    frequency      = Column(String(20), nullable=False)  # daily, weekly
    scan_filter    = Column(String(50), nullable=True)  # verdict filter
    last_sent_at   = Column(DateTime, nullable=True)
    next_send_at   = Column(DateTime, nullable=False)
    is_active      = Column(Boolean, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)


class ShareLink(Base):
    """One-time secure report share links."""
    __tablename__ = "share_links"
    id           = Column(Integer, primary_key=True, index=True)
    scan_id      = Column(String(36), nullable=False, index=True)
    token        = Column(String(64), unique=True, nullable=False, index=True)
    expires_at   = Column(DateTime, nullable=False)
    views_left   = Column(Integer, default=1)
    created_at   = Column(DateTime, default=datetime.utcnow)
    created_by   = Column(Integer, nullable=False)


class BrandingConfig(Base):
    """Company branding for reports."""
    __tablename__ = "branding_config"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    company_name = Column(String(255), nullable=True)
    logo_url     = Column(Text, nullable=True)
    footer_text  = Column(Text, nullable=True)
    primary_color = Column(String(7), default="#06B6D4")
    created_at   = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AppConfig(Base):
    __tablename__ = "app_config"
    id           = Column(Integer, primary_key=True, index=True)
    key          = Column(String(100), unique=True, nullable=False, index=True)
    value        = Column(Text, nullable=True)
    updated_by   = Column(Integer, nullable=True)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(Base):
    """Audit trail for admin actions."""
    __tablename__ = "audit_logs"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    action       = Column(String(50), nullable=False, index=True)  # role_change, user_delete, scan_delete, etc.
    target_type  = Column(String(30), nullable=False)  # user, scan, config
    target_id    = Column(String(36), nullable=True)
    details      = Column(Text, nullable=True)  # JSON with extra info
    ip_address   = Column(String(45), nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow, index=True)


class APIUsage(Base):
    """Track API key usage for quota monitoring."""
    __tablename__ = "api_usage"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, nullable=False, index=True)
    api_key_id   = Column(String(30), nullable=False, index=True)  # virustotal, abuseipdb, etc.
    requests     = Column(Integer, default=0)
    last_reset   = Column(DateTime, default=datetime.utcnow)
    created_at   = Column(DateTime, default=datetime.utcnow)


class ModelFeedback(Base):
    """User feedback for ML model improvement - enables continuous learning."""
    __tablename__ = "model_feedback"
    id              = Column(Integer, primary_key=True, index=True)
    scan_id         = Column(String(50), nullable=False, index=True)
    user_id        = Column(Integer, nullable=False, index=True)
    # User's correction: what they think it should be
    actual_verdict = Column(String(20), nullable=False)  # "phishing", "suspicious", "legitimate"
    # Optional reason
    reason         = Column(String(500), nullable=True)
    # Model's original prediction
    original_prob  = Column(Float, nullable=True)
    # Admin review status
    reviewed      = Column(Boolean, default=False)
    reviewed_by   = Column(Integer, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow, index=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

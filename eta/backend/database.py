from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Boolean, JSON, Text, Index, event, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "eta.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH.as_posix()}")

# Neon/PostgreSQL fix: replace postgres:// with postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

_is_sqlite = "sqlite" in DATABASE_URL
connect_args = {"check_same_thread": False} if _is_sqlite else {}

# SQLite uses StaticPool / NullPool — pool_size and max_overflow are PostgreSQL-only.
if _is_sqlite:
    engine = create_engine(
        DATABASE_URL,
        connect_args=connect_args,
        pool_pre_ping=True,
    )
else:
    engine = create_engine(
        DATABASE_URL,
        connect_args=connect_args,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# WAL mode for SQLite: allows concurrent reads during writes (multi-worker safe)
if _is_sqlite:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, much faster than FULL
        cur.execute("PRAGMA cache_size=-65536")   # 64 MB page cache
        cur.execute("PRAGMA temp_store=MEMORY")
        cur.execute("PRAGMA foreign_keys=ON")     # enforce FK constraints
        cur.close()


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
    user_id      = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
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
    user_id          = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    data_retention_days = Column(Integer, default=30)  # Auto-delete scans older than X days
    allow_analytics  = Column(Boolean, default=False)  # Opt-in analytics tracking
    auto_delete      = Column(Boolean, default=True)   # Enable auto-deletion
    # Explicit consent required before any client data leaves this server (URLs/IPs/hashes → external APIs)
    tier2_consent    = Column(Boolean, default=False)
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


class EmailAccount(Base):
    """IMAP accounts connected by users for auto-fetch scanning."""
    __tablename__ = "email_accounts"
    id             = Column(Integer, primary_key=True, index=True)
    user_id        = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    label          = Column(String(100), nullable=True)
    email_address  = Column(String(255), nullable=False)
    host           = Column(String(255), nullable=False)
    port           = Column(Integer, default=993)
    password_enc   = Column(Text, nullable=False)          # Fernet-encrypted
    folder         = Column(String(100), default="INBOX")
    fetch_limit    = Column(Integer, default=20)
    is_active      = Column(Boolean, default=True)
    last_synced_at = Column(DateTime, nullable=True)
    created_at     = Column(DateTime, default=datetime.utcnow)


class ChatMessage(Base):
    """Support chat messages between users and admins."""
    __tablename__ = "chat_messages"
    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    sender_role = Column(String(10), nullable=False)   # "user" or "admin"
    sender_name = Column(String(100), nullable=True)
    message     = Column(Text, nullable=False)
    topic       = Column(String(50), nullable=True)
    is_read     = Column(Boolean, default=False)
    created_at  = Column(DateTime, default=datetime.utcnow, index=True)


class Notification(Base):
    """Per-user in-app notifications."""
    __tablename__ = "notifications"
    id         = Column(Integer, primary_key=True, index=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    type       = Column(String(20), nullable=False)   # scan | message | settings | system
    title      = Column(String(200), nullable=False)
    body       = Column(String(500), nullable=True)
    link       = Column(String(200), nullable=True)
    is_read    = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


def run_migrations(engine_):
    """Add any columns present in models but missing from the live SQLite schema."""
    if "sqlite" not in str(engine_.url):
        return  # PostgreSQL uses Alembic; skip here
    import sqlite3
    db_path = str(engine_.url).replace("sqlite:///", "")
    conn = sqlite3.connect(db_path)
    try:
        pending = [
            ("privacy_settings", "tier2_consent", "BOOLEAN DEFAULT 0"),
            ("email_accounts", "label", "TEXT"),
            ("email_accounts", "folder", "TEXT DEFAULT 'INBOX'"),
            ("email_accounts", "fetch_limit", "INTEGER DEFAULT 20"),
            ("email_accounts", "last_synced_at", "DATETIME"),
        ]
        for table, col, definition in pending:
            existing = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")
                conn.commit()
    finally:
        conn.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

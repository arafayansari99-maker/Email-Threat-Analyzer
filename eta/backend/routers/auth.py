"""
Authentication router - Registration, login, JWT refresh, 2FA, and session management.
"""
import logging
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address
import pyotp

from database import get_db, User, User2FA, LoginAttempt, RefreshToken

# Import notifications service
from notifications import email_service
from security_middleware import get_client_ip  # canonical implementation

logger = logging.getLogger(__name__)

# ── Rate limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Constants ─────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set. Add it to eta/backend/.env")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60        # 1 hour
REFRESH_TOKEN_EXPIRE_DAYS   = 30        # 30 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
router = APIRouter(prefix="/auth", tags=["auth"])

# ── Helpers ───────────────────────────────────────────────────────────────────
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(64)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    from jose import jwt
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str) -> dict:
    from jose import jwt, JWTError
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = verify_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # Enforce approval check on all protected endpoints
    if not user.is_approved and user.role not in ("admin", "superadmin", "soc_analyst"):
        raise HTTPException(status_code=403, detail="Account pending approval")
    return user


def optional_user(token: Optional[str] = Depends(oauth2_scheme_optional), db: Session = Depends(get_db)) -> Optional[User]:
    """Optional user dependency - returns None if no token provided."""
    if not token:
        return None
    try:
        user = get_current_user(token, db)
        return user
    except HTTPException:
        return None


def check_admin(user: User = Depends(get_current_user)) -> User:
    if user.role not in ("admin", "superadmin", "soc_analyst"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Pydantic models ───────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    is_approved: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


class RefreshTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int  # seconds


class TOTPVerify(BaseModel):
    code: str


class TOTPSetupResponse(BaseModel):
    secret: str          # base32 secret (user must store + register in authenticator app)
    otpauth_url: str     # full otpauth:// URI for QR code scanning
    backup_codes: list[str]  # one-time backup codes (show ONCE, then hide)


class SessionResponse(BaseModel):
    id: int
    device_info: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    last_used_at: Optional[datetime]
    expires_at: datetime


class MessageResponse(BaseModel):
    message: str


# ── Security helpers ───────────────────────────────────────────────────────────
def record_login_attempt(db: Session, email: str, ip: str, request: Request, success: bool):
    db.add(LoginAttempt(
        email=email,
        ip_address=ip,
        user_agent=request.headers.get("user-agent", "")[:255],
        success=success,
    ))
    db.commit()

    # Send failed login notification (after 3 failed attempts)
    if not success:
        user = db.query(User).filter(User.email == email).first()
        if user:
            cutoff = datetime.utcnow() - timedelta(minutes=15)
            failed_count = db.query(LoginAttempt).filter(
                LoginAttempt.email == email,
                ~LoginAttempt.success,
                LoginAttempt.created_at >= cutoff,
            ).count()
            if failed_count >= 3:
                email_service.send_failed_login_alert(
                    user.email, user.username, ip, failed_count
                )


def is_rate_limited(db: Session, email: str, ip: str) -> bool:
    """Block if more than 5 failed attempts in the last 15 minutes."""
    cutoff = datetime.utcnow() - timedelta(minutes=15)
    count = db.query(LoginAttempt).filter(
        LoginAttempt.email == email,
        LoginAttempt.ip_address == ip,
        ~LoginAttempt.success,
        LoginAttempt.created_at >= cutoff,
    ).count()
    return count >= 5


# ── Endpoints ─────────────────────────────────────────────────────────────────

# Check account status without authentication
class CheckStatusRequest(BaseModel):
    email: EmailStr


class CheckStatusResponse(BaseModel):
    status: str
    message: str


@router.post("/check-status", response_model=CheckStatusResponse)
def check_account_status(
    body: CheckStatusRequest,
    db: Session = Depends(get_db),
):
    """Check if an account exists and its approval status."""
    user = db.query(User).filter(User.email == body.email).first()

    if not user:
        # Don't reveal if email exists for security
        return CheckStatusResponse(
            status="unknown",
            message="If an account exists with this email, the status will be shown above."
        )

    if not user.is_active:
        return CheckStatusResponse(
            status="disabled",
            message="Your account has been disabled. Please contact support."
        )

    if user.is_approved or user.role in ("admin", "superadmin", "soc_analyst"):
        return CheckStatusResponse(
            status="approved",
            message="Your account is active and approved. You can now login."
        )

    return CheckStatusResponse(
        status="pending",
        message="Your account is pending approval from an administrator. You'll be notified once approved."
    )


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
def register(request: Request, response: Response, user_data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()

    if existing:
        if existing.username == user_data.username:
            raise HTTPException(status_code=400, detail="Username already taken")
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = get_password_hash(user_data.password)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_pw=hashed_pw,
        role="user",
        is_active=True,
        is_approved=False,
        created_at=datetime.utcnow(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token = create_access_token(data={"sub": str(new_user.id)})
    _set_refresh_cookie(response, new_user, request, db)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(new_user),
    }


def _set_refresh_cookie(response: Response, user: User, request: Request, db: Session):
    """Create a refresh token record and write the httpOnly cookie onto response."""
    raw_token = generate_refresh_token()
    token_hash = hash_token(raw_token)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    ip = get_client_ip(request)
    rt = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        device_info=request.headers.get("user-agent", "")[:255],
        ip_address=ip,
        user_agent=request.headers.get("user-agent", "")[:255],
        is_active=True,
        expires_at=expires_at,
    )
    db.add(rt)
    db.commit()
    response.set_cookie(
        key="eta_refresh_token",
        value=raw_token,
        httponly=True,
        secure=os.environ.get("ENVIRONMENT") == "production",
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/",
    )


@router.post("/login", response_model=Token)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    ip = get_client_ip(request)
    identifier = form_data.username.strip()
    password = form_data.password

    # Brute-force protection: block after 5 failed attempts from same IP+email in 15 min
    if is_rate_limited(db, identifier, ip):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Please wait 15 minutes.")

    # Try to find user by email
    user = db.query(User).filter(User.email == identifier).first()

    # If not found by email, try username
    if not user:
        user = db.query(User).filter(User.username == identifier).first()

    # If still no user - error (removed hardcoded credentials for security)
    if not user:
        record_login_attempt(db, identifier, ip, request, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})

    # Verify password
    if not verify_password(password, user.hashed_pw):
        record_login_attempt(db, identifier, ip, request, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})

    # Check if account is active
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Check if account is approved (admin/superadmin/soc_analyst are auto-approved)
    if not user.is_approved and user.role not in ("admin", "superadmin", "soc_analyst"):
        raise HTTPException(status_code=403, detail="Account pending approval. Please wait for admin to approve your account.")

    record_login_attempt(db, identifier, ip, request, success=True)

    # Send new login notification
    user_agent = request.headers.get("user-agent", "")
    email_service.send_new_login_alert(
        user.email, user.username, ip, user_agent
    )

    # ── 2FA check for admin accounts ─────────────────────────────────────────
    if user.role in ("admin", "superadmin", "soc_analyst"):
        two_fa = db.query(User2FA).filter(User2FA.user_id == user.id, User2FA.is_enabled).first()
        if two_fa:
            # Return a partial token hint so the client knows to ask for 2FA
            partial = create_access_token(
                data={"sub": str(user.id), "pending_2fa": True},
                expires_delta=timedelta(minutes=5),
            )
            return JSONResponse({
                "access_token": partial,
                "token_type": "bearer",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                    "is_active": user.is_active,
                    "is_approved": user.is_approved,
                    "created_at": user.created_at.isoformat(),
                    "_2fa_required": True,   # signal to frontend to show 2FA prompt
                },
            })

    access_token = create_access_token(data={"sub": str(user.id)})
    # Set refresh cookie atomically with login — no separate /sessions call needed
    _set_refresh_cookie(response, user, request, db)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
    }


@router.post("/login/verify-2fa", response_model=Token)
def verify_2fa(
    request: Request,
    body: TOTPVerify,
    db: Session = Depends(get_db),
):
    """Verify TOTP code after a partial admin login."""
    ip = get_client_ip(request)
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization header")

    token = auth_header.split(" ", 1)[1]
    payload = verify_access_token(token)

    if not payload.get("pending_2fa"):
        raise HTTPException(status_code=400, detail="2FA verification not pending")

    user_id = int(payload["sub"])
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    record_login_attempt(db, user.email, ip, request, success=True)

    two_fa = db.query(User2FA).filter(User2FA.user_id == user.id, User2FA.is_enabled).first()
    if not two_fa or not two_fa.secret:
        raise HTTPException(status_code=400, detail="2FA not configured for this user")

    # Support backup codes — codes are stored as SHA-256 hashes, never plaintext
    backup_codes = two_fa.backup_codes or []
    code_hash = hashlib.sha256(body.code.encode()).hexdigest()
    if code_hash in backup_codes:
        backup_codes.remove(code_hash)
        two_fa.backup_codes = backup_codes
        db.commit()
    else:
        # Verify TOTP
        totp = pyotp.TOTP(two_fa.secret)
        if not totp.verify(body.code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid 2FA code")

    access_token = create_access_token(data={"sub": str(user.id)})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
    }


# ── Refresh token ──────────────────────────────────────────────────────────────
@router.post("/refresh", response_model=RefreshTokenResponse)
def refresh_token(
    request: Request,
    db: Session = Depends(get_db),
):
    """Exchange a refresh token for a new access token."""
    cookie_name = "eta_refresh_token"
    raw_token = request.cookies.get(cookie_name)
    if not raw_token:
        raise HTTPException(status_code=401, detail="Missing refresh token cookie")

    token_hash = hash_token(raw_token)
    rt = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.is_active,
    ).first()

    if not rt or rt.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired or revoked")

    # Update last-used
    rt.last_used_at = datetime.utcnow()
    db.commit()

    user = db.query(User).filter(User.id == rt.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    access_token = create_access_token(data={"sub": str(user.id)})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Revoke the current refresh token."""
    cookie_name = "eta_refresh_token"
    raw_token = request.cookies.get(cookie_name)
    if raw_token:
        token_hash = hash_token(raw_token)
        rt = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
        if rt:
            rt.is_active = False
            db.commit()
    response.delete_cookie(cookie_name)
    return Response(status_code=204)


# ── Password helpers ───────────────────────────────────────────────────────────
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ── Profile ────────────────────────────────────────────────────────────────────
@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)


@router.patch("/profile", response_model=UserResponse)
def update_profile(
    updates: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    allowed = ["username", "email"]
    for field in allowed:
        if field in updates:
            setattr(current_user, field, updates[field])
    db.commit()
    db.refresh(current_user)
    return UserResponse.model_validate(current_user)


# ── 2FA management (admin only) ─────────────────────────────────────────────────
@router.post("/2fa/setup", response_model=TOTPSetupResponse)
def setup_2fa(
    request: Request,
    current_user: User = Depends(check_admin),
    db: Session = Depends(get_db),
):
    """Generate a new TOTP secret and backup codes. Does NOT enable 2FA yet."""
    # Generate TOTP secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(name=current_user.email, issuer_name="ETA")

    # Generate backup codes (10 one-time codes)
    raw_codes = [secrets.token_hex(8) for _ in range(10)]
    hashed_codes = [hashlib.sha256(c.encode()).hexdigest() for c in raw_codes]

    two_fa = db.query(User2FA).filter(User2FA.user_id == current_user.id).first()
    if not two_fa:
        two_fa = User2FA(user_id=current_user.id)
        db.add(two_fa)
    two_fa.secret = secret
    two_fa.backup_codes = hashed_codes
    two_fa.is_enabled = False
    db.commit()

    return TOTPSetupResponse(
        secret=secret,
        otpauth_url=otpauth_url,
        backup_codes=raw_codes,   # returned only ONCE, never stored in plaintext
    )


@router.post("/2fa/enable", response_model=dict)
def enable_2fa(
    body: TOTPVerify,
    current_user: User = Depends(check_admin),
    db: Session = Depends(get_db),
):
    """Verify a TOTP code to confirm ownership, then enable 2FA."""
    two_fa = db.query(User2FA).filter(User2FA.user_id == current_user.id).first()
    if not two_fa or not two_fa.secret:
        raise HTTPException(status_code=400, detail="Run 2FA setup first")

    totp = pyotp.TOTP(two_fa.secret)
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    two_fa.is_enabled = True
    db.commit()
    return {"message": "2FA enabled successfully"}


@router.post("/2fa/disable", response_model=dict)
def disable_2fa(
    body: TOTPVerify,
    current_user: User = Depends(check_admin),
    db: Session = Depends(get_db),
):
    """Verify TOTP before disabling 2FA."""
    two_fa = db.query(User2FA).filter(User2FA.user_id == current_user.id).first()
    if not two_fa:
        raise HTTPException(400, "2FA not configured")

    if two_fa.is_enabled:
        totp = pyotp.TOTP(two_fa.secret)
        if not totp.verify(body.code, valid_window=1):
            raise HTTPException(status_code=401, detail="Invalid TOTP code")

    two_fa.is_enabled = False
    two_fa.secret = None
    two_fa.backup_codes = None
    db.commit()
    return {"message": "2FA disabled successfully"}


@router.get("/2fa/status", response_model=dict)
def get_2fa_status(
    current_user: User = Depends(check_admin),
    db: Session = Depends(get_db),
):
    """Return whether 2FA is enabled for the current admin."""
    two_fa = db.query(User2FA).filter(User2FA.user_id == current_user.id).first()
    return {"enabled": two_fa.is_enabled if two_fa else False}


# ── Session management ─────────────────────────────────────────────────────────
@router.post("/sessions", response_model=dict)
def create_session(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new refresh token session (called after login to persist session)."""
    raw_token = generate_refresh_token()
    token_hash = hash_token(raw_token)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    rt = RefreshToken(
        user_id=current_user.id,
        token_hash=token_hash,
        device_info=request.headers.get("user-agent", "")[:255],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", "")[:255],
        is_active=True,
        expires_at=expires_at,
    )
    db.add(rt)
    db.commit()

    # Set HttpOnly cookie
    cookie_name = "eta_refresh_token"
    response.set_cookie(
        key=cookie_name,
        value=raw_token,
        httponly=True,
        secure=os.environ.get("ENVIRONMENT") == "production",
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )
    return {"message": "Session created"}


@router.get("/sessions", response_model=list[SessionResponse])
def list_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all active sessions for the current user."""
    sessions = db.query(RefreshToken).filter(
        RefreshToken.user_id == current_user.id,
        RefreshToken.is_active,
        RefreshToken.expires_at > datetime.utcnow(),
    ).order_by(RefreshToken.last_used_at.desc().nullsfirst(), RefreshToken.created_at.desc()).all()

    return [
        SessionResponse(
            id=s.id,
            device_info=s.device_info,
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            created_at=s.created_at,
            last_used_at=s.last_used_at,
            expires_at=s.expires_at,
        )
        for s in sessions
    ]


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(
    session_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke a specific session."""
    rt = db.query(RefreshToken).filter(
        RefreshToken.id == session_id,
        RefreshToken.user_id == current_user.id,
    ).first()
    if not rt:
        raise HTTPException(status_code=404, detail="Session not found")
    rt.is_active = False
    db.commit()
    return Response(status_code=204)


@router.post("/sessions/revoke-all", status_code=204)
def revoke_all_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke all sessions for the current user."""
    db.query(RefreshToken).filter(
        RefreshToken.user_id == current_user.id,
        RefreshToken.is_active,
    ).update({"is_active": False})
    db.commit()
    return Response(status_code=204)


# ── Password Reset ─────────────────────────────────────────────────────────
class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class PasswordResetResponse(BaseModel):
    email: str
    message: str


@router.post("/password-reset-request", response_model=PasswordResetResponse)
def request_password_reset(
    body: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    """Request a password reset - sends email with reset link."""
    from database import PasswordResetToken

    user = db.query(User).filter(User.email == body.email).first()

    if user:
        # Create reset token
        token = secrets.token_urlsafe(32)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db.add(reset_token)
        db.commit()

        frontend_url = os.environ.get("FRONTEND_URL", "http://localhost:5173")
        reset_url = f"{frontend_url}/reset-password?token={token}"
        try:
            email_service.send_password_reset(
                email=user.email,
                username=user.username,
                reset_url=reset_url,
            )
        except Exception:
            logger.warning("Failed to send password reset email to %s", body.email)

    # Always return success to prevent email enumeration
    return PasswordResetResponse(
        email=body.email,
        message="If an account exists with this email, a password reset link has been sent."
    )


@router.post("/password-reset-confirm", response_model=MessageResponse)
def confirm_password_reset(
    body: PasswordResetConfirm,
    db: Session = Depends(get_db),
):
    """Confirm password reset with token."""
    from database import PasswordResetToken

    # Find valid reset token
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == hash_token(body.token),
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.expires_at > datetime.utcnow(),
    ).first()

    if not reset_token:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # Update password
    user.hashed_pw = get_password_hash(body.new_password)

    # Mark token as used
    reset_token.used_at = datetime.utcnow()

    # Revoke all existing sessions for security
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.is_active,
    ).update({"is_active": False})

    db.commit()

    return MessageResponse(message="Password reset successful. Please login with your new password.")
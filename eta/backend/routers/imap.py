"""IMAP account management and email sync endpoints."""
import os
import base64
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, EmailAccount, Notification
from routers.auth import get_current_user
from imap_fetcher import fetch_unseen_emails, test_connection, resolve_provider, list_folders
from analysis_engine import run_analysis

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/imap", tags=["imap"])


# ── Encryption helpers ────────────────────────────────────────────────────────

def _get_fernet():
    """Return a stable Fernet instance derived from IMAP_ENCRYPT_KEY or JWT_SECRET_KEY."""
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    raw = os.environ.get("IMAP_ENCRYPT_KEY") or os.environ.get("JWT_SECRET_KEY")
    if not raw:
        raise RuntimeError(
            "IMAP_ENCRYPT_KEY (or JWT_SECRET_KEY) must be set to encrypt stored credentials. "
            "Add it to eta/backend/.env before using IMAP features."
        )
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"eta_imap_v1", iterations=100_000)
    key = base64.urlsafe_b64encode(kdf.derive(raw.encode()))
    return Fernet(key)


def _encrypt(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def _decrypt(token: str) -> str:
    return _get_fernet().decrypt(token.encode()).decode()


# ── Schemas ───────────────────────────────────────────────────────────────────

class AccountIn(BaseModel):
    email_address: str
    password: str
    label: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    folder: str = "INBOX"
    fetch_limit: int = 20


class AccountOut(BaseModel):
    id: int
    label: Optional[str]
    email_address: str
    host: str
    port: int
    folder: str
    fetch_limit: int
    is_active: bool
    last_synced_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _account_or_404(account_id: int, user_id: int, db: Session) -> EmailAccount:
    acc = db.query(EmailAccount).filter(
        EmailAccount.id == account_id,
        EmailAccount.user_id == user_id,
    ).first()
    if not acc:
        raise HTTPException(404, "Account not found")
    return acc


def _sync_account(acc: EmailAccount, db: Session) -> dict:
    """Fetch unseen emails for one account, run analysis, return summary."""
    password = _decrypt(acc.password_enc)
    results = []
    errors = []

    try:
        for raw_bytes, msg_id in fetch_unseen_emails(
            acc.host, acc.port, acc.email_address, password,
            folder=acc.folder, limit=acc.fetch_limit,
        ):
            filename = f"imap_{acc.id}_{msg_id[:12]}.eml"
            try:
                result = run_analysis(raw_bytes, filename, tier2_consent=False)
                subject = result.get("meta", {}).get("subject", "").strip()
                result["filename"] = f'IMAP Report: "{subject}"' if subject else f'IMAP Report: Email {msg_id[:8]}'
                # Persist to scan history via the analysis router's _save helper
                from routers.analysis import _save
                _save(db, result, acc.user_id, "imap")
                results.append({
                    "scan_id": result["scan_id"],
                    "verdict": result["verdict"],
                    "risk_score": result["risk_score"],
                    "subject": result.get("meta", {}).get("subject", ""),
                })
            except Exception as exc:
                logger.warning("Analysis failed for msg %s: %s", msg_id, exc)
                errors.append({"msg_id": msg_id, "error": str(exc)})
    except (ValueError, ConnectionError) as exc:
        raise HTTPException(400, str(exc))

    acc.last_synced_at = datetime.utcnow()

    # Notify user
    if results and acc.user_id:
        threats = sum(1 for r in results if r["verdict"] in ("malicious", "suspicious"))
        body = f"Fetched {len(results)} email(s) from {acc.email_address}"
        if threats:
            body += f" — {threats} threat(s) detected"
        db.add(Notification(
            user_id=acc.user_id,
            type="scan",
            title=f"IMAP sync complete — {acc.label or acc.email_address}",
            body=body,
            link="/history",
        ))

    db.commit()
    return {"fetched": len(results), "errors": errors, "results": results}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/accounts", response_model=list[AccountOut])
def list_accounts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return db.query(EmailAccount).filter(
        EmailAccount.user_id == current_user.id,
        EmailAccount.is_active == True,
    ).all()


@router.post("/accounts", response_model=AccountOut, status_code=201)
def add_account(
    body: AccountIn,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    host = body.host or ""
    port = body.port or 993

    # Auto-resolve host from email domain if not provided
    if not host:
        host, port = resolve_provider(body.email_address)
        if not host:
            raise HTTPException(400, "Cannot auto-detect IMAP host. Please provide host and port manually.")

    # Verify credentials before saving
    if not test_connection(host, port, body.email_address, body.password):
        raise HTTPException(400, "IMAP login failed. Check your email, password, and host settings.")

    acc = EmailAccount(
        user_id=current_user.id,
        label=body.label or body.email_address,
        email_address=body.email_address,
        host=host,
        port=port,
        password_enc=_encrypt(body.password),
        folder=body.folder,
        fetch_limit=min(body.fetch_limit, 100),
    )
    db.add(acc)
    db.commit()
    db.refresh(acc)
    logger.info("User %d connected IMAP account %s", current_user.id, body.email_address)
    return acc


@router.delete("/accounts/{account_id}", status_code=204)
def remove_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    acc = _account_or_404(account_id, current_user.id, db)
    acc.is_active = False   # soft-delete
    db.commit()


@router.post("/accounts/{account_id}/sync")
def sync_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    acc = _account_or_404(account_id, current_user.id, db)
    return _sync_account(acc, db)


@router.post("/sync-all")
def sync_all(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    accounts = db.query(EmailAccount).filter(
        EmailAccount.user_id == current_user.id,
        EmailAccount.is_active == True,
    ).all()

    if not accounts:
        return {"message": "No active accounts configured", "synced": 0}

    summary = []
    for acc in accounts:
        try:
            result = _sync_account(acc, db)
            summary.append({"account": acc.email_address, **result})
        except HTTPException as exc:
            summary.append({"account": acc.email_address, "error": exc.detail})
        except Exception as exc:
            logger.error("sync_all failed for account %d: %s", acc.id, exc)
            summary.append({"account": acc.email_address, "error": str(exc)})

    return {"synced": len(accounts), "accounts": summary}


@router.get("/accounts/{account_id}/folders")
def get_folders(
    account_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    acc = _account_or_404(account_id, current_user.id, db)
    password = _decrypt(acc.password_enc)
    folders = list_folders(acc.host, acc.port, acc.email_address, password)
    return {"folders": folders}

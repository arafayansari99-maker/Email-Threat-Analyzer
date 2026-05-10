"""
Settings router — user API key management and dashboard widget order.
Both are persisted to the AppConfig table so they survive server restarts
and work correctly across multiple worker processes.
"""
import json
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

import sys
from pathlib import Path as PathLib
sys.path.insert(0, str(PathLib(__file__).resolve().parent.parent))

from database import get_db, AppConfig
from routers.auth import get_current_user

router = APIRouter(prefix="/settings", tags=["settings"])


# ── helpers ────────────────────────────────────────────────────────────────────

def _cfg_key_for(user_id: int, suffix: str) -> str:
    return f"user:{user_id}:{suffix}"


def _get_config(db: Session, key: str) -> Optional[str]:
    row = db.query(AppConfig).filter(AppConfig.key == key).first()
    return row.value if row else None


def _set_config(db: Session, key: str, value: str, user_id: int) -> None:
    row = db.query(AppConfig).filter(AppConfig.key == key).first()
    if row:
        row.value = value
        row.updated_by = user_id
    else:
        db.add(AppConfig(key=key, value=value, updated_by=user_id))
    db.commit()


# ── API Keys ───────────────────────────────────────────────────────────────────

class ApiKeysRequest(BaseModel):
    keys: dict


class ApiKeysResponse(BaseModel):
    keys: dict


@router.get("/keys", response_model=ApiKeysResponse)
def get_api_keys(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get all saved API keys for the current user."""
    raw = _get_config(db, _cfg_key_for(current_user.id, "api_keys"))
    keys = json.loads(raw) if raw else {}
    return ApiKeysResponse(keys=keys)


@router.post("/keys", response_model=ApiKeysResponse)
def save_api_keys(
    body: ApiKeysRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Save API keys for the current user."""
    _set_config(db, _cfg_key_for(current_user.id, "api_keys"), json.dumps(body.keys), current_user.id)
    return ApiKeysResponse(keys=body.keys)


# API key rate limits (requests per hour)
API_KEY_LIMITS = {
    "virustotal": 200,
    "abuseipdb": 1000,
    "shodan": 100,
    "urlscan": 200,
    "hybrid": 100,
    "alienvault": 100,
    "google": 100,
    "ipdb": 1000,
}


def get_api_key_limits():
    """Get API key rate limits (exposed for admin dashboard)."""
    return API_KEY_LIMITS


# ── Dashboard widget order ─────────────────────────────────────────────────────

DEFAULT_ORDER = ["threat_stats", "verdict_chart", "recent_scans", "quick_analyze", "top_threats", "activity_feed"]


@router.get("/widget-order")
def get_widget_order(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    raw = _get_config(db, _cfg_key_for(current_user.id, "widget_order"))
    order = json.loads(raw) if raw else DEFAULT_ORDER
    return {"order": order}


@router.post("/widget-order")
def save_widget_order(
    body: dict,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    order = body.get("order", DEFAULT_ORDER)
    _set_config(db, _cfg_key_for(current_user.id, "widget_order"), json.dumps(order), current_user.id)
    return {"order": order}

"""
Settings router - User API key management.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

import sys
from pathlib import Path as PathLib
sys.path.insert(0, str(PathLib(__file__).resolve().parent.parent))

from database import get_db
from routers.auth import get_current_user

router = APIRouter(prefix="/settings", tags=["settings"])


class ApiKeysRequest(BaseModel):
    keys: dict  # { "virustotal": "abc123", "ipdb": "xyz789", ... }


class ApiKeysResponse(BaseModel):
    keys: dict


# In-memory API keys store per user (keyed by user_id)
# In production this would be stored in the database encrypted
_user_api_keys: dict = {}


@router.get("/keys", response_model=ApiKeysResponse)
def get_api_keys(current_user=Depends(get_current_user)):
    """Get all saved API keys for the current user."""
    uid = current_user.id
    return ApiKeysResponse(keys=_user_api_keys.get(uid, {}))


@router.post("/keys", response_model=ApiKeysResponse)
def save_api_keys(body: ApiKeysRequest, current_user=Depends(get_current_user)):
    """Save API keys for the current user."""
    uid = current_user.id
    _user_api_keys[uid] = body.keys
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


# ── Dashboard widget order ───────────────────────────────────────────────────
_widget_orders: dict = {}

DEFAULT_ORDER = ["threat_stats", "verdict_chart", "recent_scans", "quick_analyze", "top_threats", "activity_feed"]


@router.get("/widget-order")
def get_widget_order(current_user=Depends(get_current_user)):
    uid = current_user.id
    return {"order": _widget_orders.get(uid, DEFAULT_ORDER)}


@router.post("/widget-order")
def save_widget_order(body: dict, current_user=Depends(get_current_user)):
    uid = current_user.id
    _widget_orders[uid] = body.get("order", DEFAULT_ORDER)
    return {"order": _widget_orders[uid]}
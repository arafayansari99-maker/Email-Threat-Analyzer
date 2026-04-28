"""
Threat Intelligence API router.
Provides endpoints for real-time lookups and manual enrichment of scan results.
"""
import logging
from fastapi import APIRouter, HTTPException, Query, Request, Depends
from pydantic import BaseModel
from typing import Optional

from routers.auth import optional_user

from threat_intel import (
    vt_lookup_url, vt_lookup_hash,
    abuseipdb_lookup, shodan_lookup, hybrid_lookup_hash,
    check_url_against_feeds,
    parse_email_headers,
    analyze_attachment,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])
logger = logging.getLogger(__name__)


# ── URL lookup ─────────────────────────────────────────────────────────────��──
class URLCheckRequest(BaseModel):
    url: str

@router.get("/url")
def lookup_url(url: str = Query(..., description="URL to check against VirusTotal and threat feeds")):
    feed  = check_url_against_feeds(url)
    vt    = vt_lookup_url(url)
    return {**feed, "virustotal": vt}


# ── IP reputation ─────────────────────────────────────────────────────────────
@router.get("/ip")
def lookup_ip(ip: str = Query(..., description="IP address to look up")):
    abuse = abuseipdb_lookup(ip)
    shodan = shodan_lookup(ip)
    return {"abuseipdb": abuse, "shodan": shodan}


# ── File hash lookups ─────────────────────────────────────────────────────────
@router.get("/hash/{hash}")
def lookup_hash(hash: str):
    vt = vt_lookup_hash(hash)
    ha = hybrid_lookup_hash(hash)
    return {"virustotal": vt, "hybrid_analysis": ha}


# ── Email header deep-dive ���───────────────────────────────────────────────────
class HeaderCheckRequest(BaseModel):
    raw_headers: str   # raw header block (RFC2822)

@router.post("/headers")
def analyze_headers(body: HeaderCheckRequest):
    result = parse_email_headers(body.raw_headers.encode())
    if "error" in result and not result.get("flags"):
        raise HTTPException(400, result["error"])
    return result


# ── Attachment sandbox preview ─────────────────────────────────────────────────
class AttachmentCheckRequest(BaseModel):
    filename: str
    base64_content: str   # base64-encoded file content

@router.post("/attachment")
def check_attachment(body: AttachmentCheckRequest):
    import base64
    try:
        raw = base64.b64decode(body.base64_content)
    except Exception as e:
        raise HTTPException(400, f"Invalid base64 content: {e}")
    return analyze_attachment(raw, body.filename)


# ── Enrich an existing scan with fresh threat intel ───────────────────────────
class EnrichRequest(BaseModel):
    urls: Optional[list[str]] = None
    ip:  Optional[str]         = None
    email_from: Optional[str]  = None

@router.post("/enrich")
def enrich_scan(body: EnrichRequest):
    return enrich_with_threat_intel(urls=body.urls, ip=body.ip, email_from=body.email_from)


# ── Batch URL feed check ──────────────────────────────────────────────────────
class BatchURLRequest(BaseModel):
    urls: list[str]

@router.post("/url/batch")
def batch_url_check(body: BatchURLRequest):
    results = []
    for url in (body.urls or [])[:20]:
        try:
            results.append(check_url_against_feeds(url))
        except Exception as e:
            results.append({"url": url, "verdict": "error", "error": str(e)})
    return {"results": results}
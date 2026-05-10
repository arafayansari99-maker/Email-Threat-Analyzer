"""
Threat Intelligence Module.
Provides real-time API lookups (VirusTotal, AbuseIPDB, Shodan, Hybrid Analysis),
email header deep-dive, attachment sandbox preview, and threat-feed URL checks.
"""
import os
import re
import time
import hashlib
import logging
from typing import Optional
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr

logger = logging.getLogger(__name__)

# ── API Keys (from environment) ────────────────────────────────────────────────
VT_API_KEY      = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_API_KEY", "")
SHODAN_KEY      = os.environ.get("SHODAN_API_KEY", "")
HYBRID_KEY      = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
URLSCAN_KEY    = os.environ.get("URLSCAN_API_KEY", "")
HIBP_KEY       = os.environ.get("HIBP_API_KEY", "")

HAS_VT      = bool(VT_API_KEY)
HAS_ABUSE   = bool(ABUSEIPDB_KEY)
HAS_SHODAN  = bool(SHODAN_KEY)
HAS_HYBRID  = bool(HYBRID_KEY)
HAS_URLSCAN = bool(URLSCAN_KEY)
HAS_HIBP    = bool(HIBP_KEY)


# ── HTTP client helper ─────────────────────────────────────────────────────────
# Hard cap: no single external API call may take longer than this.
_DEFAULT_TIMEOUT = 8   # seconds per request
_MAX_TOTAL_BUDGET = 20  # seconds total across all calls in one analysis


def _fetch(url: str, headers: dict, params: dict = None, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    import requests
    try:
        r = requests.get(url, headers=headers, params=params,
                         timeout=(3, timeout))  # (connect, read) timeout tuple
        r.raise_for_status()
        return r.json()
    except requests.Timeout:
        logger.warning("Threat intel request timed out: %s", url)
        return {"error": "timeout"}
    except requests.RequestException as e:
        logger.warning("Threat intel request failed for %s: %s", url, e)
        return {"error": str(e)}


# ── VirusTotal ─────────────────────────────────────────────────────────────────
def vt_lookup_url(url: str) -> dict:
    """Check a URL against VirusTotal."""
    if not HAS_VT:
        return {"available": False, "reason": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    # Step 1: submit URL for scanning
    rid = _fetch("https://www.virustotal.com/api/v3/urls", headers, {"url": url})
    if "error" in rid:
        return {"available": False, "error": rid["error"]}
    analysis_id = rid.get("data", {}).get("id", "")

    # Step 2: poll for result — max 2 attempts, 1 s apart, hard wall-clock cap of 10 s
    deadline = time.monotonic() + 10
    for _ in range(2):
        time.sleep(1)
        if time.monotonic() > deadline:
            break
        result = _fetch(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers, timeout=6)
        if "error" in result:
            return {"available": False, "error": result["error"]}
        attrs = result.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        if any(stats.values()):
            return {
                "available": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "verdict": "malicious" if stats.get("malicious") > 0 else "clean",
                "engines": attrs.get("last_analysis_results", {}),
            }

    return {"available": True, "status": "pending", "malicious": 0, "suspicious": 0}


def vt_lookup_hash(file_hash: str) -> dict:
    """Look up a file hash in VirusTotal."""
    if not HAS_VT:
        return {"available": False, "reason": "VirusTotal API key not configured"}
    headers = {"x-apikey": VT_API_KEY}
    result = _fetch(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers)
    if "error" in result:
        return {"available": False, "error": result["error"]}
    attrs = result.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "available": True,
        "type_description": attrs.get("type_description", "Unknown"),
        "size": attrs.get("size", 0),
        "magic": attrs.get("trid", []),
        "names": attrs.get("names", [])[:5],
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "verdict": "malicious" if stats.get("malicious") > 0 else "clean",
        "tags": attrs.get("tags", [])[:10],
        "first_submission": attrs.get("first_submission_date"),
        "last_analysis": attrs.get("last_analysis_date"),
    }


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
def abuseipdb_lookup(ip: str) -> dict:
    """Look up an IP address in AbuseIPDB for reputation and abuse reports."""
    if not HAS_ABUSE:
        return {"available": False, "reason": "AbuseIPDB API key not configured"}
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    result = _fetch(
        f"https://api.abuseipdb.com/api/v2/check",
        headers,
        {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
    )
    if "error" in result:
        return {"available": False, "error": result["error"]}
    data = result.get("data", {})
    abuse_score = data.get("abuseConfidenceScore", 0)
    return {
        "available": True,
        "ip": data.get("ipAddress"),
        "domain": data.get("domain"),
        "is_whitelisted": data.get("isWhitelisted", False),
        "is_tor": data.get("isTor", False),
        "is_proxy": data.get("isProxy", False),
        "is_vpn": data.get("isVpn", False),
        "is_hosting": data.get("isHostingProvider", False),
        "abuse_score": abuse_score,
        "total_reports": data.get("totalReports", 0),
        "num_distinct_users": data.get("numDistinctUsers", 0),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "verdict": "malicious" if abuse_score >= 50 else "suspicious" if abuse_score >= 25 else "clean",
        "categories": data.get("reports", [])[:3],  # summary only
    }


# ── Shodan ────────────────────────────────────────────────────────────────────
def shodan_lookup(ip: str) -> dict:
    """Look up an IP in Shodan for host info, open ports, vulnerabilities."""
    if not HAS_SHODAN:
        return {"available": False, "reason": "Shodan API key not configured"}
    headers = {"User-Agent": "ETA-EmailThreatAnalyzer/1.0"}
    result = _fetch(f"https://api.shodan.io/shodan/host/{ip}", headers, {"key": SHODAN_KEY})
    if "error" in result:
        return {"available": False, "error": result["error"]}
    vulns = result.get("vulns", {}) or {}
    return {
        "available": True,
        "ip": result.get("ip_str"),
        "org": result.get("org"),
        "isp": result.get("isp"),
        "hostnames": result.get("hostnames", []),
        "country": result.get("country_name"),
        "city": result.get("city"),
        "os": result.get("os"),
        "ports": sorted(result.get("ports", [])),
        "vulnerabilities": list(vulns.keys()),
        "last_update": result.get("last_update"),
        "tags": result.get("tags", []),
    }


# ── Hybrid Analysis ───────────────────────────────────────────────────────────
def hybrid_lookup_hash(file_hash: str) -> dict:
    """Look up a file hash in Hybrid Analysis for sandbox verdict."""
    if not HAS_HYBRID:
        return {"available": False, "reason": "Hybrid Analysis API key not configured"}
    headers = {"api-key": HYBRID_KEY, "User-Agent": "ETA-EmailThreatAnalyzer/1.0"}
    result = _fetch(
        "https://www.hybrid-analysis.com/api/v2/search/hash",
        headers,
        {"hash": file_hash},
    )
    if "error" in result:
        return {"available": False, "error": result["error"]}
    if not isinstance(result, list) or not result:
        return {"available": True, "verdict": "not found", "malicious": 0}

    item = result[0]
    verdict_map = {"malicious": 2, "suspicious": 1, "no-specific-threat": 0, "unknown": -1}
    verdict = item.get("verdict", "unknown")
    return {
        "available": True,
        "verdict": verdict,
        "score": verdict_map.get(verdict, -1),
        "threat_score": item.get("threat_score", 0),
        "vx_family": item.get("vx_family", []),
        "type": item.get("type", "Unknown"),
        "environment": item.get("environment", []),
        "sha256": item.get("sha256", file_hash),
        "file_type": item.get("file_type"),
        "size": item.get("size"),
        "av_malicious": item.get("av_detect", "N/A"),
        "ssdeep": item.get("ssdeep"),
    }


# ── Live Threat Feed Manager ──────────────────────────────────────────────────
import json
import threading
from pathlib import Path

_FEED_CACHE_PATH = Path(__file__).parent / "ml" / "feed_cache.json"
_FEED_LOCK = threading.Lock()

# Feed sources (no API key required)
_OPENPHISH_URL = "https://openphish.com/feed.txt"
_URLHAUS_URL   = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# How long (seconds) before re-fetching each feed
_OPENPHISH_TTL = 43200   # 12 hours
_URLHAUS_TTL   = 3600    # 1 hour
_MAX_FEED_DOMAINS = 50000  # cap to avoid unbounded memory


def _load_feed_cache() -> dict:
    try:
        if _FEED_CACHE_PATH.exists():
            return json.loads(_FEED_CACHE_PATH.read_text())
    except Exception:
        pass
    return {}


def _save_feed_cache(cache: dict) -> None:
    try:
        _FEED_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _FEED_CACHE_PATH.write_text(json.dumps(cache))
    except Exception:
        pass


def _fetch_openphish(now: float) -> dict:
    """Download OpenPhish feed and return {domains: [...], fetched_at: ts}."""
    try:
        resp = requests.get(_OPENPHISH_URL, timeout=10)
        resp.raise_for_status()
        domains = set()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            try:
                from urllib.parse import urlparse
                d = urlparse(line).netloc.lower().split(":")[0]
                if d:
                    domains.add(d)
            except Exception:
                continue
        return {"domains": list(domains)[:_MAX_FEED_DOMAINS], "fetched_at": now}
    except Exception as e:
        logger.warning(f"OpenPhish feed fetch failed: {e}")
        return {}


def _fetch_urlhaus(now: float) -> dict:
    """Download URLhaus recent CSV and return {domains: [...], fetched_at: ts}."""
    try:
        resp = requests.get(_URLHAUS_URL, timeout=15)
        resp.raise_for_status()
        domains = set()
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            url = parts[1].strip().strip('"')
            if not url.startswith("http"):
                continue
            try:
                from urllib.parse import urlparse
                d = urlparse(url).netloc.lower().split(":")[0]
                if d:
                    domains.add(d)
            except Exception:
                continue
        return {"domains": list(domains)[:_MAX_FEED_DOMAINS], "fetched_at": now}
    except Exception as e:
        logger.warning(f"URLhaus feed fetch failed: {e}")
        return {}


def get_live_threat_domains() -> set:
    """
    Return a set of known-malicious domains from cached live feeds.
    Refreshes feeds in the background when their TTL expires.
    Thread-safe; never blocks the caller for more than ~100 ms.
    """
    now = time.time()
    with _FEED_LOCK:
        cache = _load_feed_cache()

        openphish = cache.get("openphish", {})
        urlhaus   = cache.get("urlhaus", {})

        needs_openphish = now - openphish.get("fetched_at", 0) > _OPENPHISH_TTL
        needs_urlhaus   = now - urlhaus.get("fetched_at", 0)   > _URLHAUS_TTL

        if needs_openphish:
            fresh = _fetch_openphish(now)
            if fresh:
                cache["openphish"] = fresh
                openphish = fresh
        if needs_urlhaus:
            fresh = _fetch_urlhaus(now)
            if fresh:
                cache["urlhaus"] = fresh
                urlhaus = fresh

        if needs_openphish or needs_urlhaus:
            _save_feed_cache(cache)

    domains: set = set()
    domains.update(openphish.get("domains", []))
    domains.update(urlhaus.get("domains", []))
    return domains


# ── Static fallback patterns (URL shorteners, suspicious paths) ───────────────
KNOWN_BAD_PATTERNS = [
    r"bit\.ly/\w+", r"tinyurl\.com/\w+", r"goo\.gl/\w+",
    r"t\.co/\w+", r"ow\.ly/\w+", r"is\.gd/\w+", r"buff\.ly/\w+",
    r"rebrand\.ly/\w+", r"short\.io/\w+", r"cutt\.ly/\w+",
    r"dl\.git", r"pastebin\.com", r"anonfile\.com", r"mediafire\.com",
    r"discord\.gg/\w+", r"telegra\.ph/\w+",
]

# Legacy static list — supplemented by live feeds at runtime
KNOWN_BAD_DOMAINS = [
    "malware-check.net", "phishing-site.cc", "evil-redirect.com",
    "credential-harvest.io", "fake-login.org", "suspicious-bank.com",
]
TRUSTED_DOMAINS = {
    "google.com", "google.co.uk", "google.com.au",
    "microsoft.com", "microsoftonline.com",
    "apple.com", "icloud.com",
    "github.com", "github.io",
    "paypal.com", "paypal.co.uk",
    "amazon.com", "amazon.co.uk",
    "bankofamerica.com", "chase.com", "wellsfargo.com",
    "linkedin.com", "twitter.com", "facebook.com",
    "dropbox.com", "box.com",
    "adobe.com", "zoom.us", "slack.com",
}

GOV_TLDS = {".gov", ".gov.uk", ".gov.au", ".gov.br"}
BANK_TLDS = {
    ".bank", ".insurance", ".finance", ".accountant",
    ".tax", ".capital", ".bargains", ".bank",
}


def check_url_against_feeds(url: str) -> dict:
    """
    Check URL against known blocklists, suspicious patterns, and TLD heuristics.
    Returns a verdict with flags and explanations.
    """
    flags = []
    severity = "none"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        tld = "." + domain.rsplit(".", 1)[-1] if domain else ""
    except Exception:
        return {"verdict": "unknown", "flags": ["parse_error"], "severity": "unknown"}

    # Remove port
    domain_clean = domain.split(":")[0]

    # TLD checks
    if tld in BANK_TLDS:
        flags.append({"flag": "unusual_tld_bank", "label": f"Unusual banking TLD ({tld})", "severity": "high"})
    if tld in GOV_TLDS:
        # Gov TLD used in email is usually fine; flag only if combined with other risks
        pass

    # URL shortener check
    for pattern in KNOWN_BAD_PATTERNS:
        if re.search(pattern, url, re.I):
            flags.append({"flag": "url_shortener", "label": f"URL shortener detected ({re.search(pattern, url, re.I).group()})", "severity": "medium"})

    # Short domain check
    if len(domain_clean) < 8 and not any(domain_clean.startswith(tr) for tr in ["mail", "web", "api", "auth"]):
        flags.append({"flag": "very_short_domain", "label": "Domain suspiciously short", "severity": "low"})

    # Hyphen density in domain (common in phishing: secure-bank-login.com)
    hyphens = domain_clean.count("-")
    if hyphens >= 3:
        flags.append({"flag": "excessive_hyphens", "label": f"Excessive hyphens in subdomain ({hyphens})", "severity": "medium"})
    elif hyphens >= 2:
        flags.append({"flag": "multiple_subdomains", "label": "Multiple subdomains may obscure real domain", "severity": "low"})

    # Digit density (secure-1-bank.com)
    digits = sum(c.isdigit() for c in domain_clean)
    if digits > 3:
        flags.append({"flag": "excessive_digits", "label": "Excessive digits in domain", "severity": "medium"})

    # IP address in URL (http://192.168.1.1/login)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_clean):
        flags.append({"flag": "ip_address_url", "label": "URL contains IP address instead of domain", "severity": "high"})

    # Suspicious keywords in path
    path = parsed.path.lower()
    suspicious_path_words = ["login", "signin", "account", "verify", "update", "password", "secure", "banking", "invoice", "payment", "confirm"]
    hit_words = [w for w in suspicious_path_words if w in path and len(path) > len(w) * 2]
    if len(hit_words) >= 2:
        flags.append({"flag": "suspicious_path", "label": f"Suspicious path keywords: {', '.join(hit_words)}", "severity": "high"})

    # Static known-bad domains
    for bad in KNOWN_BAD_DOMAINS:
        if bad in domain_clean:
            flags.append({"flag": "known_bad_domain",
                          "label": f"Domain matches static threat list ({bad})",
                          "severity": "critical"})

    # Live feed check (OpenPhish + URLhaus)
    try:
        live_domains = get_live_threat_domains()
        # Check exact domain and parent domain
        check_variants = {domain_clean}
        parts = domain_clean.rsplit(".", 2)
        if len(parts) >= 2:
            check_variants.add(".".join(parts[-2:]))
        for variant in check_variants:
            if variant in live_domains:
                flags.append({"flag": "live_feed_match",
                              "label": f"Domain found in live threat feed ({variant})",
                              "severity": "critical"})
                break
    except Exception:
        pass

    # Trusted domain whitelist
    is_trusted = any(domain_clean.endswith(f".{td}") or domain_clean == td for td in TRUSTED_DOMAINS)

    # Severity rollup
    sev_map = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev = max(sev_map[f.get("severity", "none")] for f in flags) if flags else 0
    rev_sev = {v: k for k, v in sev_map.items()}
    severity = rev_sev[max_sev]

    if severity in ("high", "critical") or any(f.get("flag") == "known_bad_domain" for f in flags):
        verdict = "malicious"
    elif severity == "medium" or any(f.get("flag") == "url_shortener" for f in flags):
        verdict = "suspicious"
    elif is_trusted:
        verdict = "trusted"
    else:
        verdict = "unknown"

    return {
        "url": url,
        "verdict": verdict,
        "severity": severity,
        "is_trusted": is_trusted,
        "flags": flags,
        "domain": domain_clean,
        "tld": tld,
    }


# ── Email Header Deep-Dive ─────────────────────────────────────────────────────
MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP archive (docx/xlsx/pptx)",
    b"Rar!\x1a\x07": "RAR archive",
    b"\x1f\x8b": "GZIP compressed",
    b"BM": "BMP image",
    b"II\x2a\x00": "TIFF image (little-endian)",
    b"MM\x00\x2a": "TIFF image (big-endian)",
    b"\x00\x00\x01\x00": "ICO file",
    b"\x7fELF": "ELF executable",
    b"MZ": "Windows executable (PE/MZ)",
    b"\xca\xfe\xba\xbe": "Mach-O executable (macOS)",
    b"SQLite format 3": "SQLite database",
    b"\x00\x00\x00\x18": "MP4 video",
    b"\x00\x00\x00\x14": "MP4 video",
    b"\x1e\x2b\x1c": "7-Zip archive",
}

FILE_SIGNATURES = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "GIF": b"GIF87a",
    "PDF": b"%PDF",
    "ZIP": b"PK\x03\x04",
    "RAR": b"Rar!\x1a\x07",
    "BMP": b"BM",
    "TIFF_LE": b"II\x2a\x00",
    "TIFF_BE": b"MM\x00\x2a",
    "ELF": b"\x7fELF",
    "PE": b"MZ",
    "MACH_O": b"\xca\xfe\xba\xbe",
    "SQLITE": b"SQLite format 3",
    "7Z": b"\x1e\x2b\x1c",
}


def detect_magic_bytes(data: bytes) -> dict:
    """Identify file type by magic bytes (first 8 bytes)."""
    results = []
    for sig, name in MAGIC_BYTES.items():
        if data[:len(sig)] == sig:
            results.append({"magic": sig.hex(), "type": name})
    if not results:
        results.append({"magic": data[:8].hex(), "type": "Unknown binary"})
    return {"signatures": results}


def parse_email_headers(raw_content: bytes) -> dict:
    """
    Parse RFC2822 email headers and return structured data with risk flags.
    """
    try:
        msg = message_from_bytes(raw_content)
    except Exception as e:
        return {"error": str(e), "flags": [], "headers": {}}

    flags = []
    all_headers = {}
    raw_header_lines = raw_content.split(b"\n\n")[0].decode("utf-8", errors="replace")

    # Parse individual headers
    for line in raw_header_lines.split("\n"):
        if ": " in line:
            key, val = line.split(": ", 1)
            all_headers[key.strip()] = val.strip()

    def _flag(flag_id: str, label: str, severity: str):
        flags.append({"flag": flag_id, "label": label, "severity": severity})

    # ── Authentication results ────────────────────────────────────────────────
    auth_results = all_headers.get("Authentication-Results", "")
    spf = "pass" if "spf=pass" in auth_results.lower() else "fail" if "spf=fail" in auth_results.lower() else "none"
    dkim = "pass" if "dkim=pass" in auth_results.lower() else "fail" if "dkim=fail" in auth_results.lower() else "none"
    dmarc = "pass" if "dmarc=pass" in auth_results.lower() else "fail" if "dmarc=fail" in auth_results.lower() else "none"

    if spf == "fail":
        _flag("spf_fail", "SPF authentication failed — sender IP not authorised for domain", "high")
    if dkim == "fail":
        _flag("dkim_fail", "DKIM signature invalid — email may be tampered with", "high")
    if dmarc == "fail":
        _flag("dmarc_fail", "DMARC policy violation — email failed domain alignment check", "critical")

    if spf == "none" and dkim == "none":
        _flag("no_auth", "No authentication methods (SPF/DKIM/DMARC) detected", "medium")

    # ── Return-Path vs From ───────────────────────────────────────────────────
    return_path = all_headers.get("Return-Path", "").strip("<>")
    from_addr = parseaddr(all_headers.get("From", ""))[1]
    if return_path and from_addr and return_path.lower() != from_addr.lower():
        domain_fp = return_path.split("@")[1] if "@" in return_path else ""
        domain_from = from_addr.split("@")[1] if "@" in from_addr else ""
        if domain_fp and domain_from and domain_fp.lower() != domain_from.lower():
            _flag("from_return_mismatch", f"Return-Path domain ({domain_fp}) differs from From domain ({domain_from})", "high")

    # ── Received headers — open relay detection ───────────────────────────────
    received_headers = [k for k in all_headers if k.lower().startswith("received")]
    if len(received_headers) > 6:
        _flag("excessive_received", f"Unusually many hops ({len(received_headers)}) — possible open relay", "medium")
    for i, rh_key in enumerate(received_headers[1:], 1):
        rh_val = all_headers.get(rh_key, "")
        # Check for suspicious patterns in Received headers
        if re.search(r"unknown|unknown\.ip|\d+\.\d+\.\d+\.\d+", rh_val, re.I):
            _flag("unresolvable_hop", f"Received header {i} contains unresolvable host", "low")

    # ── X-Originating-IP ─────────────────────────────────────────────────────
    orig_ip = all_headers.get("X-Originating-IP", "")
    if orig_ip:
        ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", orig_ip)
        if ip_match:
            _flag("originating_ip_present", f"Originating IP found: {ip_match.group()}", "low")

    # ── Reply-To mismatch ────────────────────────────────────────────────────
    reply_to = parseaddr(all_headers.get("Reply-To", ""))[1]
    if reply_to and from_addr and reply_to.lower() != from_addr.lower():
        domain_reply = reply_to.split("@")[1] if "@" in reply_to else ""
        domain_from = from_addr.split("@")[1] if "@" in from_addr else ""
        if domain_reply and domain_from and domain_reply.lower() != domain_from.lower():
            _flag("replyto_mismatch", f"Reply-To domain ({domain_reply}) differs from From domain ({domain_from})", "medium")

    # ── User-Agent / X-Mailer ────────────────────────────────────────────────
    user_agent = all_headers.get("User-Agent", "") or all_headers.get("X-Mailer", "") or all_headers.get("X-Mailer", "")
    if user_agent and re.search(r"(script|http|curl|wget|python|perl|ruby)", user_agent, re.I):
        _flag("suspicious_mailer", f"Suspicious mailer identified: {user_agent[:80]}", "medium")

    # ── Content-Type security ────────────────────────────────────────────────
    ct = all_headers.get("Content-Type", "")
    if "multipart" in ct.lower() and "boundary=" in ct.lower():
        _flag("multipart_mixed", "Multipart message — verify all parts are safe", "low")

    # ── Date sanity ──────────────────────────────────────────────────────────
    date_val = all_headers.get("Date", "")
    try:
        from email.utils import parsedate_to_datetime
        msg_dt = parsedate_to_datetime(date_val)
        now_diff = abs((datetime.now() - msg_dt.replace(tzinfo=None)).total_seconds())
        if now_diff > 86400 * 7:  # more than 7 days in past or future
            _flag("suspicious_date", f"Email date unusual ({msg_dt.strftime('%Y-%m-%d %H:%M')})", "low")
    except Exception:
        _flag("invalid_date", "Email Date header is malformed or missing", "low")

    # ── MIME-Version ────────────────────────────────────��────────────────────
    if "MIME-Version" not in all_headers and "multipart" in ct.lower():
        _flag("missing_mime_version", "Missing MIME-Version header on multipart message", "low")

    # ── Message-ID ──────────────────────────────────────────────────────────
    msg_id = all_headers.get("Message-ID", "")
    if msg_id and not re.search(r"<.+@.+>", msg_id):
        _flag("malformed_message_id", "Message-ID is malformed", "medium")

    # ── X-Microsoft-OriginalMessageID ──────────────────────────────────────
    if "X-Microsoft-OriginalMessageID" in all_headers:
        # Internal MS relay — generally trustworthy
        _flag("microsoft_relay", "Message passed through Microsoft internal relay", "low")

    # ── Collect key header summary ────────────────────────────────────────────
    summary = {
        "from": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": all_headers.get("Subject", ""),
        "date": all_headers.get("Date", ""),
        "message_id": msg_id,
        "originating_ip": re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", orig_ip).group() if orig_ip else None,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "received_count": len(received_headers),
        "all_headers": all_headers,
    }

    # Severity rollup
    sev_map = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    max_sev = max((sev_map[f.get("severity", "none")] for f in flags), default=0)
    rev_sev = {v: k for k, v in sev_map.items()}
    severity = rev_sev[max_sev]

    return {
        "summary": summary,
        "flags": flags,
        "severity": severity,
        "risk_score_contribution": max_sev * 10,  # 0–40 pts
    }


# ── Attachment Sandbox Preview ────────────────────────────────────────────────
def analyze_attachment(raw_bytes: bytes, filename: str) -> dict:
    """
    Compute hash, detect magic bytes, extract strings, and classify file type.
    """
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    sha1   = hashlib.sha1(raw_bytes).hexdigest()
    md5    = hashlib.md5(raw_bytes).hexdigest()
    size   = len(raw_bytes)

    magic_info = detect_magic_bytes(raw_bytes[:8])

    # File extension mismatch vs magic bytes
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    ext_to_magic = {
        "pdf": "PDF document", "png": "PNG image", "jpg": "JPEG image",
        "jpeg": "JPEG image", "gif": "GIF image", "zip": "ZIP archive (docx/xlsx/pptx)",
        "exe": "Windows executable (PE/MZ)", "docx": "ZIP archive (docx/xlsx/pptx)",
        "xlsx": "ZIP archive (docx/xlsx/pptx)", "pptx": "ZIP archive (docx/xlsx/pptx)",
        "txt": "Unknown binary",
    }
    expected_type = ext_to_magic.get(ext, "")
    actual_type = magic_info["signatures"][0]["type"]
    type_mismatch = expected_type and actual_type != "Unknown binary" and expected_type != actual_type

    # Suspicious strings (command strings, URLs, IPs in binary)
    suspicious_strings = []
    try:
        ascii_str = raw_bytes.decode("latin-1")
        patterns = [
            (r"https?://[^\s]{10,100}", "url"),
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "ip"),
            (r"powershell\s", "cmd"),
            (r"cmd\.exe\s", "cmd"),
            (r"mshta\s", "cmd"),
            (r"wscript\s", "cmd"),
            (r"curl\s.*-", "cmd"),
            (r"wget\s", "cmd"),
            (r"bash\s", "cmd"),
            (r"sh\s-c\s", "cmd"),
            (r"certutil\s", "cmd"),
            (r"regsvr32\s", "cmd"),
            (r"rundll32\s", "cmd"),
        ]
        for pat, kind in patterns:
            for m in re.finditer(pat, ascii_str, re.I):
                suspicious_strings.append({"kind": kind, "match": m.group()[:80]})
    except Exception:
        pass

    # PE-specific checks
    pe_flags = []
    if actual_type == "Windows executable (PE/MZ)":
        if raw_bytes[0x18:0x1C] == b"\x4D\x5A":  # MZ header present
            pe_flags.append("MZ header valid")
        # Check for UPX (common packer)
        if b"UPX0" in raw_bytes[:512]:
            pe_flags.append("UPX packed — may be obfuscated")
        # Check for embedded VBS
        if b"CreateObject" in raw_bytes[:4096] or b"WScript.Shell" in raw_bytes[:4096]:
            pe_flags.append("VBScript/JScript embedded")

    # Hash lookup results (deferred — shown as available/not)
    vt_info   = vt_lookup_hash(sha256)   if HAS_VT      else {"available": False, "reason": "VT not configured"}
    ha_info   = hybrid_lookup_hash(sha256) if HAS_HYBRID else {"available": False, "reason": "Hybrid Analysis not configured"}

    return {
        "filename": filename,
        "size_bytes": size,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "detected_type": actual_type,
        "magic_signatures": magic_info["signatures"],
        "type_mismatch": type_mismatch,
        "expected_type_from_ext": expected_type,
        "suspicious_strings": suspicious_strings[:20],
        "pe_flags": pe_flags,
        "virustotal": vt_info,
        "hybrid_analysis": ha_info,
    }


# ── URLScan.io (Free 5/day) ──────────────────────────────────────────────
def urlscan_lookup(url: str) -> dict:
    """
    Check URL using urlscan.io (free tier: 5 scans/day).
    Returns screenshots and analysis results.
    """
    if not HAS_URLSCAN:
        return {"available": False, "reason": "URLScan API key not configured"}

    headers = {"Content-Type": "application/json", "API-Key": URLSCAN_KEY}
    data = {"url": url, "method": "get"}

    try:
        import requests
        # Submit URL for scanning
        r = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=60)
        if r.status_code == 200:
            result = r.json()
            api = result.get("api", "")
            # Poll for results
            time.sleep(3)  # Wait for scan to complete
            if api:
                get_r = requests.get(api, headers={"API-Key": URLSCAN_KEY}, timeout=30)
                if get_r.status_code == 200:
                    data = get_r.json()
                    return {
                        "available": True,
                        "verdict": data.get("verdict", "clean"),
                        "page_title": data.get("page", {}).get("title"),
                        "server": data.get("page", {}).get("server"),
                        "domain": data.get("page", {}).get("domain"),
                        "screenshot": data.get("screenshot", ""),
                        "cookies": data.get("cookies", []),
                        "links": len(data.get("links", [])),
                    }
        return {"available": True, "verdict": "error", "error": r.text[:100]}
    except Exception as e:
        return {"available": True, "error": str(e)[:100]}


# ── HaveIBeenPwned (Free 1/day for email, unlimited for hash) ────
def hibp_check_email(email: str) -> dict:
    """
    Check if email has been in data breaches using HaveIBeenPwned.
    Free tier: 1 search/day.
    """
    if not HAS_HIBP:
        return {"available": False, "reason": "HaveIBeenPwned API key not configured"}

    import requests
    headers = {"hibp-api-key": HIBP_KEY, "user-agent": "ETA-Threat-Analyzer"}

    try:
        # Check email breaches
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            params={"truncateResponse": "false"},
            timeout=15
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "available": True,
                "breached": True,
                "breach_count": len(breaches),
                "breaches": [{"name": b.get("Name"), "date": b.get("BreachDate")} for b in breaches[:10]],
            }
        elif r.status_code == 404:
            return {"available": True, "breached": False, "breach_count": 0}
        return {"available": True, "error": f"status {r.status_code}"}
    except Exception as e:
        return {"available": True, "error": str(e)[:100]}


def hibp_check_password(password: str) -> dict:
    """
    Check password hash using HaveIBeenPwned (k-Anonymity).
    Free: unlimited using k-anonymity (only sends first 5 chars of SHA1).
    """
    # Hash the password
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        import requests
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10
        )
        if r.status_code == 200:
            for line in r.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return {
                        "available": True,
                        "compromised": True,
                        "occurrences": int(count),
                    }
            return {"available": True, "compromised": False, "occurrences": 0}
        return {"available": True, "error": f"status {r.status_code}"}
    except Exception as e:
        return {"available": True, "error": str(e)[:50]}


def _score_vt_url(vt: dict) -> int:
    """Score a VirusTotal URL lookup result, 0-100."""
    if not vt.get("available"):
        return 0
    mal = vt.get("malicious", 0)
    sus = vt.get("suspicious", 0)
    total = vt.get("total", 0)
    if mal > 0:
        ratio = mal / max(total, 1)
        return int(60 + ratio * 40)  # 60–100 based on proportion
    if sus > 0:
        ratio = sus / max(total, 1)
        return int(30 + ratio * 30)  # 30–60
    return 0  # clean


def _score_abuseipdb(ab: dict) -> int:
    """Score an AbuseIPDB lookup result, 0–100."""
    if not ab.get("available"):
        return 0
    score = ab.get("abuse_score", 0)
    # country / isp / tor / vpn are supplementary context
    tor   = ab.get("is_tor", False)
    vpn   = ab.get("is_vpn", False)
    hosting = ab.get("is_hosting", False)
    if tor or hosting:
        score = max(score, 60)
    if vpn:
        score = max(score, 40)
    return min(100, score)


def enrich_ioc_scores(urls: list, ip: str = None, sender_domain: str = None) -> dict:
    """
    Run live threat-intel lookups and return structured per-IOC scores.

    Each returned dict contains:
      - score       : 0–100 (higher = more dangerous)
      - tier        : "critical" | "high" | "medium" | "low" | "none"
      - label       : human-readable summary of the signal
      - sources     : list of sources that contributed (e.g. ["VirusTotal","AbuseIPDB"])

    When no APIs are configured, all scores default to 0 and label describes
    the local-only signal that *would* have been checked.
    """
    result = {
        "urls":    [],
        "ip":      None,
        "domain":  None,
    }

    # ── URL scoring ───────────────────────────────────────────────────────────
    for url in (urls or [])[:8]:
        entry: dict = {
            "url":     url,
            "score":   0,
            "tier":    "none",
            "label":   "clean",
            "sources": [],
        }

        # 1. Local feed check
        try:
            feed = check_url_against_feeds(url)
            if feed.get("verdict") == "malicious":
                entry["score"] = max(entry["score"], 75)
                entry["tier"]   = "critical"
                entry["label"]  = f"Listed in threat feed ({feed.get('flags', [{}])[0].get('flag','?')})"
                entry["sources"].append("OpenPhish/URLhaus")
            elif feed.get("verdict") == "suspicious":
                sev = feed.get("severity", "medium")
                entry["score"] = max(entry["score"], {"high": 60, "medium": 40, "low": 20}.get(sev, 30))
                entry["tier"]   = "medium"
                entry["label"]  = f"Suspicious URL pattern: {feed.get('flags', [{}])[0].get('label','?')}"
                entry["sources"].append("LocalHeuristics")
        except Exception:
            pass

        # 2. VirusTotal
        try:
            vt = vt_lookup_url(url)
            if vt.get("available"):
                entry["sources"].append("VirusTotal")
                s = _score_vt_url(vt)
                entry["score"] = max(entry["score"], s)
                if s >= 80:
                    entry["tier"] = "critical"
                    entry["label"] = f"VirusTotal: {vt.get('malicious',0)}/{vt.get('total',0)} engines flag malicious"
                elif s >= 60:
                    entry["tier"] = "high"
                    entry["label"] = f"VirusTotal: {vt.get('malicious',0)} malicious, {vt.get('suspicious',0)} suspicious"
                elif s >= 30:
                    if entry["tier"] not in ("critical", "high"):
                        entry["tier"] = "medium"
                        entry["label"] = f"VirusTotal: {vt.get('suspicious',0)} suspicious flags"
        except Exception:
            pass

        # Cap and normalise
        entry["score"] = min(100, entry["score"])
        result["urls"].append(entry)

    # ── IP scoring ────────────────────────────────────────────────────────────
    if ip:
        entry: dict = {
            "ip":      ip,
            "score":   0,
            "tier":    "none",
            "label":   "no threat intelligence signal",
            "sources": [],
        }
        # Private IP is always a threat signal (internal infrastructure)
        import re as _re
        if _re.match(r"^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)", ip):
            entry["score"] = 90
            entry["tier"]   = "high"
            entry["label"]  = "Private/reserved IP address — not a public relay"
            entry["sources"].append("LocalHeuristics")
        else:
            try:
                ab = abuseipdb_lookup(ip)
                if ab.get("available"):
                    entry["sources"].append("AbuseIPDB")
                    s = _score_abuseipdb(ab)
                    entry["score"] = max(entry["score"], s)
                    if s >= 70:
                        entry["tier"] = "critical"
                        entry["label"] = f"AbuseIPDB: abuse score {s}, {ab.get('total_reports',0)} reports"
                    elif s >= 40:
                        entry["tier"] = "high"
                        entry["label"] = f"AbuseIPDB: abuse score {s}"
                    elif s > 0:
                        entry["tier"] = "low"
                        entry["label"] = f"AbuseIPDB: minimal concern (score {s})"
            except Exception:
                pass

            try:
                sh = shodan_lookup(ip)
                if sh.get("available"):
                    entry["sources"].append("Shodan")
                    vulns = len(sh.get("vulnerabilities", []))
                    if vulns > 0:
                        entry["score"] = max(entry["score"], min(100, 50 + vulns * 5))
                        entry["tier"]   = "high"
                        entry["label"]  = f"Shodan: {vulns} known vulnerabilities on this host"
                    entry["score"] = max(entry["score"], 20)
                    if entry["tier"] == "none":
                        entry["tier"]   = "low"
                        entry["label"]  = "Shodan: host present in Shodan database (no known vulns)"
            except Exception:
                pass

        result["ip"] = entry

    # ── Domain scoring ─────────────────────────────────────────────────────────
    if sender_domain:
        entry: dict = {
            "domain":  sender_domain,
            "score":   0,
            "tier":    "none",
            "label":   "no threat intelligence signal",
            "sources": [],
        }
        _KNOWN_SAFE_DOMAINS = {
            "google.com","accounts.google.com","github.com","microsoft.com",
            "live.com","outlook.com","apple.com","amazon.com","paypal.com",
            "stripe.com","shopify.com","slack.com","zoom.us","dropbox.com",
            "linkedin.com","twitter.com","x.com","facebook.com","instagram.com",
        }
        if any(sender_domain.endswith("." + d) or sender_domain == d for d in _KNOWN_SAFE_DOMAINS):
            entry["score"] = 0
            entry["tier"]   = "none"
            entry["label"]  = "Trusted domain (no signal)"
        else:
            try:
                ab = abuseipdb_lookup(sender_domain)
                if ab.get("available"):
                    entry["sources"].append("AbuseIPDB")
                    s = _score_abuseipdb(ab)
                    entry["score"] = max(entry["score"], s)
                    if s >= 60:
                        entry["tier"]  = "high"
                        entry["label"] = f"AbuseIPDB: domain has abuse confidence {s}%"
                    elif s > 0:
                        entry["tier"]  = "low"
                        entry["label"] = f"AbuseIPDB: domain appears in reports (score {s})"
            except Exception:
                pass

        result["domain"] = entry

    return result


def enrich_with_threat_intel(urls=None, ip=None, email_from=None):
    """
    Run all available threat intel lookups for the given indicators.
    Call this from the analysis engine after header parsing.
    """
    results = {
        "available": [],
        "urls": [],
        "ip_reputation": None,
        "sender_domain_reputation": None,
    }

    if HAS_VT:      results["available"].append("VirusTotal")
    if HAS_ABUSE:   results["available"].append("AbuseIPDB")
    if HAS_SHODAN:  results["available"].append("Shodan")
    if HAS_HYBRID:  results["available"].append("Hybrid Analysis")
    if HAS_URLSCAN:  results["available"].append("URLScan.io")
    if HAS_HIBP:    results["available"].append("HaveIBeenPwned")

    # URL lookups
    if urls:
        for u in urls[:5]:  # cap at 5 URLs
            try:
                feed = check_url_against_feeds(u)
                vt   = vt_lookup_url(u) if HAS_VT else {"available": False}
                feed["virustotal"] = vt
                results["urls"].append(feed)
            except Exception as e:
                logger.warning(f"URL intel error for {u}: {e}")

    # IP reputation
    if ip:
        try:
            results["ip_reputation"] = {
                "abuseipdb": abuseipdb_lookup(ip) if HAS_ABUSE else {"available": False},
                "shodan": shodan_lookup(ip) if HAS_SHODAN else {"available": False},
            }
        except Exception as e:
            logger.warning(f"IP intel error for {ip}: {e}")

    # Sender domain reputation
    if email_from and "@" in email_from:
        domain = email_from.split("@")[1].lower()
        if domain:
            try:
                results["sender_domain_reputation"] = {
                    "abuseipdb": abuseipdb_lookup(domain) if HAS_ABUSE else {"available": False},
                }
            except Exception as e:
                logger.warning(f"Domain intel error for {domain}: {e}")

    return results
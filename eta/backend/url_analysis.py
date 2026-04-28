"""
URL Analysis Module
URL extraction, TLD checking, URL shortener detection, lookalike detection.
"""
import re
import logging
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# === Constants ===

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".buzz", ".work", ".zip", ".download", ".online", ".site", ".store", ".business",
    ".info", ".biz", ".rest", ".icu", ".su", ".racing", ".live", ".chat",
    ".party", ".cricket", ".win", ".gift", ".cash", ".money", ".tools", ".host",
    ".rocks", ".digital", ".email", ".software", ".network", ".pro", ".tech", ".io",
    ".ai", ".app"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl", "short.to", "rb.gy",
    "cutt.ly", "is.gd", "buff.ly", "tiny.cc", "sho.rt", "v.gd", "tr.im",
    "lnk.in", "j.mp", "tinyurl.org", "u.to", "vurl.bz", "migre.me", "twurl.nl",
    "snipurl.com", "s2l.asia", "s7y.me", "u6l.net", "q.gs", "gfycat.com",
    "dlvr.it", "linkbee.io", "linktr.ee", "lnk.co", "rebrand.ly", "bl.ink"
}

# URL regex patterns
URL_RE = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s<>"{}|\\^`\[\]]*)?',
    re.I
)

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

PRIVATE_IP_RE = re.compile(
    r'^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)'
)

# Lookalike domains
LOOKALIKE_MAP = {
    "paypal": ["paypa1", "paypall", "paypal-secure", "paypa-l", "paypa1login", "paypallogin"],
    "microsoft": ["micros0ft", "m1crosoft", "microsofft", "micro-s0ft", "microsft"],
    "amazon": ["amaz0n", "amzon", "amazon-secure", "amazn", "amaz0n-secure"],
    "apple": ["app1e", "appl3", "apple-id-secure", "app1e-id", "appl3.com"],
    "google": ["g00gle", "goog1e", "googIe", "googl3", "g00gl3", "googie"],
    "netflix": ["netfl1x", "netfix", "netflix-billing", "netfl1x", "netflix-secure"],
    "facebook": ["faceb00k", "facebok", "facebook-login", "faceb00k.com"],
    "linkedin": ["linkedln", "linkedin-login", "l1nkedin", "link3din"],
    "chase": ["chas3", "chase-bank", "chase-secure", "chas3.com"],
    "wellsfargo": ["wellsfar9o", "wellsfargo-bank", "wellsfar9o.com"],
    "bankofamerica": ["bankofamer1ca", "b0a", "bankofamer1ca.com"],
}


# === Functions ===

def extract_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    urls = URL_RE.findall(text)
    href = re.findall(r'href=["\']([^"\']+)["\']', text, re.I)
    return list({u for u in urls + href if u.startswith("http")})


def get_domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def get_tld(url: str) -> str:
    """Get TLD from URL."""
    domain = get_domain_from_url(url)
    if '.' in domain:
        return '.' + domain.split('.')[-1]
    return ""


def is_suspicious_tld(url: str) -> bool:
    """Check if URL has suspicious TLD."""
    tld = get_tld(url)
    return tld in SUSPICIOUS_TLDS


def is_url_shortener(url: str) -> bool:
    """Check if URL is a known URL shortener."""
    domain = get_domain_from_url(url)
    return domain in URL_SHORTENERS


def has_ip_in_url(url: str) -> bool:
    """Check if URL contains IP address."""
    return bool(IP_RE.match(url))


def has_private_ip(url: str) -> bool:
    """Check if URL contains private IP address."""
    domain = get_domain_from_url(url)
    return bool(PRIVATE_IP_RE.match(domain))


def count_subdomains(url: str) -> int:
    """Count subdomains in URL."""
    domain = get_domain_from_url(url)
    parts = domain.split('.')
    return max(0, len(parts) - 2)


def check_lookalike(url: str) -> Dict[str, bool]:
    """Check for lookalike domain attacks."""
    domain = get_domain_from_url(url)
    domain_lower = domain.lower()

    result = {
        "is_lookalike": False,
        "brand": None,
        "matched_pattern": None,
    }

    for brand, patterns in LOOKALIKE_MAP.items():
        for pattern in patterns:
            if pattern in domain_lower and brand not in domain_lower:
                result["is_lookalike"] = True
                result["brand"] = brand
                result["matched_pattern"] = pattern
                return result

    return result


def analyze_single_url(url: str) -> Dict[str, Any]:
    """Analyze a single URL for phishing indicators."""
    result = {
        "url": url,
        "domain": get_domain_from_url(url),
        "tld": get_tld(url),
        "suspicious_tld": is_suspicious_tld(url),
        "url_shortener": is_url_shortener(url),
        "has_ip": has_ip_in_url(url),
        "private_ip": has_private_ip(url),
        "subdomain_count": count_subdomains(url),
        "url_length": len(url),
        "lookalike": {},
        "risk_score": 0.0,
    }

    # Lookalike check
    lookalike_result = check_lookalike(url)
    result["lookalike"] = lookalike_result
    result["is_lookalike"] = lookalike_result["is_lookalike"]

    # Calculate risk score
    risk = 0.0
    if result["suspicious_tld"]:
        risk += 0.3
    if result["url_shortener"]:
        risk += 0.2
    if result["has_ip"]:
        risk += 0.2
    if result["is_lookalike"]:
        risk += 0.5
    if result["subdomain_count"] > 2:
        risk += 0.1
    if result["url_length"] > 200:
        risk += 0.1

    result["risk_score"] = min(1.0, risk)

    return result


def analyze_urls(urls: List[str]) -> Dict[str, Any]:
    """Analyze multiple URLs for phishing indicators."""
    if not urls:
        return {
            "url_count": 0,
            "suspicious_urls": [],
            "shortener_urls": [],
            "lookalike_urls": [],
            "ip_urls": [],
            "total_risk_score": 0.0,
        }

    results = []
    suspicious_urls = []
    shortener_urls = []
    lookalike_urls = []
    ip_urls = []
    total_risk = 0.0

    for url in urls[:60]:  # Limit to 60 URLs
        analysis = analyze_single_url(url)
        results.append(analysis)

        if analysis["suspicious_tld"]:
            suspicious_urls.append(url)
        if analysis["url_shortener"]:
            shortener_urls.append(url)
        if analysis["is_lookalike"]:
            lookalike_urls.append(url)
        if analysis["has_ip"]:
            ip_urls.append(url)

        total_risk += analysis["risk_score"]

    return {
        "urls": results,
        "url_count": len(urls),
        "suspicious_urls": suspicious_urls,
        "suspicious_count": len(suspicious_urls),
        "shortener_urls": shortener_urls,
        "shortener_count": len(shortener_urls),
        "lookalike_urls": lookalike_urls,
        "lookalike_count": len(lookalike_urls),
        "ip_urls": ip_urls,
        "ip_count": len(ip_urls),
        "total_risk_score": min(1.0, total_risk / max(1, len(urls))),
    }


def _entropy(s: str) -> float:
    """Calculate Shannon entropy of string."""
    if not s:
        return 0.0

    from collections import Counter
    counts = Counter(s)
    length = len(s)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * (p.bit_length() - 1)

    return entropy


__all__ = [
    'extract_urls',
    'get_domain_from_url',
    'get_tld',
    'is_suspicious_tld',
    'is_url_shortener',
    'has_ip_in_url',
    'has_private_ip',
    'count_subdomains',
    'check_lookalike',
    'analyze_single_url',
    'analyze_urls',
    '_entropy',
]
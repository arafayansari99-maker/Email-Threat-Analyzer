"""
Risk Scoring Module
Weighted risk scoring combining all analysis results.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# === Weights ===
WEIGHTS = {
    # ML/Classification
    "ml_weight": 0.30,
    "url_weight": 0.25,
    "header_weight": 0.20,
    "attachment_weight": 0.15,
    "content_weight": 0.10,
}


def calculate_risk(
    ml_result: Dict[str, Any],
    url_result: Dict[str, Any],
    header_result: Dict[str, Any],
    attachment_result: Dict[str, Any],
    content_features: Dict[str, Any]
) -> Dict[str, Any]:
    """Calculate overall risk score from all components."""

    # ML score (0-1)
    ml_score = ml_result.get("phishing_prob", 0.5)

    # URL score (0-1)
    url_score = url_result.get("total_risk_score", 0.0)
    if url_result.get("suspicious_count", 0) > 0:
        url_score += 0.2
    if url_result.get("lookalike_count", 0) > 0:
        url_score += 0.3
    url_score = min(1.0, url_score)

    # Header score (0-1)
    header_score = 0.0
    auth = header_result.get("authentication", {})
    if auth.get("overall_auth") == "none":
        header_score = 0.8
    elif auth.get("overall_auth") == "weak":
        header_score = 0.5
    elif auth.get("overall_auth") == "moderate":
        header_score = 0.2
    elif auth.get("overall_auth") == "strong":
        header_score = 0.1

    rep = header_result.get("domain_reputation", {})
    if rep.get("suspicious_tld"):
        header_score += 0.3
    if rep.get("free_email") and rep.get("risk_indicators"):
        header_score += 0.2

    if header_result.get("domain_mismatch"):
        header_score += 0.3
    header_score = min(1.0, header_score)

    # Attachment score (0-1)
    attach_score = 0.0
    if attachment_result.get("malicious_count", 0) > 0:
        attach_score = 1.0
    elif attachment_result.get("risky_count", 0) > 0:
        attach_score = 0.6
    elif attachment_result.get("suspicious_count", 0) > 0:
        attach_score = 0.3

    # Content score (0-1)
    content_score = 0.0
    content_flags = content_features.get("red_flags", [])
    content_score = min(1.0, len(content_flags) * 0.2)

    # Add urgency keywords
    if content_features.get("has_urgency"):
        content_score += 0.3
    if content_features.get("has_credential_keywords"):
        content_score += 0.2

    content_score = min(1.0, content_score)

    # Weighted total
    total_score = (
        ml_score * WEIGHTS["ml_weight"] +
        url_score * WEIGHTS["url_weight"] +
        header_score * WEIGHTS["header_weight"] +
        attach_score * WEIGHTS["attachment_weight"] +
        content_score * WEIGHTS["content_weight"]
    )

    # Determine verdict
    if total_score >= 0.7:
        verdict = "phishing"
    elif total_score >= 0.4:
        verdict = "suspicious"
    elif total_score >= 0.2:
        verdict = "legitimate"
    else:
        verdict = "safe"

    return {
        "risk_score": round(total_score, 3),
        "verdict": verdict,
        "components": {
            "ml_score": round(ml_score, 3),
            "url_score": round(url_score, 3),
            "header_score": round(header_score, 3),
            "attachment_score": round(attach_score, 3),
            "content_score": round(content_score, 3),
        },
        "weights": WEIGHTS,
        "confidence": round(1.0 - abs(total_score - 0.5) * 2, 3),
    }


def get_risk_level(risk_score: float) -> str:
    """Get risk level string."""
    if risk_score >= 0.7:
        return "HIGH"
    elif risk_score >= 0.4:
        return "MEDIUM"
    elif risk_score >= 0.2:
        return "LOW"
    return "NONE"


def get_risk_color(risk_score: float) -> str:
    """Get risk color for UI."""
    if risk_score >= 0.7:
        return "#ef4444"  # red
    elif risk_score >= 0.4:
        return "#f59e0b"  # yellow
    elif risk_score >= 0.2:
        return "#3b82f6"  # blue
    return "#22c55e"  # green


__all__ = [
    'calculate_risk',
    'get_risk_level',
    'get_risk_color',
    'WEIGHTS',
]
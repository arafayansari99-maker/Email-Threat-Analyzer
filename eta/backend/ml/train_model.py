#!/usr/bin/env python3
"""
ETA Email Threat Analyzer – XGBoost Phishing Model Trainer (v4.0)

Problems fixed vs. v3:
  1. domain_entropy dominated 27% of predictions (trained on 2002 random-domain spam).
     Fix: inject modern brand-impersonation phishing with LOW-entropy readable domains.
  2. any_lookalike / popular_brands / gift_scam had near-zero importance.
     Fix: balanced synthetic data + scale_pos_weight tuning forces the model to learn
     these signals.
  3. Missing training / inference consistency.
     Fix: extract_ml_features() from analysis_engine is imported directly so both
     paths use identical feature extraction code.

Run from eta/backend/:
    python ml/train_model.py
"""

import os
import sys
import json
import random
import logging
from datetime import datetime, timezone

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("train_model")

# ── Path setup ─────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))      # .../ml/
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)                      # .../backend/
DATA_DIR    = os.path.join(SCRIPT_DIR, "data")
PHISH_DIR   = os.path.join(DATA_DIR, "phishing")
HAM_DIR     = os.path.join(DATA_DIR, "ham")

sys.path.insert(0, BACKEND_DIR)

# ── Import feature extractor from analysis_engine ──────────────────────────────
try:
    from analysis_engine import (
        extract_ml_features, FEATURE_NAMES, _N_FEATURES,
        LOOKALIKE_MAP, URGENCY_WORDS, CREDENTIAL_KEYWORDS, BEC_KEYWORDS,
    )
    logger.info(f"Imported extract_ml_features (N={_N_FEATURES} features)")
except ImportError as exc:
    logger.error(f"Cannot import analysis_engine: {exc}")
    sys.exit(1)

# ── ML dependencies ────────────────────────────────────────────────────────────
try:
    import xgboost as xgb
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.metrics import (
        roc_auc_score, precision_score, recall_score, f1_score,
        precision_recall_curve,
    )
    import joblib
except ImportError as exc:
    logger.error(f"Missing dependency: {exc}  — run: pip install xgboost scikit-learn joblib")
    sys.exit(1)

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ── Email parser ───────────────────────────────────────────────────────────────
import email as _email_lib
import email.policy
import re

_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)


def _parse_auth(headers_raw: str) -> dict:
    """Extract spf/dkim/dmarc verdict strings from a raw headers blob.

    extract_ml_features now reads parsed['spf'] etc. directly (not headers_raw),
    so both real and synthetic samples must have these fields set.
    """
    auth = {"spf": None, "dkim": None, "dmarc": None}
    h = headers_raw.lower()
    for proto in ["spf", "dkim", "dmarc"]:
        for verdict in ["pass", "fail", "softfail", "neutral", "none"]:
            if f"{proto}={verdict}" in h:
                auth[proto] = verdict
                break
    return auth


def _parse_eml(path: str) -> dict:
    """Parse a raw .eml file into the parsed dict that extract_ml_features expects."""
    try:
        with open(path, "rb") as f:
            raw = f.read(200_000)          # cap at 200 KB
        msg = _email_lib.message_from_bytes(raw, policy=_email_lib.policy.compat32)
    except Exception:
        return {}

    # Subject
    subj_raw = str(msg.get("Subject", "") or "")
    try:
        from email.header import decode_header
        parts = decode_header(subj_raw)
        subj = " ".join(
            p[0].decode(p[1] or "utf-8", errors="replace") if isinstance(p[0], bytes) else p[0]
            for p in parts
        )
    except Exception:
        subj = str(subj_raw)

    # Sender
    sender_raw = str(msg.get("From", "") or "")
    sender_email = ""
    sender_domain = ""
    m = re.search(r'[\w.\-+]+@[\w.\-]+', sender_raw)
    if m:
        sender_email = m.group(0).lower()
        parts_at = sender_email.split("@")
        if len(parts_at) == 2:
            sender_domain = parts_at[1]

    # Reply-To
    reply_to = str(msg.get("Reply-To", "") or "")

    # Body
    body_text = body_html = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "text/plain":
            try:
                body_text += part.get_payload(decode=True).decode("utf-8", errors="replace")
            except Exception:
                pass
        elif ct == "text/html":
            try:
                body_html += part.get_payload(decode=True).decode("utf-8", errors="replace")
            except Exception:
                pass

    # URLs
    combined_body = body_text + body_html
    urls = list(set(_URL_RE.findall(combined_body)[:60]))

    # SPF/DKIM/DMARC — parse from Authentication-Results header directly
    auth_raw = (msg.get("Authentication-Results") or "").lower()
    spf = dkim = dmarc = None
    for verdict in ["pass", "fail", "softfail", "neutral", "none"]:
        if f"spf={verdict}" in auth_raw and spf is None:
            spf = verdict
        if f"dkim={verdict}" in auth_raw and dkim is None:
            dkim = verdict
        if f"dmarc={verdict}" in auth_raw and dmarc is None:
            dmarc = verdict

    return {
        "subject":       subj,
        "body_text":     body_text,
        "body_html":     body_html,
        "urls":          urls,
        "attachments":   [],
        "sender_domain": sender_domain,
        "sender_email":  sender_email,
        "reply_to":      reply_to,
        "spf":           spf,
        "dkim":          dkim,
        "dmarc":         dmarc,
    }


# ── Synthetic data generation ──────────────────────────────────────────────────

BRAND_DOMAINS = {
    "paypal":         ("paypal-secure-login.com",    "paypal-verify-account.com",   "paypallogin-secure.com"),
    "bank":           ("fakebank.com",               "bank-secure-update.com",      "banklogin-verify.com",   "yourbank-alert.com"),
    "chase":          ("chase-bank-secure.com",      "chase-login-verify.com",      "chaseonline-secure.com"),
    "amazon":         ("amazon-secure-update.com",   "amaz0n-login.com",            "amazon-account-verify.com"),
    "apple":          ("apple-id-verify.com",        "appleid-secure-login.com",    "app1e-support.com"),
    "microsoft":      ("microsoftonline-login.com",  "microsoft-account-verify.com","micros0ft-secure.com"),
    "netflix":        ("netflix-billing-update.com", "netflix-account-verify.com",  "netfl1x-login.com"),
    "irs":            ("irs-gov-refund.com",         "irs-tax-alert.com",           "irs-payment-verify.com"),
    "wellsfargo":     ("wellsfargo-secure.com",      "wellsfargo-bank-login.com",   "wellsfargo-verify.com"),
}

URGENCY_SUBJECTS = [
    "URGENT: Your Account Has Been Compromised - Action Required",
    "Security Alert: Unusual Activity Detected - Verify Now",
    "Your Account Will Be Suspended - Immediate Action Required",
    "Final Notice: Update Your Payment Information",
    "WARNING: Your account access has been limited",
    "Action Required: Confirm Your Identity Within 24 Hours",
    "IMPORTANT: Your password expires today",
    "Alert: New login detected on your account",
    "Your account has been flagged for suspicious activity",
    "Immediate action required: Verify your email address",
]

LOTTERY_SUBJECTS = [
    "CONGRATULATIONS! You Won $1,000,000 - Claim Your Prize Now!",
    "You have been selected as a prize winner",
    "Your email won our quarterly lottery - Claim Now!",
    "Lucky Winner Notification - $500,000 Awaiting Claim",
    "Claim your reward: You have been selected",
]

CREDENTIAL_BODY = [
    "Please verify your identity by clicking the link below. Failure to verify within 24 hours will result in account suspension.",
    "To restore your account access, you must confirm your login credentials immediately.",
    "Enter your username and password to verify your account and prevent unauthorized access.",
    "Your account has been flagged. Please update your payment details and verify your identity now.",
    "We detected unusual sign-in activity. Confirm your identity to secure your account.",
]

GIFT_BODY = [
    "You have been selected as the winner of our $1,000,000 jackpot! To claim your prize, provide your banking information.",
    "Congratulations! You are our lucky winner. Please provide your bank account details to receive your reward.",
    "You won a $500,000 prize. Click the link to claim your reward and provide your financial details.",
    "Your email was selected in our monthly draw. You have won a gift card worth $1000. Claim now!",
]

LEGITIMATE_SUBJECTS = [
    "Your order has shipped",
    "Meeting scheduled for tomorrow",
    "Weekly team update",
    "Your account statement is ready",
    "Password changed successfully",
    "Your subscription has been renewed",
    "Invoice #12345 from Acme Corp",
    "New comment on your pull request",
    "Your report is ready for download",
    "Welcome to our service",
    "Your delivery is on its way",
    "Project update from the team",
    "Thanks for your purchase",
    "Security code for your login",
    "Your ticket has been resolved",
    "Your two-factor authentication is enabled",
    "Sign-in notification for your account",
    "Your payment receipt",
    "Confirm your email address",
    "Your verification code",
    "New login to your account",
    "Your invoice is ready",
    "Account activity summary",
    "Your password has been updated",
]

LEGITIMATE_BODY = [
    "Your order #12345 has been shipped and will arrive in 3-5 business days.",
    "Hi, we have scheduled a team meeting for tomorrow at 2 PM. Please review the agenda.",
    "Here is your weekly summary of activity on your account. Everything looks good.",
    "Your account statement for the month of April is now available in your online portal.",
    "We successfully changed your password. If you did not make this change, contact support.",
    "Your subscription to our premium service has been renewed for another year.",
    "Please find attached the invoice for services rendered this month.",
    "John left a comment on your pull request: 'Looks good to me, approved!'",
    "Your monthly report is ready. Log in to download it from your dashboard.",
    "Welcome! Your account has been created. Here is what you can do next...",
    # Keyword-rich but legitimate — the model must learn these are safe
    "Your two-factor authentication code is 847291. This code expires in 10 minutes. Do not share it with anyone.",
    "We noticed a new sign-in to your account from Chrome on Windows. If this was you, no action is needed.",
    "Your payment of $29.99 has been confirmed. Log in to your account to view your receipt.",
    "Please confirm your email address by clicking the link below. This helps keep your account secure.",
    "Your verification code is 392847. Enter this code to complete your login.",
    "A new device has been added to your account. If you did not do this, please contact support immediately.",
    "Your password was successfully updated. If you did not make this change, please reset your password.",
    "Thank you for your payment. Your invoice #INV-2024-0042 has been paid in full.",
    "Your account login was successful from a new location. Review your recent account activity.",
    "We have verified your identity. Your account is now confirmed and fully active.",
]

# Legitimate financial/transactional bodies that mention payment keywords safely
LEGITIMATE_FINANCIAL_BODY = [
    "Your payment of $49.99 to Acme Corp has been processed successfully. Reference: TXN-88291.",
    "Your invoice from Stripe is ready. Amount due: $120.00. Log in to view or pay your invoice.",
    "We received your payment. Your subscription is active until December 31, 2025.",
    "Your bank transfer of $500 has been initiated. Funds will arrive in 1-2 business days.",
    "Your PayPal payment to seller@example.com for $35.00 was completed successfully.",
    "Your monthly statement is ready. Total charges this month: $89.50. Login to review details.",
]

AUTH_HEADERS = [
    "Authentication-Results: spf=pass smtp.mailfrom=domain.com;\n dkim=pass header.d=domain.com;\n dmarc=pass action=none",
    "Received-SPF: pass (domain.com: designated sender)\nAuthentication-Results: dkim=pass",
    "ARC-Authentication-Results: spf=pass; dkim=pass; dmarc=pass",
]

# Phishing auth headers — properly configured malicious domains or compromised ESPs
PHISH_AUTH_HEADERS = [
    "Authentication-Results: spf=pass smtp.mailfrom=domain.com;\n dkim=pass header.d=domain.com;\n dmarc=none",
    "Authentication-Results: spf=pass smtp.mailfrom=domain.com;\n dkim=pass header.d=domain.com",
    "Received-SPF: pass (domain.com: designated sender)",
    "Authentication-Results: spf=pass; dkim=pass; dmarc=none action=none",
]

# Modern phishing domains — look legitimate, low entropy
MODERN_PHISH_DOMAINS = [
    "secure-accountverify.com", "account-notifications.net", "verify-identity-now.com",
    "login-secureportal.com", "account-alert-service.com", "identity-verify-center.com",
    "securelogin-portal.net", "accountverification-center.com", "notification-alerts.net",
    "verify-account-secure.com", "security-notification-center.com", "account-update-required.com",
]


def _phish_url(domain: str, path: str, rng: random.Random) -> str:
    """Return a phishing URL — 50% HTTPS (modern), 50% HTTP (old-style)."""
    scheme = "https" if rng.random() < 0.5 else "http"
    return f"{scheme}://{domain}/{path}?token={rng.randint(100000, 999999)}"


def _phish_auth(domain: str, rng: random.Random) -> str:
    """Return auth headers for 35% of phishing samples (compromised/properly-configured senders)."""
    if rng.random() < 0.35:
        return rng.choice(PHISH_AUTH_HEADERS).replace("domain.com", domain)
    return ""


def _make_phishing_parsed(style: str, rng: random.Random) -> dict:
    """Build a parsed dict for one synthetic phishing email."""
    parsed = {"attachments": []}

    if style == "brand_impersonation":
        brand = rng.choice(list(BRAND_DOMAINS.keys()))
        sender_domain = rng.choice(BRAND_DOMAINS[brand])
        parsed["sender_domain"] = sender_domain
        parsed["sender_email"]  = f"security@{sender_domain}"
        parsed["reply_to"]      = ""
        parsed["subject"]       = rng.choice(URGENCY_SUBJECTS)
        cred_body               = rng.choice(CREDENTIAL_BODY)
        url = _phish_url(sender_domain, "verify", rng)
        parsed["urls"]          = [url]
        parsed["body_text"]     = cred_body
        parsed["body_html"]     = f"<html><body><p>{cred_body}</p><a href='{url}'>Verify Now</a></body></html>"
        parsed.update(_parse_auth(_phish_auth(sender_domain, rng)))

    elif style == "urgency_credential":
        sender_domain = f"{rng.choice(['secure','verify','alert','update'])}-{rng.choice(['mail','service','notice'])}.{rng.choice(['com','net','org'])}"
        parsed["sender_domain"] = sender_domain
        parsed["sender_email"]  = f"noreply@{sender_domain}"
        parsed["reply_to"]      = f"reply@{rng.choice(['gmail.com','yahoo.com','hotmail.com'])}"
        parsed["subject"]       = rng.choice(URGENCY_SUBJECTS)
        cred_body               = rng.choice(CREDENTIAL_BODY)
        url = _phish_url(sender_domain, "login", rng)
        parsed["urls"]          = [url]
        parsed["body_text"]     = cred_body + " Click here to confirm your account details and update your password."
        parsed["body_html"]     = f"<html><body><p>{cred_body}</p><a href='{url}'>Update Now</a></body></html>"
        parsed.update(_parse_auth(_phish_auth(sender_domain, rng)))

    elif style == "gift_lottery":
        sender_domain = f"{rng.choice(['lottery','prize','claim','winner','reward'])}-{rng.choice(['center','official','notify'])}.{rng.choice(['com','net','org'])}"
        parsed["sender_domain"] = sender_domain
        parsed["sender_email"]  = f"winner@{sender_domain}"
        parsed["reply_to"]      = ""
        parsed["subject"]       = rng.choice(LOTTERY_SUBJECTS)
        gift_body               = rng.choice(GIFT_BODY)
        url = _phish_url(sender_domain, "claim", rng)
        parsed["urls"]          = [url]
        parsed["body_text"]     = gift_body
        parsed["body_html"]     = f"<html><body><h1>CONGRATULATIONS!</h1><p>{gift_body}</p><a href='{url}'>Claim Your Prize</a></body></html>"
        parsed.update(_parse_auth(_phish_auth(sender_domain, rng)))

    elif style == "bec":
        parsed["sender_domain"] = rng.choice(["gmail.com", "yahoo.com", "outlook.com"])
        parsed["sender_email"]  = f"ceo.{rng.randint(100,999)}@gmail.com"
        parsed["reply_to"]      = f"attacker{rng.randint(1000,9999)}@protonmail.com"
        parsed["subject"]       = rng.choice(["Urgent Wire Transfer", "Confidential Payment Request", "Invoice Payment - Urgent", "Vendor Payment Authorization"])
        bec_body = rng.choice([
            "I need you to process an urgent wire transfer of $50,000 to our new vendor. Bank details: Account 1234567, Routing 987654321.",
            "Confidential: Please arrange immediate payment to our partner. Wire $75,000 to account number 5551234 routing 111000025.",
            "This is urgent. Can you process the attached invoice payment today? It's $25,000 and needs to go out before close of business.",
        ])
        parsed["urls"]          = []
        parsed["body_text"]     = bec_body
        parsed["body_html"]     = ""
        legit_domain = parsed["sender_domain"]
        parsed.update(_parse_auth(rng.choice(PHISH_AUTH_HEADERS).replace("domain.com", legit_domain)))

    elif style == "crypto_scam":
        sender_domain = f"crypto-{rng.choice(['invest','wallet','profit','mining'])}.{rng.choice(['com','net','io'])}"
        parsed["sender_domain"] = sender_domain
        parsed["sender_email"]  = f"invest@{sender_domain}"
        parsed["reply_to"]      = ""
        parsed["subject"]       = rng.choice(["Double your Bitcoin in 24 hours", "Crypto investment opportunity - 500% returns", "Your Bitcoin wallet needs verification", "Urgent: Your crypto account requires attention"])
        crypto_body = rng.choice([
            "Invest your Bitcoin now and earn 500% returns in 24 hours. Send BTC to our secure wallet: 1A2b3C4d5E6f7G8h",
            "Your crypto wallet has been flagged. Verify your account by sending 0.1 BTC to confirm ownership.",
            "Limited time: double your Bitcoin. Send any amount and receive double within 24 hours.",
        ])
        url = _phish_url(sender_domain, "invest", rng)
        parsed["urls"]          = [url]
        parsed["body_text"]     = crypto_body
        parsed["body_html"]     = ""
        parsed.update(_parse_auth(_phish_auth(sender_domain, rng)))

    elif style == "malicious_attachment":
        sender_domain = f"{rng.choice(['billing','invoice','document','report'])}-{rng.choice(['service','system','auto'])}.{rng.choice(['com','net'])}"
        parsed["sender_domain"] = sender_domain
        parsed["sender_email"]  = f"invoice@{sender_domain}"
        parsed["reply_to"]      = ""
        parsed["subject"]       = rng.choice(["Invoice #9847 - Action Required", "Document Shared With You", "Your Statement is Ready - Download Now", "Payroll Update - Open Attachment"])
        parsed["body_text"]     = "Please review and sign the attached document. Open the attachment to view your invoice."
        parsed["body_html"]     = ""
        parsed["urls"]          = []
        parsed["attachments"]   = [{"filename": rng.choice(["Invoice.exe", "Statement.pdf.exe", "Document.scr", "Report.zip"]), "is_malicious_ext": True, "is_risky_ext": False, "content_type": "application/octet-stream"}]
        parsed.update(_parse_auth(_phish_auth(sender_domain, rng)))

    elif style == "modern_auth_phishing":
        sender_domain = rng.choice(MODERN_PHISH_DOMAINS)
        parsed["sender_domain"] = sender_domain
        parsed["sender_email"]  = f"no-reply@{sender_domain}"
        parsed["reply_to"]      = ""
        parsed["subject"]       = rng.choice(URGENCY_SUBJECTS)
        cred_body               = rng.choice(CREDENTIAL_BODY)
        url = f"https://{sender_domain}/verify?session={''.join(rng.choices('abcdef0123456789', k=16))}"
        parsed["urls"]          = [url]
        parsed["body_text"]     = cred_body
        parsed["body_html"]     = f"<html><body><p>{cred_body}</p><a href='{url}'>Verify Now</a></body></html>"
        # Always has auth — this is the hard case the model must learn
        parsed.update(_parse_auth(rng.choice(PHISH_AUTH_HEADERS).replace("domain.com", sender_domain)))

    else:  # random_domain (old-style spam with high-entropy domain)
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        domain_part = "".join(rng.choices(chars, k=rng.randint(8, 16)))
        sender_domain = f"{domain_part}.{rng.choice(['com','net','xyz','top','ru','tk'])}"
        parsed["sender_domain"] = sender_domain
        parsed["sender_email"]  = f"phish@{sender_domain}"
        parsed["reply_to"]      = ""
        parsed["subject"]       = rng.choice(URGENCY_SUBJECTS + LOTTERY_SUBJECTS)
        body = rng.choice(CREDENTIAL_BODY + GIFT_BODY)
        url = f"http://{sender_domain}/{rng.choice(['verify','login','secure','update'])}?id={rng.randint(10000,99999)}"
        parsed["urls"]          = [url]
        parsed["body_text"]     = body
        parsed["body_html"]     = ""
        parsed["spf"] = parsed["dkim"] = parsed["dmarc"] = None

    return parsed


def _make_legitimate_parsed(style: str, rng: random.Random) -> dict:
    """Build a parsed dict for one synthetic legitimate email."""
    parsed = {"attachments": [], "urls": [], "reply_to": ""}

    legit_domains = [
        "amazon.com", "github.com", "google.com", "microsoft.com", "apple.com",
        "netflix.com", "shopify.com", "stripe.com", "sendgrid.com", "mailchimp.com",
        "zendesk.com", "salesforce.com", "slack.com", "zoom.us", "dropbox.com",
        "notion.so", "atlassian.com", "hubspot.com", "twilio.com", "paypal.com",
    ]

    domain = rng.choice(legit_domains)
    parsed["sender_domain"] = domain
    parsed["sender_email"]  = f"noreply@{domain}"
    parsed["subject"]       = rng.choice(LEGITIMATE_SUBJECTS)

    if style == "transactional":
        body = rng.choice(LEGITIMATE_BODY)
        url = f"https://{domain}/track?order={rng.randint(100000,999999)}"
        parsed["urls"]      = [url]
        parsed["body_text"] = body
        parsed["body_html"] = f"<html><body><p>{body}</p><a href='{url}'>View Details</a></body></html>"
        parsed.update(_parse_auth(rng.choice(AUTH_HEADERS).replace("domain.com", domain)))

    elif style == "newsletter":
        body = "Here is your weekly newsletter. Top stories: 1. Market update. 2. Product launches. 3. Tips and tricks."
        parsed["urls"]      = [f"https://{domain}/unsubscribe", f"https://{domain}/view-online"]
        parsed["body_text"] = body
        parsed["body_html"] = f"<html><body><p>{body}</p></body></html>"
        parsed.update(_parse_auth(rng.choice(AUTH_HEADERS).replace("domain.com", domain)))

    elif style == "notification":
        body = rng.choice(LEGITIMATE_BODY)
        parsed["body_text"] = body
        parsed["body_html"] = ""
        parsed["urls"]      = []
        parsed.update(_parse_auth(rng.choice(AUTH_HEADERS).replace("domain.com", domain)))

    elif style == "security_legitimate":
        body = rng.choice(LEGITIMATE_BODY[10:])
        url = f"https://{domain}/security?token={''.join(rng.choices('abcdef0123456789', k=32))}"
        parsed["urls"]      = [url]
        parsed["body_text"] = body
        parsed["body_html"] = ""
        parsed.update(_parse_auth(rng.choice(AUTH_HEADERS).replace("domain.com", domain)))

    elif style == "financial_legitimate":
        body = rng.choice(LEGITIMATE_FINANCIAL_BODY)
        url = f"https://{domain}/invoices/{rng.randint(10000, 99999)}"
        parsed["urls"]      = [url]
        parsed["body_text"] = body
        parsed["body_html"] = f"<html><body><p>{body}</p><a href='{url}'>View Invoice</a></body></html>"
        parsed.update(_parse_auth(rng.choice(AUTH_HEADERS).replace("domain.com", domain)))
        if rng.random() < 0.4:
            parsed["attachments"] = [{"filename": f"Invoice_{rng.randint(1000,9999)}.pdf",
                                       "is_malicious_ext": False, "is_risky_ext": True,
                                       "content_type": "application/pdf"}]

    else:
        parsed["body_text"] = rng.choice(LEGITIMATE_BODY)
        parsed["body_html"] = ""
        parsed.update(_parse_auth(rng.choice(AUTH_HEADERS).replace("domain.com", domain)))

    return parsed


# ── Feature extraction from real email files ───────────────────────────────────

def load_real_samples(limit_per_class: int = 4000):
    """Load real phishing and ham email files, extract features."""
    X, y = [], []

    phish_styles = ["brand_impersonation", "urgency_credential", "gift_lottery",
                    "bec", "crypto_scam", "malicious_attachment", "random_domain"]

    def _load_dir(path, label, limit):
        if not os.path.isdir(path):
            logger.warning(f"Directory not found: {path}")
            return
        files = [f for f in os.listdir(path) if f.endswith(".eml")][:limit]
        logger.info(f"Loading {len(files)} real {'phishing' if label==1 else 'ham'} emails…")
        for fname in files:
            parsed = _parse_eml(os.path.join(path, fname))
            if not parsed:
                continue
            try:
                feats, _ = extract_ml_features(parsed)
                X.append(feats)
                y.append(label)
            except Exception:
                pass

    _load_dir(PHISH_DIR, 1, limit_per_class)
    _load_dir(HAM_DIR,   0, limit_per_class)
    return X, y


# ── Main training pipeline ─────────────────────────────────────────────────────

def generate_synthetic(n_phish: int = 9000, n_legit: int = 9000, seed: int = 42):
    """Generate balanced modern synthetic data."""
    rng = random.Random(seed)
    X, y = [], []

    phish_styles = [
        "brand_impersonation",      # most important — LOW domain entropy
        "brand_impersonation",      # doubled weight
        "urgency_credential",
        "gift_lottery",
        "bec",
        "crypto_scam",
        "malicious_attachment",
        "random_domain",            # keep some high-entropy examples
        "modern_auth_phishing",     # phishing with valid auth + HTTPS (false negative fix)
        "modern_auth_phishing",     # doubled weight — most underrepresented case
    ]
    legit_styles = [
        "transactional", "newsletter", "notification",
        "security_legitimate", "security_legitimate",  # doubled — most FP-prone
        "financial_legitimate",
        "other",
    ]

    logger.info(f"Generating {n_phish} synthetic phishing samples…")
    for i in range(n_phish):
        style = phish_styles[i % len(phish_styles)]
        parsed = _make_phishing_parsed(style, rng)
        try:
            feats, _ = extract_ml_features(parsed)
            X.append(feats)
            y.append(1)
        except Exception:
            pass

    logger.info(f"Generating {n_legit} synthetic legitimate samples…")
    for i in range(n_legit):
        style = legit_styles[i % len(legit_styles)]
        parsed = _make_legitimate_parsed(style, rng)
        try:
            feats, _ = extract_ml_features(parsed)
            X.append(feats)
            y.append(0)
        except Exception:
            pass

    return X, y


def train():
    logger.info("=" * 60)
    logger.info("ETA Phishing Model Trainer v4.0")
    logger.info("=" * 60)

    # Load real data
    X_real, y_real = load_real_samples(limit_per_class=4000)
    logger.info(f"Real data: {sum(y_real)} phishing, {len(y_real)-sum(y_real)} ham")

    # Generate synthetic data
    X_syn, y_syn = generate_synthetic(n_phish=9000, n_legit=9000, seed=RANDOM_SEED)
    logger.info(f"Synthetic data: {sum(y_syn)} phishing, {len(y_syn)-sum(y_syn)} ham")

    # Combine
    X_all = np.array(X_real + X_syn, dtype=np.float32)
    y_all = np.array(y_real + y_syn, dtype=np.int32)

    n_phish = int(y_all.sum())
    n_legit = len(y_all) - n_phish
    logger.info(f"Total: {len(y_all)} samples ({n_phish} phishing, {n_legit} ham)")

    # Shuffle
    idx = np.random.permutation(len(y_all))
    X_all, y_all = X_all[idx], y_all[idx]

    # Scale features (XGBoost doesn't need it, but keeps scaler consistent)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_all)

    # Train/val split (80/20 stratified)
    from sklearn.model_selection import train_test_split
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_scaled, y_all, test_size=0.20, random_state=RANDOM_SEED, stratify=y_all
    )

    # XGBoost — balanced class weights, regularised to reduce single-feature dominance
    scale_pos = n_legit / max(1, n_phish)
    model = xgb.XGBClassifier(
        n_estimators=400,
        max_depth=5,              # shallower trees → less domain_entropy overfitting
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.7,     # each tree sees 70% of features
        colsample_bylevel=0.7,
        reg_alpha=0.3,            # L1 regularisation
        reg_lambda=1.5,           # L2 regularisation
        min_child_weight=3,
        scale_pos_weight=scale_pos,
        use_label_encoder=False,
        eval_metric="auc",
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
    )

    logger.info("Training XGBoost…")
    model.fit(
        X_tr, y_tr,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    # Threshold calibration on validation set
    y_prob = model.predict_proba(X_val)[:, 1]
    precision_arr, recall_arr, thresh_arr = precision_recall_curve(y_val, y_prob)

    # Find the highest threshold where precision ≥ 0.85.
    # Iterating thresholds from high→low finds the first (highest) threshold
    # that achieves sufficient precision — maximising recall at that precision floor.
    phishing_thr = 0.45   # safe default
    for t, p, r in sorted(zip(thresh_arr, precision_arr[:-1], recall_arr[:-1]), reverse=True):
        if p >= 0.85:
            phishing_thr = float(t)
            break

    # Clamp to a sane operating range
    phishing_thr = max(0.30, min(0.70, phishing_thr))
    suspicious_thr = max(0.15, phishing_thr - 0.15)

    logger.info(f"Calibrated thresholds: phishing={phishing_thr:.3f}, suspicious={suspicious_thr:.3f}")

    # Evaluation
    y_pred = (y_prob >= phishing_thr).astype(int)
    roc    = roc_auc_score(y_val, y_prob)
    prec   = precision_score(y_val, y_pred, zero_division=0)
    rec    = recall_score(y_val, y_pred, zero_division=0)
    f1     = f1_score(y_val, y_pred, zero_division=0)
    logger.info(f"Validation  ROC-AUC={roc:.4f}  Precision={prec:.4f}  Recall={rec:.4f}  F1={f1:.4f}")

    # 5-fold CV (on scaled data)
    cv_scores = cross_val_score(model, X_scaled, y_all, cv=StratifiedKFold(5, shuffle=True, random_state=RANDOM_SEED), scoring="f1")
    logger.info(f"5-fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Feature importance
    fi = dict(zip(FEATURE_NAMES, model.feature_importances_))
    top10 = sorted(fi.items(), key=lambda x: x[1], reverse=True)[:10]
    logger.info("Top-10 feature importances:")
    for name, imp in top10:
        logger.info(f"  {name:<30} {imp:.4f}")

    low_importance = [k for k, v in fi.items() if v < 0.005]

    # Save model and scaler
    model_path  = os.path.join(SCRIPT_DIR, "phishing_model.pkl")
    scaler_path = os.path.join(SCRIPT_DIR, "feature_scaler.pkl")
    joblib.dump(model,  model_path)
    joblib.dump(scaler, scaler_path)
    logger.info(f"Model saved  → {model_path}")
    logger.info(f"Scaler saved → {scaler_path}")

    # Save model_meta.json
    meta = {
        "features":             FEATURE_NAMES,
        "n_features":           _N_FEATURES,
        "n_samples":            int(len(y_all)),
        "n_real_samples":       int(len(X_real)),
        "n_synthetic_samples":  int(len(X_syn)),
        "model_type":           "XGBoost",
        "version":              "4.0.0",
        "trained_at":           datetime.now(timezone.utc).isoformat(),
        "phishing_threshold":   round(phishing_thr, 3),
        "suspicious_threshold": round(suspicious_thr, 3),
        "malicious_score":      50,
        "suspicious_score":     30,
        "roc_auc":              round(roc, 4),
        "cv_f1":                round(float(cv_scores.mean()), 4),
        "cv_accuracy":          None,
        "optimal_precision":    round(prec, 4),
        "optimal_recall":       round(rec, 4),
        "feature_importance":   {k: round(float(v), 4) for k, v in top10},
        "low_importance_features": low_importance,
    }
    meta_path = os.path.join(SCRIPT_DIR, "model_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    logger.info(f"Metadata saved → {meta_path}")

    logger.info("=" * 60)
    logger.info("Training complete.")
    logger.info("=" * 60)
    return meta


if __name__ == "__main__":
    train()

"""
Comprehensive Suspicious Words and Phrases Dictionary
for Advanced Email Threat Detection and Analysis
"""

# ─── URGENCY & TIME PRESSURE ───────────────────────────────────────────────────
URGENCY_WORDS = {
    # High Urgency
    "urgent", "immediate", "asap", "critical", "emergency", "alert", "alarm",
    "warning", "act now", "click now", "respond now", "action required",

    # Time Pressure
    "expires", "expired", "expiring", "deadline", "due date", "final notice",
    "last chance", "limited time", "time sensitive", "don't delay",
    "must act", "quickly", "without delay", "no time to waste",

    # Account/Service Threats
    "suspended", "blocked", "locked", "disabled", "deactivated", "terminated",
    "restricted", "limited", "unusual activity", "suspicious activity",
    "unauthorized access", "unauthorized changes", "compromised",

    # Reactivation Urgency
    "reactivate", "restore", "recover", "reinstate", "re-enable", "unblock",
    "unlock", "activate", "confirm account", "verify account",
}

# ─── CREDENTIAL HARVESTING & AUTHENTICATION ────────────────────────────────────
CREDENTIAL_KEYWORDS = {
    # Password/Login Related
    "password", "passwd", "pwd", "login", "log in", "sign in", "signin",
    "authenticate", "credentials", "username", "user name", "email address",
    "account details", "personal information", "sensitive information",

    # Password Reset/Update
    "reset password", "change password", "update password", "confirm password",
    "verify password", "validate password", "re-enter password",
    "temporary password", "new password", "old password",

    # Session Management
    "session expired", "session timeout", "log in again", "sign in again",
    "re-login", "login again", "sign in again", "re-authenticate",

    # Verification/Confirmation
    "verify", "validation", "confirm", "confirmation code", "verification code",
    "otp", "two-factor", "2fa", "2-factor", "security code", "passcode",
    "pin", "security question", "secret question",

    # Identity Verification
    "confirm identity", "verify identity", "validate identity", "proof of identity",
    "verify your identity", "prove your identity", "identify yourself",
}

# ─── FINANCIAL & PAYMENT HARVESTING ────────────────────────────────────────────
FINANCIAL_KEYWORDS = {
    # Payment Methods
    "credit card", "debit card", "bank account", "banking account", "account number",
    "routing number", "swift code", "iban", "bic code", "cvv", "cvc", "exp date",
    "expiration date", "cardholder", "card holder",

    # Payment/Transfer
    "payment", "pay", "paid", "paying", "paypal", "stripe", "square",
    "wire transfer", "wire", "transfer", "transaction", "payment method",
    "billing address", "shipping address",

    # Financial Institutions
    "bank", "banking", "banker", "bank account", "checking account",
    "savings account", "investment", "broker", "stock", "crypto", "bitcoin",
    "ethereum", "wallet", "exchange",

    # Money-Related Services
    "amazon pay", "google pay", "apple pay", "venmo", "paypal", "western union",
    "moneygram", "cryptocurrency", "digital currency",

    # Refund & Money Back
    "refund", "refunded", "reimbursement", "reimbursed", "money back",
    "return money", "claim refund", "process refund",

    # Billing Issues
    "billing", "billing issue", "invoice", "invoice overdue", "past due",
    "payment failed", "failed payment", "declined", "payment declined",
    "billing problem", "billing dispute", "charge", "billing cycle",
}

# ─── PHISHING & DECEPTION ──────────────────────────────────────────────────────
PHISHING_KEYWORDS = {
    # Generic Phishing
    "click here", "click link", "click the link", "open attachment",
    "download attachment", "open file", "execute file", "run file",
    "view document", "view file", "read document",

    # Fake Services/Contests
    "prize", "winner", "congratulations", "claim prize", "claim reward",
    "lottery", "raffle", "sweepstakes", "lucky", "selected", "chosen",
    "special offer", "exclusive offer", "limited offer", "unique offer",

    # Free/Too Good To Be True
    "free", "free money", "free cash", "free gift", "free item",
    "no cost", "complimentary", "bonus", "extra money", "cash bonus",

    # Social Engineering
    "dear customer", "dear user", "dear valued", "dear friend",
    "dear sir", "dear madam", "to whom it may concern",
    "help us verify", "help us confirm", "help us validate",

    # Urgency Manipulation
    "act immediately", "must verify", "must confirm", "required to confirm",
    "required to verify", "important notice", "important message",
}

# ─── BUSINESS EMAIL COMPROMISE (BEC) & CEO FRAUD ──────────────────────────────
BEC_KEYWORDS = {
    # Authority/Position
    "ceo", "cfo", "cto", "president", "executive", "manager", "director",
    "controller", "accountant", "finance team", "accounting team",
    "hr department", "human resources", "it department", "admin",

    # Confidentiality
    "confidential", "strictly confidential", "private", "private and confidential",
    "do not forward", "do not share", "keep confidential", "secret",

    # Urgent Business Requests
    "urgent wire transfer", "confidential request", "sensitive request",
    "time-sensitive request", "request for quote", "rfq", "purchase order",
    "po", "request for information", "rfi", "vendor quote",

    # Approval Requests
    "approve", "approval needed", "needs approval", "sign off", "sign-off",
    "sign document", "sign contract", "sign agreement", "authorize",
    "authorization needed", "authorize payment",

    # Bank Instructions
    "bank details", "banking information", "account information",
    "wire instructions", "wire details", "swift details",
    "beneficiary name", "beneficiary account", "bank name",
}

# ─── MALWARE & TECHNICAL THREATS ───────────────────────────────────────────────
MALWARE_KEYWORDS = {
    # File Execution
    "execute", "run", "launch", "start", "open", "double-click",
    "enable macros", "enable content", "allow macros", "enable editing",
    "update", "update required", "install", "installer",

    # Technical Jargon (Often Used in Malware)
    "macro", "macros", "script", "scripts", "code", "active content",
    "java applet", "activex", "plugin", "extension", "add-on",

    # System/Security Terms (Misused)
    "system update", "security update", "patch", "virus definition",
    "antivirus", "malware signature", "windows update",
}

# ─── BRAND IMPERSONATION & LOOKALIKES ──────────────────────────────────────────
BRAND_KEYWORDS = {
    # Major Payment Services
    "paypal", "amazon", "ebay", "apple", "microsoft", "google",
    "facebook", "meta", "twitter", "instagram", "netflix",

    # Banks & Financial
    "bank of america", "chase", "wells fargo", "citibank", "barclays",
    "irs", "irs.gov", "internal revenue service", "tax return",

    # Email Providers
    "gmail", "outlook", "yahoo", "aol", "icloud", "mail",

    # Social Networks
    "facebook", "instagram", "twitter", "linkedin", "snapchat", "tiktok",
}

# ─── DO NOT TRUST INDICATORS ─────────────────────────────────────────────────
DO_NOT_TRUST_INDICATORS = {
    # Sender Mismatch
    "on behalf of", "behalf", "from", "sent on behalf",
    "forwarded message", "fwd", "re:", "regarding",

    # Unusual Email characteristics
    "external email", "external sender", "outside organization",
    "unverified sender", "unconfirmed sender", "new sender",

    # Technical Red Flags
    "internal email", "system email", "automated message", "automated email",
    "noreply", "do-not-reply", "no-reply", "no reply",
    "notification", "alert", "notification email",
}

# ─── TECHNICAL OBFUSCATION & ENCODING ──────────────────────────────────────────
OBFUSCATION_KEYWORDS = {
    # HTML Encoding
    "&#", "&lt", "&gt", "&quot", "&apos", "&nbsp", "&#x",

    # URL Encoding
    "%20", "%2f", "%3a", "%40", "%25",

    # Base64 (Common in Malware)
    "base64", "encoded", "base-64", "b64",
}

# ─── TRUST-RELATED KEYWORDS ───────────────────────────────────────────────────
TRUST_KEYWORDS = {
    # Legitimate Business
    "invoice attached", "attached invoice", "receipt", "statement",
    "order confirmation", "shipping confirmation", "delivery confirmation",
    "tracking number", "order number", "reference number", "case number",

    # Customer Service
    "customer service", "support", "help desk", "technical support",
    "contact us", "reach out", "get in touch",
}

# ─── COMMON PHISHING PHRASES ──────────────────────────────────────────────────
PHISHING_PHRASES = {
    # Verify/Confirm Phrases
    "verify now", "verify immediately", "verify your account",
    "confirm account", "confirm details", "confirm information",
    "validate account", "validate information", "complete verification",

    # Update/Reconfirm Phrases
    "update your details", "update your information", "update your profile",
    "reconfirm", "revalidate", "re-authenticate", "re-login",

    # Action Required
    "action needed", "immediate action required", "action is required",
    "urgent action", "quick action", "prompt action",

    # Unusual Activity
    "unusual activity detected", "suspicious activity", "unauthorized access",
    "unauthorized login", "login from unknown location",
    "new device login", "device change", "ip change",
}

# ─── CALL TO ACTION (CTA) KEYWORDS ────────────────────────────────────────────
CTA_KEYWORDS = {
    "click here", "click below", "click the button", "go to", "visit",
    "open attachment", "download file", "download now", "download here",
    "view document", "view attachment", "open file", "open document",
    "confirm now", "verify now", "update now", "secure now",
    "act now", "start now", "get started", "join now", "apply now",
    "sign up", "sign up now", "register", "register now",
    "complete form", "fill form", "fill out form", "submit form",
}

# ─── DICTIONARIES FOR QUICK LOOKUP ────────────────────────────────────────────

# Combined suspicious dictionaries
ALL_SUSPICIOUS_WORDS = (
    URGENCY_WORDS | CREDENTIAL_KEYWORDS | FINANCIAL_KEYWORDS |
    PHISHING_KEYWORDS | BEC_KEYWORDS | MALWARE_KEYWORDS |
    BRAND_KEYWORDS | DO_NOT_TRUST_INDICATORS | OBFUSCATION_KEYWORDS |
    TRUST_KEYWORDS | PHISHING_PHRASES | CTA_KEYWORDS
)

# Severity levels
CRITICAL_KEYWORDS = CREDENTIAL_KEYWORDS | BEC_KEYWORDS | MALWARE_KEYWORDS
HIGH_PRIORITY_KEYWORDS = PHISHING_KEYWORDS | FINANCIAL_KEYWORDS | URGENCY_WORDS
MEDIUM_PRIORITY_KEYWORDS = DO_NOT_TRUST_INDICATORS | OBFUSCATION_KEYWORDS

# Grouped by category for analysis
CATEGORIES = {
    "urgency": URGENCY_WORDS,
    "credentials": CREDENTIAL_KEYWORDS,
    "financial": FINANCIAL_KEYWORDS,
    "phishing": PHISHING_KEYWORDS,
    "bec": BEC_KEYWORDS,
    "malware": MALWARE_KEYWORDS,
    "brands": BRAND_KEYWORDS,
    "trust": DO_NOT_TRUST_INDICATORS,
    "obfuscation": OBFUSCATION_KEYWORDS,
    "cta": CTA_KEYWORDS,
}


def get_keyword_severity(keyword: str) -> str:
    """Return severity level for a keyword."""
    if keyword.lower() in CRITICAL_KEYWORDS:
        return "critical"
    elif keyword.lower() in HIGH_PRIORITY_KEYWORDS:
        return "high"
    elif keyword.lower() in MEDIUM_PRIORITY_KEYWORDS:
        return "medium"
    else:
        return "low"


def find_keyword_category(keyword: str) -> str:
    """Find which category a keyword belongs to."""
    keyword_lower = keyword.lower()
    for category, keywords in CATEGORIES.items():
        if keyword_lower in keywords:
            return category
    return "unknown"


def analyze_keywords(text: str) -> dict:
    """Analyze text and return detected keywords with categories."""
    text_lower = text.lower()
    detected = {
        "total": 0,
        "critical": [],
        "high": [],
        "medium": [],
        "by_category": {}
    }

    # Check for multi-word phrases first (most specific)
    for phrase in PHISHING_PHRASES:
        if phrase in text_lower:
            severity = "critical"  # Phishing phrases are critical
            detected["critical"].append(phrase)
            detected["total"] += 1

    import re

    # Check single keywords (regex-based). Fallback to previous space-boundary
    # method is kept for safety.
    for keyword in ALL_SUSPICIOUS_WORDS:
        found = False

        # Multi-word phrases: allow flexible whitespace between words.
        if " " in keyword:
            words = [re.escape(w) for w in keyword.split() if w]
            # Example: "action required" -> r"action\\s+required"
            pat = r"\\b" + r"\\s+".join(words) + r"\\b"
            try:
                if re.search(pat, text_lower, flags=re.IGNORECASE):
                    found = True
            except re.error:
                found = False

        # Single word: match with word boundaries so punctuation (urgent.) is found.
        else:
            w = keyword.strip()
            if w:
                pat = r"\\b" + re.escape(w) + r"\\b"
                try:
                    if re.search(pat, text_lower, flags=re.IGNORECASE):
                        found = True
                except re.error:
                    found = False

        # Fallback to the original conservative check.
        if not found:
            if f" {keyword} " in f" {text_lower} ":
                found = True

        if found:
            severity = get_keyword_severity(keyword)
            category = find_keyword_category(keyword)

            if category not in detected["by_category"]:
                detected["by_category"][category] = []
            detected["by_category"][category].append(keyword)

            if severity == "critical":
                if keyword not in detected["critical"]:
                    detected["critical"].append(keyword)
            elif severity == "high":
                if keyword not in detected["high"]:
                    detected["high"].append(keyword)
            else:
                if keyword not in detected["medium"]:
                    detected["medium"].append(keyword)

            detected["total"] += 1

    return detected

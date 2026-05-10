
"""
Core email analysis engine.
Handles parsing, header analysis, URL checking, attachment analysis,
ML classification, and risk scoring in a single pipeline.
"""
import os
import re
import json
import math
import email
import email.policy
import hashlib
import uuid
import time
import logging
import csv
import io
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from email import message_from_bytes
from email.header import decode_header
from pypdf import PdfReader

# Import the comprehensive suspicious words dictionary
try:
    from suspicious_dictionary import (
        ALL_SUSPICIOUS_WORDS, CREDENTIAL_KEYWORDS, BEC_KEYWORDS,
        analyze_keywords
    )
except ImportError:
    import logging as _logging
    _logging.getLogger(__name__).warning("suspicious_dictionary not found, using fallback keyword lists")
    ALL_SUSPICIOUS_WORDS = set()
    CREDENTIAL_KEYWORDS = set()
    BEC_KEYWORDS = set()

# Email authentication verification
try:
    import spf
    HAS_SPF = True
except ImportError:
    HAS_SPF = False

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as whois_lib  # type: ignore[reportMissingImports]
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    whois_lib = None

try:
    from email_validator import validate_email, EmailNotValidError
    HAS_EMAIL_VALIDATOR = True
except ImportError:
    HAS_EMAIL_VALIDATOR = False

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

URGENCY_WORDS = [
    "urgent","immediate","asap","critical","warning","alert",
    "action required","expires","deadline","final notice","last chance",
    "suspended","limited time","respond now","act now","click now",
    "verify immediately","confirm identity","validate account","reactivate",
    "urgent reply","quick action","time sensitive","don't delay",
    "must click","required to confirm","important notice","immediate action",
    "account compromised","unauthorized access","suspicious activity",
    "confirm receipt","click link","activate account","restore access",
]
SUSPICIOUS_KEYWORDS = [
    "verify","validate","confirm","update","login","signin","password",
    "credential","account","bank","credit card","social security","paypal",
    "bitcoin","transfer","refund","prize","winner","lottery","free",
    "congratulations","click here","download now","invoice overdue",
    "reset password","update payment","confirm details","unusual activity",
    "confirm identity","request information","billing issue","payment failed",
    "secure your account","protect your account","verify now","complete profile",
    "limited offer","exclusive deal","claim reward","special offer",
    "tax refund","irs","banking","wire transfer","swift","iban",
    "urgent request","dear customer","dear user","dear valued",
    "access granted","download attachment","open attachment","pdf attached",
    "invoice","receipt","statement","report","document","form",
    "authorization","approval","compliance","regulation","policy",
    "support ticket","case number","reference number","track order",
    "reset link","confirmation code","verification code","otp",
    "reconfirm","revalidate","resend","retry","again",
    "unusual login","new device","location change","ip address",
    # Expanded keywords (50+ new)
    "account frozen","suspended","restricted","limited access",
    "breach alert","security alert","unauthorized access",
    "immediate action","act now","time sensitive","expires today",
    "winning notification","selected winner","lucky winner",
    "gift card","free gift","bonus credit","credit bonus",
    "bank statement","account summary","monthly statement",
    "direct deposit","payroll deposit","salary advance",
    "loan approval","loan accepted","pre-approved","instant approval",
    "investment opportunity","high returns","guaranteed return",
    "cryptocurrency","bitcoin bonus","ethereum","blockchain",
    "suspended account","account locked","temporarily disabled",
    "confirm email","verify email","validate email","email verification",
    "password expired","password reset required","force logout",
    "suspicious activity detected","unusual sign-in","new login",
    "click below","below link","tap here","tap below",
    "scan qr code","qr code","scan now",
    "social security number","ssn","tin","ein",
    "routing number","account number","card number",
    "cvv","expiration date","billing address",
    "kyc","know your customer","verification needed",
    "aml","anti money laundering","compliance check",
    "urgent wire","same day","immediate transfer",
    "executive transfer","ceo request","executive request",
    "vendor payment","invoice due","payment overdue",
    "domain renewal","domain expiration","hosting renew",
    "ssl expired","certificate expired","security certificate",
    "fake invoice","duplicate invoice","modified invoice",
    ]
CREDENTIAL_HARVEST_KEYWORDS = [
    "verify your identity", "confirm your password", "enter username",
    "login credentials", "validate credentials", "security check",
    "re-enter password", "update credentials", "change password",
    "session expired", "login again", "sign in again",
    "enter your password", "type your password", "input password",
    "confirm your account", "validate your account", "verify account",
    "re-enter your credentials", "update login details", "modify password",
    ]
BEC_KEYWORDS = [
    "wire transfer", "urgent payment", "confidential", "request for quote",
    "rfq", "invoice attached", "payment needed", "urgent fund transfer",
    "bank details", "account number", "routing number", "wire instruction",
    "ceo", "cfo", "controller", "finance dept", "accounting",
    "executive", "director", "board member", "authorized signatory",
    "payment release", "funds transfer", "remittance", "advance payment",
    "retainer", "deposit required", "commitment fee",
    ]
SUSPICIOUS_TLDS = {".xyz",".top",".click",".tk",".ml",".ga",".cf",".gq",".pw",".cc",".buzz",".work",".zip",".download",".online",".site",".store",".business",".info",".biz",".rest",".icu",".su",".racing",".live",".chat",".party",".cricket",".win",".gift",".cash",".money",".tools",".host",".rocks",".digital",".email",".software",".network",".pro",".tech",".io",".ai",".app"}
FREE_EMAIL_DOMAINS = {"gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","protonmail.com","tutanota.com","icloud.com","mail.com","zoho.com","yandex.com","pm.me","proton.me"}
MALICIOUS_EXTENSIONS = {".exe",".bat",".cmd",".ps1",".vbs",".wsf",".hta",".scr",".com",".pif",".lnk",".js",".jar",".msi",".dll",".sys",".reg",".inf",".bat",".chm",".hta",".jse",".vbe",".wg",".fon"}
RISKY_EXTENSIONS = {".docm",".xlsm",".pptm",".zip",".rar",".7z",".iso",".img",".dmg",".pkg",".app",".docb",".xlb",".pptb",".pdf"}
URL_SHORTENERS = {"bit.ly","tinyurl.com","ow.ly","t.co","goo.gl","short.to","rb.gy","cutt.ly","is.gd","buff.ly","tiny.cc","sho.rt","v.gd","tr.im","lnk.in","j.mp","tinyurl.org","u.to","vurl.bz","migre.me","twurl.nl","snipurl.com","s2l.asia","s7y.me","u6l.net","q.gs","gfycat.com","dlvr.it","linkbee.io","linktr.ee","lnk.co","rebrand.ly","bl.ink","tinyurl.one"}
LOOKALIKE_MAP = {
    "paypal":["paypa1","paypall","paypal-secure","paypal-login","paypal-verify","paypal-update","paypal-account","paypa-l","paypa1login","paypallogin","paypaI","paypai","paypaI.com","paypal-secure-login","paypal-support","paypal-billing"],
    "microsoft":["micros0ft","m1crosoft","microsofft","micro-s0ft","microsft","rnicrosoft","micros0ft.com","microsoft-login","microsoft-verify","microsoft-secure","microsoft-account","microsoftonline"],
    "amazon":["amaz0n","amzon","amazon-secure","amazon-login","amazon-verify","amazon-update","amazon-account","amazn","amaz0n-secure","amaz0n.com","amazonn.com","amazon-support"],
    "apple":["app1e","appl3","apple-id-secure","apple-id-verify","apple-id-login","apple-support","app1e-id","appl3.com","app1e.com","aplle","appleid-login","appleid-verify"],
    "google":["g00gle","goog1e","googIe","googl3","g00gl3","googl3.com","googie","google-login","google-verify","google-account","google-secure"],
    "netflix":["netfl1x","netfix","netflix-billing","netflix-login","netflix-verify","netflix-update","netflix-account","netfl1x","netflix-secure","netf1ix","netflix-support"],
    "facebook":["faceb00k","facebok","facebook-login","facebook-verify","facebook-secure","faceb00k.com","faceb00k.net","facebook-account","facebook-support"],
    "linkedin":["linkedln","linkedin-login","linkedin-verify","linkedin-secure","l1nkedin","link3din","linkedin-account"],
    "twitter":["tw1tter","twiter","twitter-help","twitter-login","twitter-verify","twitter-secure","tw1tter.com","twitter-account","twitter-support"],
    "instagram":["1nstagram","1nstagrarn","instagram-login","instagram-verify","instagram-secure","instagrarn","instagram-account","instagram-support"],
    "chase":["chas3","chase-bank","chase-secure","chase-login","chase-verify","chase-update","chas3.com","chasebank","cashase","chase-account","chase-online"],
    "wellsfargo":["wellsfar9o","wellsfargo-bank","wellsfargo-login","wellsfargo-verify","wellsfargo-secure","wellsfar9o.com","wellsfargo-online"],
    "bankofamerica":["bankofamer1ca","bankofamerica-login","bankofamerica-verify","bankofamerica-secure","bankofamerica-update","b0a","bankofamer1ca.com","bankofamerica-online"],
    "usbank":["usbank-login","usbank-verify","usbank-secure","us-bank-login","usbank-online","us-bank-verify"],
    "citibank":["citi-bank","citibank-login","citibank-verify","citibank-secure","citibank-online","citibank-update"],
    "bank":["fakebank","mybank","safebank","yourbank","banklogin","bankverify","banksecure","bankupdate","bank-secure","bank-verify","bank-login","bank-update","bank-alert","bank-account","bank-online","banking-secure","banking-verify","banking-login","securebank","verifybank"],
    "aol":["a0l","aol-login","aol-verify","a0l.com","aolmail","aol-secure"],
    "yahoo":["yah0o","yahoo-mail","yahoo-login","yahoo-verify","yhoo","yahoo-secure","yahoo-account"],
    "dropbox":["dropb0x","dropbox-login","dropbox-verify","dropb0x.com","dr0pbox","dropbox-secure"],
    "drive":["dr1ve","google-drive","google-drive-login","dr1ve.com","googledrive-login"],
    "whatsapp":["whats-app","whatsaap","whtasapp","whatsapp-verify","whatsapp-login","whatsapp-secure"],
    "telegram":["teligram","telegarm","telgram","telegram-verify","telegram-login","telegram-secure"],
    "zoom":["zo0m","zoom-us","zo0m.com","z00m","zoom-login","zoom-verify","zoom-secure","zoom-meeting"],
    "teams":["team5","teams-secure","teams-login","teams-verify","teams-microsoft","microsoft-teams-login"],
    "irs":["irs-refund","irs-verify","irs-update","irs-gov-login","irs-payment","irs-tax","irs-alert"],
    "crypto":["crypto-wallet","bitcoin-verify","crypto-login","blockchain-login","crypto-secure","wallet-verify"],
}

URL_RE = re.compile(
    r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s<>"{}|\\^`\[\]]*)?',
    re.I
)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PRIVATE_IP_RE = re.compile(r'^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)')

# ─── Optimization Config ──────────────────────────────────────────────────────

MAX_TEXT_EXTRACT_SIZE = 10 * 1024 * 1024  # Extract up to 10MB of text for analysis (increased)
MAX_PDF_PAGES = 200  # Limit PDF page extraction for large files (increased)
MAX_CSV_ROWS = 50000  # Limit CSV row processing (increased significantly)
URL_EXTRACTION_LIMIT = 60  # Cap URLs per document
RECEIVED_HEADER_LIMIT = 8  # Cap parsed received headers


# ─── Parser ───────────────────────────────────────────────────────────────────

def _decode_header(value: str) -> str:
    if not value:
        return ""
    try:
        parts = decode_header(value)
        result = ""
        for part, charset in parts:
            if isinstance(part, bytes):
                result += part.decode(charset or "utf-8", errors="replace")
            else:
                result += str(part)
        return result.strip()
    except Exception:
        return str(value)

def _extract_text_from_file(content: bytes, filename: str) -> str:
    """Extract text content from file based on extension (optimized for large files)."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "pdf":
        try:
            reader = PdfReader(io.BytesIO(content))
            text = ""
            # Extract from all pages up to limit for comprehensive analysis
            pages_to_process = min(len(reader.pages), MAX_PDF_PAGES)
            for page_num in range(pages_to_process):
                page = reader.pages[page_num]
                extracted = page.extract_text()
                if extracted:
                    text += f"Page {page_num + 1}:\n{extracted}\n\n"
                # Stop if we've extracted enough text
                if len(text) > MAX_TEXT_EXTRACT_SIZE:
                    text = text[:MAX_TEXT_EXTRACT_SIZE]
                    break

            # If we hit the page limit, add a note
            if len(reader.pages) > MAX_PDF_PAGES:
                text += f"\n[Note: PDF processing limited to {MAX_PDF_PAGES} pages for performance]"

            return text.strip()
        except Exception as e:
            logger.error("PDF extraction failed: %s", e)
            # Fallback to raw text extraction
            return content.decode("utf-8", errors="ignore")[:MAX_TEXT_EXTRACT_SIZE]
    elif ext == "csv":
        try:
            text = content.decode("utf-8", errors="ignore")
            # Parse CSV and extract all data for comprehensive analysis
            reader = csv.reader(io.StringIO(text))
            rows = list(reader)[:MAX_CSV_ROWS + 1]  # +1 for header, but increased limit

            if rows:
                # Extract all raw text content for better analysis
                all_text_parts = []

                # Add headers
                if len(rows) > 0:
                    all_text_parts.append(", ".join(rows[0]))

                # Add all data rows as raw text
                for row in rows[1:]:
                    # Include both formatted and raw row data
                    if len(row) > 0:
                        # Formatted row for readability
                        all_text_parts.append(", ".join(str(cell).strip() for cell in row if cell.strip()))
                        # Also add individual cell content for keyword matching
                        for cell in row:
                            cell_text = str(cell).strip()
                            if cell_text and len(cell_text) > 2:  # Skip very short content
                                all_text_parts.append(cell_text)

                result = "\n".join(all_text_parts)

                # If we hit the row limit, add a note
                if len(rows) >= MAX_CSV_ROWS + 1:
                    result += f"\n[Note: CSV processing limited to {MAX_CSV_ROWS} rows for performance]"

                return result[:MAX_TEXT_EXTRACT_SIZE]
            return text[:MAX_TEXT_EXTRACT_SIZE]
        except Exception as e:
            logger.error("CSV parsing failed: %s", e)
            # Fallback to raw text extraction
            return content.decode("utf-8", errors="ignore")[:MAX_TEXT_EXTRACT_SIZE]
    elif ext in {"json", "xml", "html", "htm", "log", "md"}:
        try:
            text = content.decode("utf-8", errors="ignore")
            # For structured formats, try to extract meaningful content
            if ext == "json":
                try:
                    data = json.loads(text)
                    # Extract all string values from JSON for analysis
                    def extract_strings(obj, path=""):
                        strings = []
                        if isinstance(obj, dict):
                            for key, value in obj.items():
                                strings.extend(extract_strings(value, f"{path}.{key}" if path else key))
                        elif isinstance(obj, list):
                            for i, item in enumerate(obj):
                                strings.extend(extract_strings(item, f"{path}[{i}]"))
                        elif isinstance(obj, str) and len(obj.strip()) > 1:
                            strings.append(obj.strip())
                        return strings
                    json_strings = extract_strings(data)
                    if json_strings:
                        return "\n".join(json_strings)[:MAX_TEXT_EXTRACT_SIZE]
                    # If no strings extracted, fall back to raw text
                except Exception as e:
                    logger.debug("JSON parsing failed: %s", e)
                    # Fall through to raw text
            elif ext in {"xml", "html", "htm"}:
                # Remove HTML/XML tags and extract text content
                import re as regex
                clean_text = regex.sub(r'<[^>]+>', ' ', text)
                clean_text = regex.sub(r'\s+', ' ', clean_text).strip()
                return clean_text[:MAX_TEXT_EXTRACT_SIZE]
            # For .log, .md and other text files, return as-is
            return text[:MAX_TEXT_EXTRACT_SIZE]
        except Exception as e:
            logger.error("%s processing failed: %s", ext.upper(), e)
            return content.decode("utf-8", errors="ignore")[:MAX_TEXT_EXTRACT_SIZE]
    else:
        # Default text extraction for any other supported file type
        try:
            text = content.decode("utf-8", errors="ignore")
            return text[:MAX_TEXT_EXTRACT_SIZE]
        except Exception:
            # Last resort: try latin-1 encoding
            try:
                text = content.decode("latin-1", errors="ignore")
                return text[:MAX_TEXT_EXTRACT_SIZE]
            except Exception:
                return ""


def _extract_email_addr(header: str) -> str:
    """Extract email address from header string like 'Name <email@domain.com>'."""
    if not header:
        return ""
    # Look for email in angle brackets
    match = re.search(r'<([^>]+)>', header)
    if match:
        return match.group(1).strip()
    # If no brackets, check if the whole string is an email
    header = header.strip()
    if '@' in header and '.' in header.split('@')[-1]:
        return header
    return ""


def _extract_domain(header: str) -> str:
    """Extract the domain from an email header or address."""
    if not header:
        return ""
    addr = _extract_email_addr(header)
    if not addr and '@' in header:
        addr = header.strip()
    if '@' in addr:
        return addr.split('@')[-1].lower().strip()
    return ""


def _extract_urls(text: str) -> List[str]:
    urls = URL_RE.findall(text)
    href = re.findall(r'href=["\']([^"\']+)["\']', text, re.I)
    # Strip trailing punctuation that CSV/plain-text context appends to URLs
    cleaned = {u.rstrip('.,;:)\'"') for u in urls + href if u.startswith("http")}
    return list(cleaned)[:URL_EXTRACTION_LIMIT]

def _compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def parse_email_bytes(content: bytes, filename: str = "email.eml") -> Dict[str, Any]:
    """Parse raw email bytes into structured dict."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # .msg is Outlook OLE binary — try extract-msg, fall back to text extraction
    if ext == "msg":
        try:
            import extract_msg  # type: ignore[reportMissingImports]
            import io as _io
            with extract_msg.openMsg(_io.BytesIO(content)) as m:
                text = (m.body or "") + "\n" + (m.htmlBody.decode("utf-8", errors="ignore") if m.htmlBody else "")
                result = {
                    "subject": m.subject or filename,
                    "sender": m.sender or "", "sender_email": m.sender or "",
                    "sender_domain": (m.sender or "").split("@")[-1] if "@" in (m.sender or "") else "",
                    "sender_name": "", "recipient": m.to or "", "reply_to": "",
                    "return_path": "", "date": str(m.date or ""), "message_id": "",
                    "x_mailer": "", "body_text": text, "body_html": m.htmlBody.decode("utf-8", errors="ignore") if m.htmlBody else "",
                    "spf": None, "dkim": None, "dmarc": None,
                    "received_headers": [], "extracted_ips": [],
                    "urls": _extract_urls(text), "domains": [], "attachments": [], "iocs": [],
                }
                result["domains"] = list({u.split("/")[2].split(":")[0] for u in result["urls"] if "//" in u})
                return result
        except Exception:
            # extract-msg not installed or parse failed — treat as text
            ext = "txt"

    if ext not in {"eml", "txt", "mbox"}:
        # For non-email files, extract text and create minimal structure
        text = _extract_text_from_file(content, filename)
        result = {
            "subject": filename,
            "sender": "", "sender_email": "", "sender_domain": "",
            "sender_name": "", "recipient": "", "reply_to": "", "return_path": "",
            "date": "", "message_id": "", "x_mailer": "",
            "body_text": text, "body_html": "",
            "spf": None, "dkim": None, "dmarc": None,
            "received_headers": [],
            "extracted_ips": [],
            "urls": _extract_urls(text), "domains": [], "attachments": [], "iocs": [],
        }
        result["domains"] = list({u.split("/")[2].split(":")[0] for u in result["urls"] if "//" in u})
        for u in result["urls"]:
            result["iocs"].append({"type": "url", "value": u})
        for d in result["domains"]:
            result["iocs"].append({"type": "domain", "value": d})
        return result

    result = {
        "subject": "", "sender": "", "sender_email": "", "sender_domain": "",
        "sender_name": "", "recipient": "", "reply_to": "", "return_path": "",
        "date": "", "message_id": "", "x_mailer": "",
        "body_text": "", "body_html": "",
        "spf": None, "dkim": None, "dmarc": None,
        "received_headers": [],
        "extracted_ips": [],
        "urls": [], "domains": [], "attachments": [], "iocs": [],
    }
    try:
        msg = message_from_bytes(content, policy=email.policy.default)
    except Exception:
        try:
            msg = message_from_bytes(content)
        except Exception as parse_error:
            logger.error("Email parse failed: %s", parse_error)
            return result

    result["subject"]    = _decode_header(msg.get("Subject", ""))
    result["sender"]     = _decode_header(msg.get("From", ""))
    result["recipient"]  = _decode_header(msg.get("To", ""))
    result["reply_to"]   = _decode_header(msg.get("Reply-To", ""))
    result["return_path"]= msg.get("Return-Path", "")
    result["date"]       = msg.get("Date", "")
    result["message_id"] = msg.get("Message-ID", "")
    result["x_mailer"]   = msg.get("X-Mailer", "")

    result["sender_email"]  = _extract_email_addr(result["sender"])
    result["sender_domain"] = _extract_domain(result["sender"])

    name_m = re.match(r'^"?([^"<]+)"?\s*<', result["sender"])
    result["sender_name"] = name_m.group(1).strip() if name_m else ""

    # Auth results
    auth_raw = (msg.get("Authentication-Results") or "").lower()
    for proto in ["spf", "dkim", "dmarc"]:
        for verdict in ["pass", "fail", "softfail", "neutral", "none"]:
            if f"{proto}={verdict}" in auth_raw:
                result[proto] = verdict
                break

    # Received headers → IPs
    received = msg.get_all("Received") or []
    result["received_headers"] = received[:RECEIVED_HEADER_LIMIT]
    seen_ips = set()
    for h in received:
        for ip in IP_RE.findall(h):
            if not PRIVATE_IP_RE.match(ip) and ip not in seen_ips:
                seen_ips.add(ip)
                result["extracted_ips"].append(ip)

    # Body
    all_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                att = _parse_attachment(part)
                if att:
                    result["attachments"].append(att)
            elif ct == "text/plain":
                try:
                    b = part.get_payload(decode=True)
                    if b:
                        t = b.decode(part.get_content_charset() or "utf-8", errors="replace")
                        result["body_text"] += t
                        all_text += t
                except Exception:
                    pass
            elif ct == "text/html":
                try:
                    b = part.get_payload(decode=True)
                    if b:
                        t = b.decode(part.get_content_charset() or "utf-8", errors="replace")
                        result["body_html"] += t
                        all_text += re.sub(r"<[^>]+>", " ", t)
                except Exception:
                    pass
    else:
        try:
            b = msg.get_payload(decode=True)
            if b:
                t = b.decode(msg.get_content_charset() or "utf-8", errors="replace")
                result["body_text"] = t
                all_text = t
        except Exception:
            pass

    result["urls"] = _extract_urls(all_text + result.get("body_html", ""))
    result["domains"] = list({
        re.sub(r'^www\.', '', re.search(r'https?://([^/\s?#]+)', u, re.I).group(1).lower())
        for u in result["urls"]
        if re.search(r'https?://([^/\s?#]+)', u, re.I)
    })

    # IOCs
    for u in result["urls"]:
        result["iocs"].append({"type": "url", "value": u})
    for d in result["domains"]:
        result["iocs"].append({"type": "domain", "value": d})
    for ip in result["extracted_ips"]:
        result["iocs"].append({"type": "ip", "value": ip})
    for a in result["attachments"]:
        if a.get("sha256"):
            result["iocs"].append({"type": "hash", "value": a["sha256"], "filename": a.get("filename")})

    return result

def _parse_attachment(part) -> Optional[Dict[str, Any]]:
    try:
        filename = _decode_header(part.get_filename() or "")
        payload = part.get_payload(decode=True)
        if not payload:
            return None
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
        hashes = _compute_hashes(payload)
        return {
            "filename": filename or "unnamed",
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "size_kb": round(len(payload) / 1024, 1),
            "extension": ext,
            "md5": hashes["md5"],
            "sha256": hashes["sha256"],
            "is_malicious_ext": ext in MALICIOUS_EXTENSIONS,
            "is_risky_ext": ext in RISKY_EXTENSIONS,
        }
    except Exception:
        return None


# ─── Email Authentication Verification ────────────────────────────────────────

def verify_spf(sender_email: str, received_ip: str) -> Optional[str]:
    """Verify SPF record for sender domain. Returns 'pass', 'fail', 'softfail', 'neutral', or None."""
    if not HAS_SPF or not sender_email or not received_ip:
        return None
    
    try:
        domain = sender_email.split("@")[-1] if "@" in sender_email else None
        if not domain:
            return None
        
        # Perform SPF check
        result = spf.check(i=received_ip, s=sender_email, h=domain)
        return result[0] if isinstance(result, tuple) else str(result)
    except Exception as e:
        logger.debug("SPF check failed for %s: %s", sender_email, e)
        return None

def verify_dmarc_policy(domain: str) -> Optional[Dict[str, Any]]:
    """Fetch and parse DMARC policy for domain. Returns policy dict or None."""
    if not HAS_DNS or not domain:
        return None
    
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT", dns.dnssection.ANSWER)
        
        for rdata in answers:
            txt_record = rdata.to_text().strip('"')
            if txt_record.startswith("v=DMARC1"):
                # Parse DMARC policy
                policy = {}
                for part in txt_record.split(";"):
                    part = part.strip()
                    if "=" in part:
                        key, val = part.split("=", 1)
                        policy[key.strip()] = val.strip()
                return policy
        return None
    except dns.exception.DNSException:
        logger.debug("DMARC policy not found for %s", domain)
        return None
    except Exception as e:
        logger.debug("DMARC check failed for %s: %s", domain, e)
        return None

def check_dkim_present(msg: email.message.Message) -> bool:
    """Check if DKIM-Signature header is present in email."""
    return bool(msg.get("DKIM-Signature"))

def validate_sender_email(sender_email: str) -> bool:
    """Validate sender email format and deliverability."""
    if not HAS_EMAIL_VALIDATOR or not sender_email:
        # Fallback to basic regex check
        return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', sender_email))
    
    try:
        validate_email(sender_email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

# ─── Domain Age Check (Enhanced) ────────────────────────────────────────

def get_domain_age(domain: str) -> Dict[str, Any]:
    """Check domain registration age using WHOIS-like heuristics."""
    import socket as _socket

    result = {
        "domain": domain,
        "age_days": None,
        "is_new": False,
        "registration_date": None,
        "error": None
    }

    if not domain:
        return result

    if not HAS_WHOIS:
        result["error"] = "whois library not installed"
        return result

    try:
        # Try python-whois library
        w = whois_lib.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation = w.creation_date[0]
            else:
                creation = w.creation_date

            if creation:
                age_days = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
                result["age_days"] = age_days
                result["is_new"] = age_days < 30  # Less than 30 days = suspicious
                result["registration_date"] = str(creation.date()) if creation else None
    except Exception as e:
        result["error"] = str(e)[:50]
        # Fallback: use DNS resolution time heuristic
        try:
            start = time.time()
            _socket.gethostbyname(domain)
            resolve_time = (time.time() - start) * 1000
            # Very fast resolution might indicate a new/malicious domain
            result["is_new"] = resolve_time < 1
        except Exception:
            pass

    return result

def analyze_domain_reputation(domain: str) -> Dict[str, Any]:
    """Analyze domain for reputation indicators."""
    rep = {
        "domain": domain,
        "is_suspicious_tld": False,
        "is_free_email": False,
        "is_new": False,
        "age_days": None,
        "typosquatting": False,
        "risk_score": 0
    }

    if not domain:
        return rep

    tld = "." + domain.split(".")[-1] if "." in domain else ""
    rep["is_suspicious_tld"] = tld in SUSPICIOUS_TLDS

    rep["is_free_email"] = domain.lower() in FREE_EMAIL_DOMAINS

    # Check typosquatting
    for brand, lookalikes in LOOKALIKE_MAP.items():
        for lookalike in lookalikes:
            if lookalike in domain.lower() and brand not in domain.lower():
                rep["typosquatting"] = True
                rep["risk_score"] += 25
                break

    # TLD risk
    if rep["is_suspicious_tld"]:
        rep["risk_score"] += 30

    # Free email domain (slightly less trust)
    if rep["is_free_email"]:
        rep["risk_score"] -= 10

    rep["risk_score"] = max(0, min(100, rep["risk_score"]))

    return rep

def analyze_email_authentication(msg: email.message.Message, parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Comprehensive email authentication analysis (SPF, DKIM, DMARC)."""
    sender_email = parsed.get("sender_email", "")
    sender_domain = parsed.get("sender_domain", "")
    received_ips = parsed.get("extracted_ips", [])
    
    auth_result = {
        "spf_status": parsed.get("spf", None),
        "dkim_present": check_dkim_present(msg),
        "dkim_status": parsed.get("dkim", None),
        "dmarc_status": parsed.get("dmarc", None),
        "dmarc_policy": None,
        "sender_valid": validate_sender_email(sender_email),
        "issues": []
    }
    
    # Try to verify SPF if we have an IP
    if received_ips and sender_email:
        spf_result = verify_spf(sender_email, received_ips[0])
        if spf_result:
            auth_result["spf_verified"] = spf_result
            if spf_result in ("fail", "softfail"):
                auth_result["issues"].append({
                    "type": "spf_failure",
                    "severity": "high",
                    "desc": f"SPF check {spf_result}: IP {received_ips[0]} not authorized for {sender_domain}"
                })
    
    # Check DKIM signature presence
    if not auth_result["dkim_present"]:
        auth_result["issues"].append({
            "type": "no_dkim",
            "severity": "medium",
            "desc": "DKIM signature not present - email not cryptographically signed"
        })
    
    # Retrieve DMARC policy
    if sender_domain:
        dmarc_policy = verify_dmarc_policy(sender_domain)
        if dmarc_policy:
            auth_result["dmarc_policy"] = dmarc_policy
            
            # Check if policy enforces DMARC
            if dmarc_policy.get("p") == "reject":
                auth_result["issues"].append({
                    "type": "dmarc_strict",
                    "severity": "info",
                    "desc": f"Sender domain {sender_domain} enforces strict DMARC policy (reject)"
                })
            elif dmarc_policy.get("p") == "quarantine":
                auth_result["issues"].append({
                    "type": "dmarc_quarantine",
                    "severity": "info",
                    "desc": f"Sender domain {sender_domain} uses quarantine DMARC policy"
                })
    
    # Validate sender email format
    if not auth_result["sender_valid"]:
        auth_result["issues"].append({
            "type": "invalid_sender",
            "severity": "high",
            "desc": "Sender email address format is invalid"
        })
    
    return auth_result

# ─── Header Analysis ──────────────────────────────────────────────────────────

def analyze_headers(p: Dict) -> Dict[str, Any]:
    indicators = []
    score = 0

    sender_domain = p.get("sender_domain", "")
    reply_to      = p.get("reply_to", "")
    subject       = (p.get("subject") or "").lower()

    # Auth checks
    if p.get("spf") in ("fail", "softfail"):
        indicators.append({"type":"spf_fail","severity":"high","desc":f"SPF {p['spf'].upper()}"})
        score += 20
    if p.get("dkim") == "fail":
        indicators.append({"type":"dkim_fail","severity":"high","desc":"DKIM signature invalid"})
        score += 20
    if p.get("dmarc") == "fail":
        indicators.append({"type":"dmarc_fail","severity":"critical","desc":"DMARC policy violation"})
        score += 30

    # Reply-to mismatch
    if reply_to:
        rto_domain = _extract_domain(reply_to)
        if rto_domain and rto_domain != sender_domain:
            indicators.append({"type":"reply_mismatch","severity":"high","desc":f"Reply-To ({rto_domain}) ≠ sender ({sender_domain})"})
            score += 20

    # Lookalike domain
    for brand, variants in LOOKALIKE_MAP.items():
        if any(v in sender_domain for v in variants):
            indicators.append({"type":"lookalike","severity":"critical","desc":f"Impersonates '{brand}': {sender_domain}"})
            score += 30
            break

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            indicators.append({"type":"sus_tld","severity":"medium","desc":f"Suspicious TLD: {tld}"})
            score += 15
            break

    # Free email
    if sender_domain in FREE_EMAIL_DOMAINS:
        indicators.append({"type":"free_email","severity":"low","desc":f"Free provider: {sender_domain}"})
        score += 5

    # Subject analysis
    found_urgency = [w for w in URGENCY_WORDS if w in subject]
    found_kw      = [w for w in SUSPICIOUS_KEYWORDS if w in subject]
    if found_urgency:
        indicators.append({"type":"urgency","severity":"medium","desc":f"Urgency words: {', '.join(found_urgency[:3])}"})
        score += min(15, len(found_urgency) * 5)
    if found_kw:
        indicators.append({"type":"sus_keywords","severity":"medium","desc":f"Suspicious keywords: {', '.join(found_kw[:3])}"})
        score += min(15, len(found_kw) * 5)
    if subject.count("!") > 2:
        indicators.append({"type":"punctuation","severity":"low","desc":f"{subject.count('!')} exclamation marks"})
        score += 5

    auth_score = sum([
        33 if p.get("spf") == "pass" else 0,
        33 if p.get("dkim") == "pass" else 0,
        34 if p.get("dmarc") == "pass" else 0,
    ])

    # Derive overall_auth label so calculate_risk() can read it
    pass_count = sum(1 for x in [p.get("spf"), p.get("dkim"), p.get("dmarc")] if x == "pass")
    if pass_count >= 3:
        overall_auth = "strong"
    elif pass_count >= 2:
        overall_auth = "moderate"
    elif pass_count >= 1:
        overall_auth = "weak"
    else:
        overall_auth = "none"

    return {
        "indicators": indicators,
        "score": min(100, score),
        "auth_score": auth_score,
        "spf": p.get("spf") or "unknown",
        "dkim": p.get("dkim") or "unknown",
        "dmarc": p.get("dmarc") or "unknown",
        "authentication": {
            "overall_auth": overall_auth,
            "spf": p.get("spf") or "unknown",
            "dkim": p.get("dkim") or "unknown",
            "dmarc": p.get("dmarc") or "unknown",
        },
    }


# ─── URL Analysis ─────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in freq.values())

def analyze_single_url(url: str) -> Dict[str, Any]:
    score = 0
    flags = []
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        domain = p.netloc.lower()

        if IP_RE.match(domain.split(":")[0]):
            flags.append("IP-based URL")
            score += 30
        if any(s in domain for s in URL_SHORTENERS):
            flags.append("URL shortener")
            score += 20
        if "@" in url:
            flags.append("@ in URL")
            score += 25
        if len(url) > 200:
            flags.append(f"Long URL ({len(url)} chars)")
            score += 10
        if p.scheme == "http":
            flags.append("HTTP (not HTTPS)")
            score += 5

        # subdomain depth
        parts = domain.replace("www.", "").split(".")
        if len(parts) > 4:
            flags.append(f"Deep subdomains ({len(parts)-2})")
            score += 15

        # domain entropy
        base = parts[0] if parts else ""
        ent = _entropy(base)
        if ent > 3.8:
            flags.append(f"High domain entropy ({ent:.1f}) — possible DGA")
            score += 20

        # suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append(f"Suspicious TLD: {tld}")
                score += 15
                break

        # brand impersonation in URL
        for brand, variants in LOOKALIKE_MAP.items():
            if any(v in domain for v in variants):
                flags.append(f"Brand impersonation: {brand}")
                score += 25
                break

        # suspicious keywords in path — only flag on short/unknown domains,
        # not on well-known services where login/account paths are expected
        known_safe_domains = {
            "google.com","accounts.google.com","github.com","microsoft.com",
            "live.com","outlook.com","apple.com","amazon.com","paypal.com",
            "stripe.com","shopify.com","slack.com","zoom.us","dropbox.com",
            "linkedin.com","twitter.com","x.com","facebook.com","instagram.com",
        }
        is_known = any(domain == kd or domain.endswith("." + kd) for kd in known_safe_domains)
        if not is_known:
            kw_in_url = [k for k in ["login","verify","confirm","secure","update","account"] if k in url.lower()]
            if kw_in_url:
                flags.append(f"Credential keywords in URL: {', '.join(kw_in_url[:3])}")
                score += min(20, len(kw_in_url) * 7)

    except Exception:
        flags.append("Parse error")

    score = min(100, score)
    return {
        "url": url,
        "score": score,
        "verdict": "malicious" if score >= 60 else "suspicious" if score >= 30 else "safe",
        "flags": flags,
    }

def analyze_urls(urls: List[str]) -> Dict[str, Any]:
    if not urls:
        return {"total":0,"malicious":0,"suspicious":0,"safe":0,"analyses":[],"score":0,"high_risk":[]}
    analyses = [analyze_single_url(u) for u in urls[:50]]
    mal = [a for a in analyses if a["verdict"]=="malicious"]
    sus = [a for a in analyses if a["verdict"]=="suspicious"]
    saf = [a for a in analyses if a["verdict"]=="safe"]
    if mal:
        agg = 80 + min(20, len(mal) * 5)
    elif sus:
        agg = 40 + min(30, len(sus) * 5)
    elif analyses:
        # No individually-suspicious URLs, but carry the highest single-URL score
        # so borderline signals (entropy, HTTP-only, odd TLD) still reach the risk formula
        agg = max(a["score"] for a in analyses)
    else:
        agg = 0
    return {
        "total": len(analyses),
        "malicious": len(mal),
        "suspicious": len(sus),
        "safe": len(saf),
        "analyses": analyses,
        "score": min(100,agg),
        "high_risk": [a["url"] for a in mal+sus][:10],
    }


# ─── Attachment Analysis ──────────────────────────────────────────────────────

def analyze_attachments(attachments: List[Dict]) -> Dict[str, Any]:
    if not attachments:
        return {"count":0,"score":0,"malicious":[],"risky":[],"safe":[],"indicators":[]}
    mal, risky, safe, indicators = [], [], [], []
    total_score = 0
    for a in attachments:
        ext = a.get("extension","")
        fn  = a.get("filename","?")
        if a.get("is_malicious_ext"):
            a["risk"] = "malicious"
            a["risk_score"] = 90
            indicators.append({"severity":"critical","desc":f"Executable attachment: {fn}"})
            total_score += 35
            mal.append(a)
        elif a.get("is_risky_ext") or ext in {".doc",".xls",".ppt"}:
            a["risk"] = "risky"
            a["risk_score"] = 55
            indicators.append({"severity":"high","desc":f"Risky file type: {fn}"})
            total_score += 15
            risky.append(a)
        else:
            a["risk"] = "safe"
            a["risk_score"] = 5
            safe.append(a)
        # double extension check
        parts = fn.split(".")
        if len(parts) >= 3:
            outer = "." + parts[-1].lower()
            inner = "." + parts[-2].lower()
            if outer in MALICIOUS_EXTENSIONS and inner in {".pdf",".doc",".jpg",".png"}:
                indicators.append({"severity":"critical","desc":f"Double extension: {fn}"})
                total_score += 30
    return {
        "count": len(attachments),
        "score": min(100, total_score),
        "malicious": mal, "risky": risky, "safe": safe,
        "indicators": indicators,
        "all": mal+risky+safe,
    }


# ─── ML Classifier ────────────────────────────────────────────────────────────

# 58 clean features (5 redundant removed: all_caps, paypal_lookalike,
# microsoft_lookalike, has_critical, urgency_words)
FEATURE_NAMES = [
    "url_count", "avg_url_len", "ip_in_url", "url_shorteners",
    "at_in_url", "multi_subdomain", "long_url",
    "subj_urgency", "body_urgency", "exclamations", "triple_exclaim", "long_subject",
    "critical_keywords", "high_keywords", "credential_keywords", "bec_keywords",
    "reply_mismatch", "suspicious_tld", "domain_entropy",
    "any_lookalike", "free_email_financial", "malformed_sender",
    "attach_count", "malicious_ext", "risky_ext", "long_filename",
    "body_length", "short_body", "click_count", "http_refs",
    "non_http_urls", "hidden_html", "malformed_html",
    "special_char_ratio", "dashes_subject", "html_entities", "google_phish",
    "total_keywords",
    "spf_header", "dkim_header", "dmarc_header", "missing_auth",
    "sus_url_tld", "url_long_numbers", "url_random_string",
    "popular_brands", "password_reset",
    "executable_attach", "compressed_attach", "hidden_executable",
    "subject_ratio", "long_words", "action_keywords", "http_only", "login_http",
    "gift_scam", "crypto_scam", "invoice_scam",
]
_N_FEATURES = len(FEATURE_NAMES)  # 58

_ML_DIR = os.path.join(os.path.dirname(__file__), "ml")

def _load_thresholds() -> dict:
    """Load tuned classification thresholds from model_meta.json (with safe defaults)."""
    defaults = {
        "phishing_threshold":   0.65,
        "suspicious_threshold": 0.35,
        "malicious_score":      50,
        "suspicious_score":     30,
    }
    try:
        meta_path = os.path.join(_ML_DIR, "model_meta.json")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)
            for k in defaults:
                if k in meta:
                    defaults[k] = meta[k]
    except Exception:
        pass
    return defaults


def _try_load_model():
    """Load trained model and scaler; validate feature count matches."""
    try:
        import joblib
        model_path  = os.path.join(_ML_DIR, "phishing_model.pkl")
        scaler_path = os.path.join(_ML_DIR, "feature_scaler.pkl")
        model, scaler = None, None
        if os.path.exists(model_path):
            model = joblib.load(model_path)
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
        # Verify feature count matches what scaler was trained on
        if scaler is not None and hasattr(scaler, "n_features_in_"):
            if scaler.n_features_in_ != _N_FEATURES:
                logger.warning(
                    "Model scaler expects %d features but engine extracts %d. "
                    "Run ml/train_model.py to regenerate the model.",
                    scaler.n_features_in_, _N_FEATURES
                )
                return None, None
        return model, scaler
    except Exception:
        pass
    return None, None

_MODEL  = None
_SCALER = None
_THRESHOLDS: dict = {}  # loaded lazily on first inference

# Flat list of all lookalike variants (cached for performance)
_ALL_LOOKALIKES: list = []

def _get_lookalikes() -> list:
    global _ALL_LOOKALIKES
    if not _ALL_LOOKALIKES:
        _ALL_LOOKALIKES = sum(LOOKALIKE_MAP.values(), [])
    return _ALL_LOOKALIKES


def extract_ml_features(parsed: Dict):
    """Extract 58 ML features from a parsed email dict.

    Returns (features: list[float], keyword_analysis: dict).
    The same extraction is used at both training time and inference time.
    """
    subject     = (parsed.get("subject") or "").lower()
    body        = ((parsed.get("body_text") or "") + (parsed.get("body_html") or "")).lower()
    urls        = parsed.get("urls") or []
    atts        = parsed.get("attachments") or []
    domain      = parsed.get("sender_domain") or ""
    sender      = parsed.get("sender_email") or ""
    reply_to    = (parsed.get("reply_to") or "").lower()
    text_to_analyze = f"{subject} {body}"
    keyword_analysis = analyze_keywords(text_to_analyze) if ALL_SUSPICIOUS_WORDS else {
        "total": 0, "critical": [], "high": [], "by_category": {}
    }
    critical_count = len(keyword_analysis.get("critical", []))
    high_count     = len(keyword_analysis.get("high", []))

    lookalikes = _get_lookalikes()
    url_domains = [re.sub(r'https?://', '', u).split('/')[0].split('?')[0] for u in urls]

    # ── 58-feature extraction (5 redundant features removed) ──────────────────
    features = [
        # URL (0-6)
        min(len(urls), 30),
        min(sum(len(u) for u in urls) / max(1, len(urls)) / 100, 8),
        int(any(IP_RE.match(re.sub(r'https?://', '', u).split('/')[0]) for u in urls)),
        sum(1 for u in urls if any(s in u for s in URL_SHORTENERS)),
        int(any("@" in re.sub(r'https?://', '', u) for u in urls)),
        sum(1 for u in urls if u.count('.') > 3),
        int(any(len(u) > 150 for u in urls)),
        # Urgency (7-11)
        sum(1 for w in URGENCY_WORDS if w in subject) * 2,
        min(sum(1 for w in URGENCY_WORDS if w in body), 15),
        subject.count("!") * 2 + subject.count("!!!") * 3,
        int("!!!" in subject or "!!!" in body),
        int(len(subject) > 80),
        # Keywords (12-15)
        min(critical_count * 2, 20),
        min(high_count, 30),
        sum(1 for k in CREDENTIAL_KEYWORDS if k in body) * 3,
        sum(1 for k in BEC_KEYWORDS if k in body or k in subject) * 2.5,
        # Domain/Sender (16-21)
        int(bool(reply_to) and _extract_domain(reply_to) != domain),
        int(any(domain.endswith(t) for t in SUSPICIOUS_TLDS)),
        round(_entropy(domain.split(".")[0]), 2),
        int(any(lk in domain or lk in sender or any(lk in ud for ud in url_domains)
                for lk in lookalikes)),
        int(domain in FREE_EMAIL_DOMAINS and any(
            bank in body for bank in ['bank', 'paypal', 'amazon'])),
        int(" " in sender or len(sender) > 100),
        # Attachment (22-25)
        min(len(atts), 8),
        int(any(a.get("is_malicious_ext") for a in atts)),
        int(any(a.get("is_risky_ext") for a in atts)),
        int(any(len(a.get("filename", "")) > 50 for a in atts)),
        # Content (26-32)
        min(len(body) / 5000, 8),
        int(len(body) < 200),
        min(body.count("click"), 10),
        min(body.count("http"), 15),
        sum(1 for u in urls if "http" not in u),
        int(bool(re.search(r'<!--.*?-->', body))),
        int(body.count(">") - body.count("<") > 5),
        # Obfuscation (33-36)
        min(len(re.findall(r'[^\w\s@.\-]', body)) / max(1, len(body)), 1.0) * 10,
        min(subject.count("-"), 8),
        int("&nbsp" in body or "&#" in body),
        int("google" in body and "verify" in body),
        # Dictionary (37)
        min(keyword_analysis.get("total", 0), 50),
        # Sender reputation (38-41) — use parsed auth values, not raw string
        int(bool(parsed.get("spf"))),
        int(bool(parsed.get("dkim"))),
        int(bool(parsed.get("dmarc"))),
        int(not parsed.get("spf") and not parsed.get("dkim") and not parsed.get("dmarc")),
        # URL analysis (42-44)
        sum(1 for u in urls if any(t in u for t in ['.xyz', '.top', '.club', '.online', '.site'])),
        sum(1 for u in urls if re.search(r'\d{8,}', u)),
        sum(1 for u in urls if re.search(r'[a-z]{20,}', u)),
        # Brand impersonation (45-46)
        int(any(brand in body for brand in ['apple', 'netflix', 'facebook', 'instagram'])),
        int("reset" in body or ("password" in body and "expire" in body)),
        # Attachment deep (47-49)
        sum(1 for a in atts if a.get("filename", "").endswith((".exe", ".scr", ".bat", ".cmd"))),
        sum(1 for a in atts if a.get("filename", "").endswith((".zip", ".rar", ".7z"))),
        int(any(a.get("content_type", "").startswith("application/") for a in atts)),
        # Text analysis (50-54)
        min(len(subject) / 100, 5),
        sum(1 for w in subject.split() if len(w) > 15),
        min(body.count("confirm") + body.count("verify") + body.count("update"), 10),
        int("http" in body and "https" not in body),
        int("login" in body and "http" in body),
        # Social engineering (55-57)
        int("gift" in body or "reward" in body or "winner" in body),
        int("bitcoin" in body or "btc" in body or "crypto" in body),
        int("invoice" in body and ("pay" in body or "due" in body)),
    ]

    features = [float(f) if isinstance(f, (int, float)) else 0.0 for f in features]
    if len(features) != _N_FEATURES:
        logger.warning("Feature count mismatch: %d != %d; padding/trimming", len(features), _N_FEATURES)
        while len(features) < _N_FEATURES:
            features.append(0.0)
        features = features[:_N_FEATURES]

    return features, keyword_analysis


def _rule_based_override(features: list, prob: float) -> float:
    """Boost phishing probability when multiple strong signals align.

    The previous model over-relied on domain_entropy (trained on 2002 spam with
    random domains). This layer catches modern brand-impersonation and social-
    engineering phishing that the model may score too low due to readable domains.

    Minimums are kept above the calibrated phishing_threshold (0.70) so that
    any email matching these rules is definitively classified as phishing.
    """
    F_SUBJ_URGENCY   = 7   # subj_urgency
    F_CRITICAL_KW    = 12  # critical_keywords
    F_CREDENTIAL     = 14  # credential_keywords
    F_ANY_LOOKALIKE  = 19  # any_lookalike (sender domain OR URL domain)
    F_MISSING_AUTH   = 41  # missing_auth (no SPF/DKIM/DMARC)
    F_ACTION_KW      = 52  # action_keywords (confirm/verify/update)
    F_HTTP_ONLY      = 53  # http_only (links are plain http)
    F_GIFT_SCAM      = 55  # gift_scam (winner/reward/gift)
    F_CRYPTO_SCAM    = 56  # crypto_scam

    missing_auth  = features[F_MISSING_AUTH] >= 1
    any_lookalike = features[F_ANY_LOOKALIKE] >= 1
    subj_urgency  = features[F_SUBJ_URGENCY] > 0
    credential_kw = features[F_CREDENTIAL] > 0
    action_kw     = features[F_ACTION_KW] > 0
    http_only     = features[F_HTTP_ONLY] >= 1
    gift_scam     = features[F_GIFT_SCAM] >= 1
    crypto_scam   = features[F_CRYPTO_SCAM] >= 1
    critical_kw   = features[F_CRITICAL_KW] > 0

    # Auth de-boost: verified sender with no high-risk combination → reduce raw probability.
    # Catches the case where a legitimate service email (e.g. GitHub security digest)
    # has alert language but proper SPF/DKIM/DMARC and no brand-impersonation or
    # dangerous signal combination (lookalike domain, scam patterns, or credential phishing).
    # Kept mild (0.82) so modern phishing that passes auth still scores high enough
    # if other signals (urgency, credential keywords, suspicious domain) are present.
    # high_risk_combo: signals that indicate real phishing even with auth present.
    # credential_kw alone is NOT enough — 2FA/password-reset emails are legitimate.
    # Requires either brand impersonation, a scam pattern, OR both credential
    # seeking AND urgency together (rare in legit transactional email).
    high_risk_combo = (
        any_lookalike or gift_scam or crypto_scam
        or (credential_kw and subj_urgency)
    )
    if (not missing_auth) and (not high_risk_combo):
        prob = prob * 0.82

    # Rule 1: brand impersonation + no auth + any urgency/credential signal
    if any_lookalike and missing_auth and (subj_urgency or credential_kw or critical_kw or action_kw):
        prob = max(prob, 0.82)

    # Rule 2: brand impersonation + no auth (alone — lower confidence)
    elif any_lookalike and missing_auth:
        prob = max(prob, 0.75)

    # Rule 3: no auth + urgency + credential seeking + HTTP-only link
    elif missing_auth and subj_urgency and credential_kw and (http_only or action_kw):
        prob = max(prob, 0.76)

    # Rule 4: gift / lottery scam + no auth (social engineering)
    elif gift_scam and missing_auth:
        prob = max(prob, 0.75)

    # Rule 5: crypto scam + no auth
    elif crypto_scam and missing_auth:
        prob = max(prob, 0.75)

    # Rule 6: critical keywords + urgency + no auth (general high-confidence phishing)
    elif critical_kw and subj_urgency and missing_auth:
        prob = max(prob, 0.73)

    return prob


def classify_phishing(parsed: Dict) -> Dict[str, Any]:
    global _MODEL, _SCALER, _THRESHOLDS
    if _MODEL is None:
        _MODEL, _SCALER = _try_load_model()
    if not _THRESHOLDS:
        _THRESHOLDS = _load_thresholds()

    features, keyword_analysis = extract_ml_features(parsed)
    body_text = parsed.get("body", "") or ""

    # ── TF-IDF / LogReg secondary classifier ─────────────────────────────────
    # Always run as a parallel signal. When XGBoost is available it is used as
    # a corroboration label only (does not affect the probability). When
    # XGBoost fails it becomes the primary classifier via _rule_score fallback.
    tfidf_result = None
    try:
        from ml_classifier import load_model as _tfidf_load, classify_text_tfidf
        _tfidf_pipeline, _tfidf_vec, _ = _tfidf_load()
        if _tfidf_pipeline and body_text.strip():
            tfidf_result = classify_text_tfidf(body_text, _tfidf_pipeline, _tfidf_vec)
    except Exception as e:
        logger.debug("TF-IDF classifier unavailable: %s", e)

    # ── XGBoost primary classifier ────────────────────────────────────────────
    explanation = []
    if _MODEL:
        try:
            import numpy as np
            arr = np.array(features, dtype=np.float32).reshape(1, -1)
            if _SCALER is not None:
                arr = _SCALER.transform(arr)
            proba  = _MODEL.predict_proba(arr)[0]
            prob   = float(proba[1])
            conf   = float(max(proba))
            method = "xgboost" if hasattr(_MODEL, "get_booster") else "gradient_boosting"

            # Blend TF-IDF as a 10% soft signal when XGBoost is primary and
            # both agree directionally (avoids overfit TF-IDF nudging safe emails)
            if tfidf_result and tfidf_result.get("phishing_prob") is not None:
                tfidf_prob = float(tfidf_result["phishing_prob"])
                # Only blend when both classifiers agree on direction
                if (prob >= 0.5) == (tfidf_prob >= 0.5):
                    prob = prob * 0.90 + tfidf_prob * 0.10

            # SHAP explanation (top-5 features driving the prediction)
            try:
                import shap
                explainer  = shap.TreeExplainer(_MODEL)
                shap_vals  = explainer.shap_values(arr)
                sv = shap_vals[0] if shap_vals.ndim == 2 else shap_vals
                top_idx = np.argsort(np.abs(sv))[::-1][:5]
                explanation = [
                    {
                        "feature":       FEATURE_NAMES[i],
                        "impact":        "increases_risk" if sv[i] > 0 else "decreases_risk",
                        "shap_value":    round(float(sv[i]), 4),
                        "feature_value": round(features[i], 4),
                    }
                    for i in top_idx
                ]
            except Exception:
                pass  # SHAP optional — skip silently if not installed
        except Exception as e:
            logger.warning("XGBoost prediction error: %s", e)
            # Fall back to TF-IDF if available, else rule-based heuristic
            if tfidf_result and tfidf_result.get("phishing_probability") is not None:
                prob   = float(tfidf_result["phishing_probability"])
                conf   = float(tfidf_result.get("confidence", 0.5))
                method = "tfidf_fallback"
            else:
                prob, conf, method = _rule_score(features)
    else:
        # XGBoost not loaded — use TF-IDF if available, else rule-based
        if tfidf_result and tfidf_result.get("phishing_probability") is not None:
            prob   = float(tfidf_result["phishing_probability"])
            conf   = float(tfidf_result.get("confidence", 0.5))
            method = "tfidf"
        else:
            prob, conf, method = _rule_score(features)

    # Apply rule-based override AFTER model prediction (catches modern phishing
    # the domain-entropy-biased model misses).
    prob = _rule_based_override(features, prob)

    phishing_thr   = _THRESHOLDS.get("phishing_threshold", 0.65)
    suspicious_thr = _THRESHOLDS.get("suspicious_threshold", 0.35)
    if prob >= phishing_thr:
        cls = "phishing"
    elif prob >= suspicious_thr:
        cls = "suspicious"
    else:
        cls = "legitimate"

    return {
        "phishing_probability": round(prob, 3),
        "confidence":           round(conf, 3),
        "classification":       cls,
        "method":               method,
        "explanation":          explanation,
        "tfidf_result":         tfidf_result,
        "domain_entropy":       round(features[17], 2) if len(features) > 17 else None,
        "suspicious_keywords_found": {
            "critical":       keyword_analysis.get("critical", [])[:5],
            "high":           keyword_analysis.get("high", [])[:5],
            "total_detected": keyword_analysis.get("total", 0),
        },
    }


def _rule_score(features):
    # Weights aligned to 58-feature set
    weights = [
        6,4,18,7,15,4,12,    # URL (0-6)
        10,8,12,14,6,         # Urgency (7-11)
        8,9,18,16,            # Keywords (12-15)
        12,14,6,12,6,6,       # Domain (16-21)
        5,18,15,12,           # Attachment (22-25)
        3,8,10,8,6,8,8,      # Content (26-32)
        6,5,12,12,            # Obfuscation (33-36)
        8,                    # Dict (37)
        4,4,4,8,              # Sender rep (38-41)
        6,5,5,                # URL analysis (42-44)
        8,10,                 # Brand imp (45-46)
        14,8,6,               # Attach deep (47-49)
        3,4,8,10,8,           # Text (50-54)
        8,10,8,               # Social eng (55-57)
    ]
    norms = [
        8,4,1,3,1,2,1,
        8,8,8,1,1,
        8,15,5,5,
        1,1,2,2,1,1,
        5,1,1,1,
        5,1,5,10,3,1,1,
        0.5,3,1,1,
        25,
        2,2,2,1,
        3,3,3,
        2,2,
        1,2,1,
        2,3,8,8,1,
        1,1,1,
    ]
    score = sum(min(1.5, float(f) / max(0.1, n)) * w
                for f, w, n in zip(features, weights, norms))
    prob = min(0.98, score / 90)
    return prob, 0.75, "rule_based"


# ─── Risk Scoring ─────────────────────────────────────────────────────────────

def calculate_risk(
    header: Dict, url: Dict, attachment: Dict, ml: Dict,
    sem: Dict = None,
    threat_boost: int = 0,
    ioc_intel: Dict = None,
) -> Dict[str, Any]:
    """
    Compute weighted risk score from all analysis modules.

    Scoring philosophy:
      IOC-based signals (URLs, IPs, domains, attachment hashes) carry more weight
      than text/body content because they are concrete Indicators of Compromise
      that survive email translation and cannot be hidden by simple obfuscation.
      Text-based signals are still captured via the ML classifier.

    Weight distribution (DistilBERT always active):
      URL intelligence:     27%  (rule-based heuristics + live API scores)
      XGBoost (58 feats):  25%  (text + structural)
      Semantic (DistilBERT): 15% (subject + body text, on-prem)
      Header/auth:        18%  (SPF/DKIM/DMARC, Reply-To mismatch, TLD)
      Attachment analysis: 15% (extension, magic bytes, executable payload)
      Threat intel boost: +N   (per-IOC API verdicts override local scores)
    """
    global _THRESHOLDS
    if not _THRESHOLDS:
        _THRESHOLDS = _load_thresholds()

    sem = sem or {}
    ioc_intel = ioc_intel or {}
    sem_prob = sem.get("semantic_prob", 0.0)
    sem_active = bool(sem and sem.get("semantic_prob", 0) > 0)

    # ── Base scores from each analysis module (0–100 each) ─────────────────────
    header_score     = header.get("score", 0)
    url_score_base   = url.get("score", 0)       # rule-based URL score
    attach_score_base = attachment.get("score", 0)

    # ── Threat-intel IOC scores override / amplify local scores ────────────────
    # URL IOC: find the worst-tier URL in the threat-intel results
    url_ioc_score = 0
    for entry in (ioc_intel.get("urls") or [])[:8]:
        if entry.get("tier") in ("critical", "high"):
            url_ioc_score = entry.get("score", 0)
            break
        elif entry.get("score", 0) > url_ioc_score:
            url_ioc_score = entry.get("score", 0)

    # Attachment IOC: check if any attachment hash has a threat-intel verdict
    attach_ioc_score = 0
    attach_ioc_tier  = "none"
    for att in (attachment.get("all") or attachment.get("malicious") or []):
        # Threat intel on attachment hashes is embedded in attachment dict by run_analysis
        ti = att.get("threat_intel", {})
        if ti:
            vt_score = 0
            vt = ti.get("virustotal") or {}
            if vt.get("available"):
                mal = vt.get("malicious", 0)
                sus = vt.get("suspicious", 0)
                if mal > 0:
                    vt_score = 60 + (mal / max(vt.get("total", 1), 1)) * 40
                elif sus > 0:
                    vt_score = 30 + (sus / max(vt.get("total", 1), 1)) * 30
            ha_score = 0
            ha = ti.get("hybrid_analysis") or {}
            if ha.get("available"):
                score_map = {"malicious": 90, "suspicious": 60, "no-specific-threat": 0, "unknown": -1}
                v = score_map.get(ha.get("verdict", ""), -1)
                if v >= 0:
                    ha_score = v
            best = max(vt_score, ha_score)
            if best > attach_ioc_score:
                attach_ioc_score = best
                attach_ioc_tier  = "critical" if best >= 80 else "high" if best >= 60 else "medium" if best >= 30 else "low"

    # IP and domain IOC scores from threat intel
    ip_ioc_score = 0
    ip_entry = ioc_intel.get("ip") or {}
    if ip_entry:
        ip_ioc_score = ip_entry.get("score", 0)

    domain_ioc_score = 0
    domain_entry = ioc_intel.get("domain") or {}
    if domain_entry:
        domain_ioc_score = domain_entry.get("score", 0)

    # ── Compute final per-component scores ──────────────────────────────────────
    # URL: use whichever is higher — local heuristic or API verdict
    url_score = max(url_score_base, url_ioc_score)
    attach_score = max(attach_score_base, attach_ioc_score)

    # Header contribution increases when IP/domain have threat-intel signals
    header_ioc_boost = 0.0
    if ip_ioc_score >= 70 or domain_ioc_score >= 70:
        header_ioc_boost = 15.0   # IP/domain strong signal boosts header weight
    elif ip_ioc_score >= 40 or domain_ioc_score >= 40:
        header_ioc_boost = 7.0

    # ── Weighted aggregation ───────────────────────────────────────────────────
    # DistilBERT always active: XGBoost 25%, Semantic 15%, Headers 18%, URLs 27%, Attach 15%
    raw = (
        (header_score + header_ioc_boost)          * 0.18 +
        url_score                                  * 0.27 +
        attach_score                               * 0.15 +
        ml.get("phishing_probability", 0) * 100   * 0.25 +
        sem_prob                             * 100 * 0.15
    )

    # Critical IOC bonus: any critical-tier API hit adds a flat boost
    critical_bonus = 0
    for entry in (ioc_intel.get("urls") or []):
        if entry.get("tier") == "critical":
            critical_bonus = 20
            break
    if (ip_entry or {}).get("tier") == "critical":
        critical_bonus = max(critical_bonus, 20)
    if (domain_entry or {}).get("tier") == "critical":
        critical_bonus = max(critical_bonus, 20)
    if attach_ioc_tier == "critical":
        critical_bonus = max(critical_bonus, 20)

    # High-confidence ML bonus
    ml_prob = ml.get("phishing_probability", 0)
    ml_bonus = (ml_prob - 0.80) * 100 if ml_prob > 0.80 else 0

    final = max(0, min(100, raw + critical_bonus + ml_bonus + threat_boost))

    malicious_score  = _THRESHOLDS.get("malicious_score",  50)
    suspicious_score = _THRESHOLDS.get("suspicious_score", 30)
    if final >= malicious_score:
        verdict, color = "malicious", "#ef4444"
    elif final >= suspicious_score:
        verdict, color = "suspicious", "#f59e0b"
    else:
        verdict, color = "safe", "#10b981"

    recs = _build_recs(verdict, final, header, url, attachment, ml)

    confidence_bonus = round(ml_bonus, 1) if ml_bonus > 0 else None
    breakdown = {
        "header":           round((header_score + header_ioc_boost) * 0.20, 1),
        "url":              round(url_score * 0.25, 1),
        "attachment":       round(attach_score * (0.15 if sem_active else 0.20), 1),
        "ml":               round(ml_prob * 100 * (0.25 if sem_active else 0.35), 1),
        "confidence_bonus": confidence_bonus,
        "semantic":         round(sem_prob * 100 * 0.15, 1) if sem_active else None,
        "ioc_boost":        round(critical_bonus, 1) if critical_bonus > 0 else None,
        "ip_intel_score":   ip_ioc_score if ip_ioc_score > 0 else None,
        "domain_intel_score": domain_ioc_score if domain_ioc_score > 0 else None,
    }

    return {
        "risk_score":  round(final, 1),
        "verdict":     verdict,
        "color":       color,
        "recommendations": recs,
        "breakdown":   breakdown,
        "semantic":    sem,
    }

def _build_recs(verdict, score, header, url, attachment, ml):
    r = []
    if verdict == "phishing":
        r += ["🚨 DO NOT click any links or open attachments",
              "Delete this email immediately and empty your trash",
              "If you entered credentials, change passwords immediately",
              "Report to your IT/security team and enable 2FA",
              "Forward email as attachment to your security team"]
    elif verdict == "suspicious":
        r += ["⚠️ Exercise extreme caution with this email",
              "DO NOT enter credentials or personal information",
              "Verify sender identity via official channels before responding",
              "Do not click links until independently verified",
              "Hover over links to see actual URL before clicking"]
    else:
        r.append("✓ Email appears safe — remain vigilant as always")

    if header.get("spf") in ("fail","softfail"):
        r.append("SPF failure: email may not be from the claimed sender")
    if header.get("dmarc") == "fail":
        r.append("DMARC violation: high risk of domain spoofing")
    if url.get("malicious",0) > 0:
        r.append(f"⚠️ {url['malicious']} malicious URL(s) detected — do not visit")
    if attachment.get("malicious"):
        r.append("🚨 Executable attachment detected — dangerous, do not open")
    if ml.get("phishing_probability",0) > 0.7:
        r.append(f"ML classifier: {round(ml['phishing_probability']*100)}% phishing probability")
    return r[:7]  # Increased from 6 to 7 recommendations


# ─── Rule-Based Threat Insight Engine ─────────────────────────────────────────
# Generates narrative threat assessments, social engineering tactic detection,
# authentication verdicts, and additional IOC inference — all from existing
# analysis signals. Zero external API calls / keys required.

_THREAT_ATTACK_TYPES = [
    ("Credential Phishing / Login Fraud",
     ["login", "verify", "signin", "password", "reset", "account", "authentication",
      "credentials", "username", "sign in", "log in", "authenticate", "two-factor",
      "2fa", "multifactor", " MFA ", "mfa", "identity"]),
    ("Business Email Compromise (BEC) / Wire Fraud",
     ["wire transfer", "bank details", "urgent payment", "payment release",
      "account number", "routing number", "swift", "iban", "funds transfer",
      "remittance", "invoice", "purchase order", "po ", "quote ", "ceo", "cfo",
      "finance dept", "accounting", "confidential", "executive request",
      "advance payment", "retainer", "commitment fee", "vendor payment",
      "payment overdue", "invoice due"]),
    ("Malware / Ransomware Delivery",
     [".exe", ".zip", ".rar", ".7z", ".js", ".jar", ".ps1", ".vbs", ".scr",
      ".bat", ".cmd", ".dll", ".msi", ".chm", ".hta", "download now",
      "open attachment", "enable macros", "enable content", "macros enabled",
      "click to run", "run the file"]),
    ("Brand Impersonation",
     ["apple", "microsoft", "amazon", "paypal", "netflix", "facebook",
      "instagram", "google", "linkedin", "twitter", "chase", "wells fargo",
      "bank of america", "usbank", "citibank", "dropbox", "zoom", "teams"]),
    ("Lottery / Prize / Financial Scam",
     ["congratulations", "winner", "lottery", "prize", "you've won", "claim reward",
      "free gift", "gift card", "bonus credit", "cash prize", "selected winner",
      "lucky winner", "winning notification", "tax refund", "irs refund",
      "inheritance", "unclaimed funds"]),
    ("Tech Support Scam",
     ["support call", "call now", "technical support", "help desk", "system alert",
      "firewall", "antivirus", "subscription expired", "renewal", "fake antivirus",
      "security warning", "virus detected", "infected"]),
    ("Sextortion / Coercion",
     ["bitcoin", "cryptocurrency", "wallet", "btc", "ethereum", "crypto",
      "ransom", "compromise", "webcam", "browsing history", "private information"]),
]

_SOCIAL_ENGINEERING_PATTERNS = {
    "Urgency / Time Pressure": [
        "urgent", "immediate", "asap", "critical", "deadline", "expires",
        "final notice", "last chance", "limited time", "act now", "click now",
        "respond now", "time sensitive", "don't delay", "suspended", "locked",
    ],
    "Authority / Executive Impersonation": [
        "ceo", "cfo", "director", "board", "manager", "supervisor",
        "head of", "vice president", "vp ", "chief", "executive",
        "urgent request from", "request from the ceo", "from the desk of",
        "private", "confidential",
    ],
    "Fear / Threat Induction": [
        "account compromised", "unauthorized access", "suspicious activity",
        "security alert", "breach", "hacked", "terminated", "lawsuit",
        "legal action", "frozen", "locked", "suspended", "restricted",
    ],
    "Scarcity / Limited Opportunity": [
        "limited offer", "only a few left", "while supplies last",
        "exclusive", "special offer", "one-time", "not available elsewhere",
        "invitation only", "private sale", "early access",
    ],
    "Reciprocity / Trust": [
        "gift", "free", "bonus", "reward", "prize", "congratulations",
        "valued customer", "loyalty", "appreciation", "special bonus",
        "welcome", "thank you for being",
    ],
    "Social Proof": [
        "200,000 customers", "thousands of", "millions of users",
        "top rated", "5 star", "industry leading", "most popular",
        "trusted by", "used by millions",
    ],
    "Likeability / Familiarity": [
        "dear customer", "dear user", "dear valued", "dear sir",
        "dear friend", "hello friend", "hi friend", "dear winner",
    ],
}


def _detect_attack_type(body_text: str, subject: str, attachments, ml_r: Dict) -> List[str]:
    """Return ranked list of detected attack types based on content signals."""
    combined = (subject + " " + body_text).lower()
    scores = {}
    for name, keywords in _THREAT_ATTACK_TYPES:
        score = 0
        for kw in keywords:
            if kw.lower() in combined:
                score += 1
        score += len(ml_r.get("suspicious_keywords_found", {}).get("critical", [])) * 2
        if attachments:
            if any(a.get("is_malicious_ext") for a in attachments if isinstance(a, dict)):
                score += 5
        scores[name] = score
    sorted_types = sorted(scores.items(), key=lambda x: -x[1])
    return [t for t, s in sorted_types if s > 0][:3]


def _detect_social_engineering(body_text: str, subject: str, ml_r: Dict) -> List[str]:
    """Infer social engineering tactics from content signals."""
    combined = (subject + " " + body_text).lower()
    detected = []
    critical_kw = set(ml_r.get("suspicious_keywords_found", {}).get("critical", []))
    high_kw = set(ml_r.get("suspicious_keywords_found", {}).get("high", []))
    all_kw = critical_kw | high_kw

    for tactic, patterns in _SOCIAL_ENGINEERING_PATTERNS.items():
        if any(p.lower() in combined for p in patterns):
            detected.append(tactic)
    if ml_r.get("phishing_probability", 0) >= 0.7:
        if "Urgency / Time Pressure" not in detected:
            detected.insert(0, "Urgency / Time Pressure")
    if all_kw & {"password", "login", "verify", "account"}:
        if "Authority / Executive Impersonation" not in detected:
            detected.insert(0, "Authority / Executive Impersonation")
    return list(dict.fromkeys(detected))[:5]


def _assess_auth(auth_val: str, auth_name: str) -> Optional[str]:
    """Generate a one-sentence human-readable auth verdict."""
    if auth_val == "pass":
        return f"{auth_name} passed — the sending server is authorized for this domain, indicating legitimate sending infrastructure."
    elif auth_val == "fail":
        return f"{auth_name} failed — the sending server is not authorized for this domain, a strong indicator of spoofing."
    elif auth_val in ("softfail", "neutral"):
        return f"{auth_name} is uncertain/neutral — the authorization result is ambiguous, common in forwarded or secondary-server emails."
    elif auth_val == "none":
        return f"{auth_name} produced no result — no authentication record was published for this domain, making sender legitimacy unverifiable."
    return None


def _infer_additional_iocs(
    body_text: str, subject: str, sender_domain: str, parsed: Dict, header_r: Dict
) -> List[str]:
    """Infer extra IOCs that the main extractor might miss."""
    iocs = []
    combined = (subject + " " + body_text).lower()

    # Typosquat lookalikes
    if sender_domain:
        for brand, variants in LOOKALIKE_MAP.items():
            if brand in combined and not any(v in sender_domain for v in variants):
                for v in variants:
                    if v in combined:
                        iocs.append(f"Potential typosquat of '{brand}': lookalike pattern '{v}' found in content")
                        break

    # Bitcoin address
    btc = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', combined)
    if btc:
        iocs.append(f"Bitcoin address detected: {btc[0][:20]}... (potential ransom)")
    # Phone number
    phone = re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', combined)
    if phone:
        iocs.append(f"Phone number detected: {phone[0]} (potential vishing callback)")
    # SSN-like
    ssn_like = re.findall(r'\b\d{3}-\d{2}-\d{4}\b', combined)
    if ssn_like:
        iocs.append("SSN-like pattern detected — potential identity theft material")
    # Reply-To mismatch
    reply_to = parsed.get("reply_to", "")
    from_dom = sender_domain
    if reply_to and from_dom:
        reply_dom = _extract_domain(reply_to)
        if reply_dom and reply_dom != from_dom:
            iocs.append(f"Reply-To domain mismatch: From={from_dom}, Reply-To={reply_dom} — classic BEC indicator")
    # Suspicious local paths
    for path in re.findall(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\r\n]*', combined):
        if any(ext in path.lower() for ext in [".exe", ".bat", ".ps1", ".vbs"]):
            iocs.append(f"Suspicious local file path in body: {path[:60]}")
            break
    # Header injection signal
    if re.search(r'from:\s*"?\w', body_text[:500], re.I):
        iocs.append("Possible email header injection detected in early body content")
    return iocs[:5]


def _build_rule_based_assessment(
    parsed: Dict, risk_r: Dict, header_r: Dict,
    url_r: Dict, attach_r: Dict, ml_r: Dict, iocs: List[Dict],
) -> Dict[str, Any]:
    """Generate narrative threat assessment fields from existing analysis signals."""
    body_text = (parsed.get("body_text") or "") + (parsed.get("body_html") or "")
    subject = parsed.get("subject", "")
    sender_domain = parsed.get("sender_domain", "")

    # Detect attack type
    attack_types = _detect_attack_type(body_text, subject, parsed.get("attachments", []), ml_r)
    primary_attack = attack_types[0] if attack_types else "Uncategorized Threat"

    # Severity adjectives
    risk_score = (risk_r.get("risk_score", 0) * 100) if risk_r else 0
    if risk_score >= 70:
        severity = "high-severity"
        risk_adj = "a likely malicious"
    elif risk_score >= 40:
        severity = "suspicious"
        risk_adj = "a suspicious"
    else:
        severity = "low-risk"
        risk_adj = "a mostly safe"

    verdict_label = (risk_r.get("verdict", "unknown") if risk_r else "unknown").upper()
    ml_prob = ml_r.get("phishing_probability", 0)
    url_mal = url_r.get("malicious", 0) if url_r else 0
    att_mal = len((attach_r or {}).get("malicious", []))

    parts = [f"Classified as {risk_adj} {severity} email ({verdict_label}, {int(ml_prob * 100)}% ML phishing probability)."]
    if attack_types:
        parts.append(f"Primary threat: {primary_attack}.")
    if url_mal > 0:
        parts.append(f"{url_mal} malicious URL(s) identified in message body.")
    if att_mal > 0:
        parts.append(f"{att_mal} dangerous attachment(s) detected.")
    if not attack_types and url_mal == 0 and att_mal == 0:
        parts.append("No definitive attack pattern identified from structural signals.")

    tactics = _detect_social_engineering(body_text, subject, ml_r)

    spf_val = (header_r or {}).get("spf")
    dkim_val = (header_r or {}).get("dkim")
    dmarc_val = (header_r or {}).get("dmarc")

    return {
        "enabled": True,
        "model": "rule-based (local)",
        "threat_assessment": " ".join(parts),
        "social_engineering_tactics": tactics,
        "spf_assessment": _assess_auth(spf_val, "SPF") if spf_val else None,
        "dkim_assessment": _assess_auth(dkim_val, "DKIM") if dkim_val else None,
        "dmarc_assessment": _assess_auth(dmarc_val, "DMARC") if dmarc_val else None,
        "additional_iocs": _infer_additional_iocs(body_text, subject, sender_domain, parsed, header_r),
    }


def _enrich_with_llm(parsed, risk_r, header_r, url_r, attach_r, ml_r, iocs) -> Dict[str, Any]:
    """Generate threat insights using local rule-based engine (no external APIs)."""
    return _build_rule_based_assessment(parsed, risk_r, header_r, url_r, attach_r, ml_r, iocs)


# ─── IOC Graph ────────────────────────────────────────────────────────────────

def build_ioc_graph(parsed: Dict, risk: Dict, url_r: Dict = None) -> Dict[str, Any]:
    """
    Build IOC graph with per-IOC verdicts independent of overall scan verdict.

    Design rules:
    - URL risk -> from url_analysis rule-based verdict (analyze_single_url).
      A safe URL stays safe even if the overall scan verdict is malicious.
    - IP risk  -> private/reserved IP = threat; public IP with no signal = safe.
    - Domain risk -> from header auth analysis (SPF/DKIM/DMARC pass = safe).
    - Hash risk  -> malicious extension (.exe/.ps1/.vbs etc.) = threat.

    Node colours: safe=#10b981 (green), threat=#ef4444 (red), suspicious=#f59e0b (amber).
    """
    nodes, edges = [], []
    RISK_COLOR = {"safe": "#10b981", "threat": "#ef4444", "suspicious": "#f59e0b"}
    _KNOWN_SAFE = {
        "google.com", "accounts.google.com", "github.com", "microsoft.com",
        "live.com", "outlook.com", "apple.com", "amazon.com", "paypal.com",
        "stripe.com", "shopify.com", "slack.com", "zoom.us", "dropbox.com",
        "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
    }

    def _url_risk(value: str) -> str:
        if not url_r:
            return "safe"
        if value in (url_r.get("high_risk") or []):
            return "threat"
        if value in (url_r.get("suspicious_urls") or []):
            return "threat"
        if value in (url_r.get("shortener_urls") or []):
            return "threat"
        for u in url_r.get("urls", []):
            if isinstance(u, dict) and u.get("url") == value:
                return u.get("verdict", "safe")
        return "safe"

    def _ip_risk(value: str) -> str:
        import re as _re
        if _re.match(r"^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)", value):
            return "threat"
        return "safe"

    def _domain_risk(domain: str) -> str:
        if domain in _KNOWN_SAFE or any(domain.endswith("." + kd) for kd in _KNOWN_SAFE):
            return "safe"
        auth = parsed.get("auth_status", {})
        overall = auth.get("overall_auth", "none") if isinstance(auth, dict) else "none"
        return "threat" if overall in ("none", "weak") else "safe"

    def _hash_risk(sha256: str) -> str:
        if not sha256:
            return "safe"
        for att in parsed.get("attachments", []) or []:
            if att.get("sha256") == sha256:
                fname = att.get("filename", "").lower()
                for ext in (".exe",".bat",".cmd",".ps1",".vbs",".wsf",".hta",".scr",
                             ".com",".pif",".lnk",".js",".jar",".msi",".dll",".sys"):
                    if fname.endswith(ext):
                        return "threat"
        return "safe"

    sender = parsed.get("sender_email", "unknown@unknown.com")
    nodes.append({
        "id": "n_email", "label": sender[:35], "type": "email",
        "risk": "safe", "color": RISK_COLOR["safe"], "value": sender,
    })

    if domain := parsed.get("sender_domain", ""):
        dr = _domain_risk(domain)
        nodes.append({
            "id": "n_domain0", "label": domain, "type": "domain",
            "risk": dr, "color": RISK_COLOR.get(dr, "#8b5cf6"), "value": domain,
        })
        edges.append({"source": "n_email", "target": "n_domain0", "label": "from"})

    for i, url in enumerate(parsed.get("urls", [])[:8]):
        rr = _url_risk(url)
        label = url[8:43] + "…" if len(url) > 43 else url[8:]
        nodes.append({
            "id": f"n_url{i}", "label": label, "type": "url",
            "risk": rr, "color": RISK_COLOR.get(rr, "#3b82f6"), "value": url,
        })
        edges.append({"source": "n_email", "target": f"n_url{i}", "label": "link"})

    for i, ip in enumerate(parsed.get("extracted_ips", [])[:4]):
        pr = _ip_risk(ip)
        nodes.append({
            "id": f"n_ip{i}", "label": ip, "type": "ip",
            "risk": pr, "color": RISK_COLOR.get(pr, "#f97316"), "value": ip,
        })
        edges.append({"source": "n_email", "target": f"n_ip{i}", "label": "routes"})

    for i, att in enumerate(parsed.get("attachments", [])[:4]):
        hr = _hash_risk(att.get("sha256", ""))
        nodes.append({
            "id": f"n_hash{i}", "label": att.get("filename", "file")[:20],
            "type": "hash", "risk": hr,
            "color": RISK_COLOR.get(hr, "#ec4899"),
            "value": att.get("sha256", ""),
        })
        edges.append({"source": "n_email", "target": f"n_hash{i}", "label": "attach"})

    return {"nodes": nodes, "edges": edges}


# ─── Main Pipeline ────────────────────────────────────────────────────────────

def run_analysis(content: bytes, filename: str = "email.eml", tier2_consent: bool = False) -> Dict[str, Any]:
    """Full analysis pipeline. Returns complete result dict."""
    scan_id = str(uuid.uuid4())
    t0 = time.time()

    parsed     = parse_email_bytes(content, filename)

    # Extract message object for authentication verification
    msg = None
    try:
        msg = message_from_bytes(content, policy=email.policy.default)
    except Exception:
        try:
            msg = message_from_bytes(content)
        except Exception:
            pass

    # Perform comprehensive email authentication analysis
    auth_analysis = analyze_email_authentication(msg, parsed) if msg else {"spf_status": parsed.get("spf"), "dkim_status": parsed.get("dkim")}

    header_r   = analyze_headers(parsed)
    url_r      = analyze_urls(parsed.get("urls", []))
    attach_r   = analyze_attachments(parsed.get("attachments", []))
    ml_r       = classify_phishing(parsed)

    # Remove known-safe service URLs/domains from IOCs so that GitHub, Google,
    # etc. don't appear as threat indicators. Uses the same domain list as the
    # URL scorer to stay consistent. Score-based filtering is intentionally
    # avoided here — a low-scoring URL on an unknown domain is still an IOC.
    _KNOWN_SAFE = {
        "google.com", "accounts.google.com", "github.com", "microsoft.com",
        "live.com", "outlook.com", "apple.com", "amazon.com", "paypal.com",
        "stripe.com", "shopify.com", "slack.com", "zoom.us", "dropbox.com",
        "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
    }
    def _domain_is_safe(domain: str) -> bool:
        return any(domain == kd or domain.endswith("." + kd) for kd in _KNOWN_SAFE)

    parsed["iocs"] = [
        ioc for ioc in parsed.get("iocs", [])
        if not (ioc["type"] == "domain" and _domain_is_safe(ioc["value"]))
        and not (ioc["type"] == "url" and _domain_is_safe(
            ioc["value"].split("/")[2].split(":")[0] if "//" in ioc["value"] else ""
        ))
    ]

    # Semantic NLP — local DistilBERT, no data leaves this server
    from ml.semantic_classifier import classify_semantic
    sem_r = classify_semantic(parsed.get("subject", ""), parsed.get("body_text", ""))

    # Known-safe IPs (public CDNs, trusted services) — mark as safe, not filtered
    _KNOWN_SAFE_IPS = {
        "8.8.8.8", "8.8.4.4",        # Google DNS
        "1.1.1.1", "1.0.0.1",        # Cloudflare DNS
        "9.9.9.9",                   # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "4.2.2.1", "4.2.2.2",        # Level3
    }

    # Suppress threat-intel verdict override for trusted service IOCs
    # so that e.g. a URL on an established domain that scores medium on heuristics
    # (but is actually a legitimate login link) is not force-labelled as threat
    # just because the overall scan verdict is malicious.
    def _is_trusted_service(value: str, ioc_type: str) -> bool:
        if ioc_type == "url":
            domain = value.split("//")[1].split("/")[0].split(":")[0] if "//" in value else ""
            return any(domain == kd or domain.endswith("." + kd) for kd in _KNOWN_SAFE)
        if ioc_type == "ip":
            return value in _KNOWN_SAFE_IPS
        return False

    # ── Threat Intelligence enrichment (live API lookups) ───────────────────
    # Runs BEFORE risk calculation so API verdicts can influence the score.
    # Only activates when user has explicitly consented (tier2_consent).
    ioc_intel = {}
    threat_intel = {}

    if tier2_consent:
        try:
            from threat_intel import (
                enrich_ioc_scores,
                enrich_with_threat_intel,
                parse_email_headers,
                analyze_attachment,
            )

            # Extract originating IP from headers
            import re as _re
            ip_match = None
            for line in content.split(b"\n"):
                decoded = line.decode("utf-8", errors="ignore")
                m = _re.search(r"X-Originating-IP[\s:]*\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?", decoded, _re.I)
                if m:
                    ip_match = m.group(1)
                    break

            # Build list of URLs to check — prioritize high-risk / suspicious / threat
            urls_to_check = (
                list(url_r.get("high_risk") or []) +
                list(url_r.get("suspicious_urls") or []) +
                [u["url"] for u in url_r.get("urls", []) if u.get("verdict") == "threat"]
            )
            urls_to_check = list(dict.fromkeys(urls_to_check))[:8]  # dedupe, cap at 8

            # Structured per-IOC scores (URLs, IP, domain) — used in calculate_risk
            ioc_intel = enrich_ioc_scores(
                urls=urls_to_check,
                ip=ip_match,
                sender_domain=parsed.get("sender_domain"),
            )

            # Legacy enrichment dict (header deep-dive, raw API responses) — stored in result
            threat_intel["header_deep_dive"] = parse_email_headers(content)
            threat_intel["enrichment"] = enrich_with_threat_intel(
                urls=urls_to_check,
                ip=ip_match,
                email_from=parsed.get("sender_email", ""),
            )

            # Enrich attachment objects with hash lookup results before risk calculation
            for att in parsed.get("attachments", []):
                sha = att.get("sha256")
                if sha:
                    ti = analyze_attachment(b"", att.get("filename", ""))
                    ti["sha256"]          = sha
                    ti["md5"]             = att.get("md5", "")
                    ti["sha1"]            = att.get("sha1", "")
                    ti["size_bytes"]      = att.get("size_bytes", 0)
                    ti["detected_type"]   = att.get("content_type", "unknown")
                    att["threat_intel"]   = ti
                    # Also store in attach_r so calculate_risk can read it
                    for bucket in (attach_r.get("all") or []):
                        if bucket.get("sha256") == sha:
                            bucket["threat_intel"] = ti

        except ImportError:
            logger.warning("threat_intel module not available — skipping enrichment")
            threat_intel["skipped"] = "module unavailable"
        except Exception as e:
            logger.warning("Threat intel enrichment failed: %s", e)
            threat_intel["error"] = str(e)[:80]
    else:
        threat_intel["skipped"] = "External enrichment disabled — enable in Settings > Privacy"

    risk_r = calculate_risk(header_r, url_r, attach_r, ml_r, sem_r, ioc_intel=ioc_intel)

    return {
        "scan_id":   scan_id,
        "filename":  filename,
        "duration":  round(time.time() - t0, 3),
        "timestamp": datetime.utcnow().isoformat(),

        # Email metadata
        "meta": {
            "sender":        parsed.get("sender",""),
            "sender_email":  parsed.get("sender_email",""),
            "sender_domain": parsed.get("sender_domain",""),
            "recipient":     parsed.get("recipient",""),
            "subject":       parsed.get("subject",""),
            "date":          parsed.get("date",""),
            "reply_to":      parsed.get("reply_to",""),
            # body_text intentionally excluded — never persisted to protect client data privacy
        },

        # Results
        "risk_score":      risk_r["risk_score"],
        "verdict":         risk_r["verdict"],
        "color":           risk_r["color"],
        "recommendations": risk_r["recommendations"],
        "breakdown":       risk_r["breakdown"],

        "header_analysis":     header_r,
        "authentication":      auth_analysis,
        "url_analysis":        url_r,
        "attachment_analysis": attach_r,
        "ml_analysis":         ml_r,
        "semantic_analysis":   sem_r,

        "iocs":      parsed.get("iocs",[]),
        "ioc_graph": build_ioc_graph(parsed, risk_r, url_r),

        "url_count":    len(parsed.get("urls",[])),
        "attach_count": len(parsed.get("attachments",[])),

        "threat_intel": threat_intel,

        # Generate analysis summary
        "analysis_summary": generate_summary(risk_r, ml_r, url_r, attach_r, parsed.get("iocs", [])),

        # LLM narrative — gpt-4o-mini threat assessment (triggered after rule-based scoring)
        "narrative": _enrich_with_llm(parsed, risk_r, header_r, url_r, attach_r, ml_r, parsed.get("iocs", [])),
    }

def generate_summary(verdict_r, ml_r, url_r, attach_r, iocs):
    """Generate a human-readable analysis summary."""
    parts = []

    verdict = verdict_r.get("verdict", "unknown")
    risk_score = verdict_r.get("risk_score", 0)
    parts.append(f"Verdict: {verdict.upper()} (Risk Score: {risk_score}/100)")

    ml_cls = ml_r.get("classification", "unknown")
    ml_prob = ml_r.get("phishing_probability", 0)
    parts.append(f"ML Detection: {ml_cls} ({ml_prob:.0%} phishing probability)")

    # Unsafe keywords — always surface these so the user knows exactly what triggered the alert
    kw = ml_r.get("suspicious_keywords_found", {})
    critical_kw = kw.get("critical", [])
    high_kw = kw.get("high", [])
    if critical_kw:
        parts.append(f"Critical threats detected: {', '.join(critical_kw[:6])}")
    if high_kw:
        parts.append(f"High-risk keywords: {', '.join(high_kw[:6])}")

    # URL analysis — use counts from analyses list (suspicious_urls/malicious_urls keys don't exist)
    mal_urls = url_r.get("malicious", 0)
    sus_urls = url_r.get("suspicious", 0)
    if mal_urls:
        parts.append(f"{mal_urls} malicious URL(s) detected")
    elif sus_urls:
        parts.append(f"{sus_urls} suspicious URL(s) detected")

    # Attachment analysis
    mal_atts = attach_r.get("malicious", [])
    risky_atts = attach_r.get("risky", [])
    if mal_atts:
        parts.append(f"{len(mal_atts)} dangerous attachment(s): {', '.join(a.get('filename','?') for a in mal_atts[:3])}")
    elif risky_atts:
        parts.append(f"{len(risky_atts)} risky attachment(s): {', '.join(a.get('filename','?') for a in risky_atts[:3])}")

    # IOCs
    if iocs:
        parts.append(f"{len(iocs)} indicator(s) of compromise extracted")

    return " | ".join(parts) if parts else "Email analyzed. No threats detected."

# datetime import fixed at top

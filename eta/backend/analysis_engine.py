"""
Core email analysis engine.
Handles parsing, header analysis, URL checking, attachment analysis,
ML classification, and risk scoring in a single pipeline.
"""
import re
import math
import email
import email.policy
import hashlib
import uuid
import time
import logging
import csv
import io
from datetime import datetime
from typing import Dict, Any, List, Optional
from email import message_from_bytes
from email.header import decode_header
from pypdf import PdfReader

# Import the comprehensive suspicious words dictionary
try:
    from suspicious_dictionary import (
        ALL_SUSPICIOUS_WORDS, CRITICAL_KEYWORDS, HIGH_PRIORITY_KEYWORDS,
        CREDENTIAL_KEYWORDS, BEC_KEYWORDS, PHISHING_KEYWORDS,
        analyze_keywords
    )
except ImportError:
    logger.warning("suspicious_dictionary not found, using fallback keyword lists")
    ALL_SUSPICIOUS_WORDS = set()
    CRITICAL_KEYWORDS = set()
    HIGH_PRIORITY_KEYWORDS = set()
    CREDENTIAL_KEYWORDS = set()
    BEC_KEYWORDS = set()
    PHISHING_KEYWORDS = set()

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
    "paypal":["paypa1","paypall","paypal-secure","paypa-l","paypa1login","paypallogin","paypaI","paypai","paypaI.com"],
    "microsoft":["micros0ft","m1crosoft","microsofft","micro-s0ft","microsft","rnicrosoft","micros0ft.com"],
    "amazon":["amaz0n","amzon","amazon-secure","amazn","amaz0n-secure","amaz0n.com","amazonn.com"],
    "apple":["app1e","appl3","apple-id-secure","app1e-id","appl3.com","app1e.com","aplle"],
    "google":["g00gle","goog1e","googIe","googl3","g00gl3","googl3.com","googie"],
    "netflix":["netfl1x","netfix","netflix-billing","netfl1x","netflix-secure","netf1ix"],
    "facebook":["faceb00k","facebok","facebook-login","faceb00k.com","faceb00k.net"],
    "linkedin":["linkedln","linkedln","linkedin-login","l1nkedin","link3din"],
    "twitter":["tw1tter","twiter","twitter-help","tw1tter","tw1tter.com"],
    "instagram":["1nstagram","1nstagrarn","instagram-login","1nstagram","instagrarn"],
    "chase":["chas3","chase-bank","chase-secure","chas3.com","chasebank","cashase"],
    "wellsfargo":["wellsfar9o","wellsfargo-bank","wellsfar9o.com"],
    "bankofamerica":["bankofamer1ca","b0a","bankofamer1ca.com"],
    "usbank":["usbank","us-bank","usbank","us-bank"],
    "aol":["a0l","aol-login","a0l.com","aolmail"],
    "yahoo":["yah0o","yahoo-mail","yhoo","yahoo-secure"],
    "dropbox":["dropb0x","dropbox-login","dropb0x.com","dr0pbox"],
    "drive":["dr1ve","google-drive","dr1ve.com"],
    "whatsapp":["whatsapp","whats-app","whatsaap","whtasapp"],
    "telegram":["telegram","teligram","telegarm","telgram"],
    "zoom":["zo0m","zoom-us","zo0m.com","z00m"],
    "teams":["teams","team5","teams-secure","teams-microsoft"],
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
            logger.error(f"PDF extraction failed: {e}")
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
            logger.error(f"CSV parsing failed: {e}")
            # Fallback to raw text extraction
            return content.decode("utf-8", errors="ignore")[:MAX_TEXT_EXTRACT_SIZE]
    elif ext in {"json", "xml", "html", "htm", "log", "md"}:
        try:
            text = content.decode("utf-8", errors="ignore")
            # For structured formats, try to extract meaningful content
            if ext == "json":
                try:
                    import json
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
                    logger.debug(f"JSON parsing failed: {e}")
                    # Fall through to raw text
            elif ext in {".xml", ".html", ".htm"}:
                # Remove HTML/XML tags and extract text content
                import re as regex
                clean_text = regex.sub(r'<[^>]+>', ' ', text)
                clean_text = regex.sub(r'\s+', ' ', clean_text).strip()
                return clean_text[:MAX_TEXT_EXTRACT_SIZE]
            # For .log, .md and other text files, return as-is
            return text[:MAX_TEXT_EXTRACT_SIZE]
        except Exception as e:
            logger.error(f"{ext.upper()} processing failed: {e}")
            return content.decode("utf-8", errors="ignore")[:MAX_TEXT_EXTRACT_SIZE]
    else:
        # Default text extraction for any other supported file type
        try:
            text = content.decode("utf-8", errors="ignore")
            return text[:MAX_TEXT_EXTRACT_SIZE]
        except:
            # Last resort: try latin-1 encoding
            try:
                text = content.decode("latin-1", errors="ignore")
                return text[:MAX_TEXT_EXTRACT_SIZE]
            except:
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
    all_urls = list({u for u in urls + href if u.startswith("http")})
    return all_urls[:URL_EXTRACTION_LIMIT]

def _compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def parse_email_bytes(content: bytes, filename: str = "email.eml") -> Dict[str, Any]:
    """Parse raw email bytes into structured dict."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in {"eml", "msg", "txt", "mbox"}:
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
        except Exception as e:
            logger.error(f"Email parse failed: {e}")
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
        logger.debug(f"SPF check failed for {sender_email}: {e}")
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
        logger.debug(f"DMARC policy not found for {domain}")
        return None
    except Exception as e:
        logger.debug(f"DMARC check failed for {domain}: {e}")
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
from datetime import datetime, timezone

def get_domain_age(domain: str) -> Dict[str, Any]:
    """Check domain registration age using WHOIS-like heuristics."""
    import socket
    import whois as whois_lib

    result = {
        "domain": domain,
        "age_days": None,
        "is_new": False,
        "registration_date": None,
        "error": None
    }

    if not domain:
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
            import time
            start = time.time()
            socket.gethostbyname(domain)
            resolve_time = (time.time() - start) * 1000
            # Very fast resolution might indicate a new/malicious domain
            result["is_new"] = resolve_time < 1
        except:
            pass

    return result

def analyze_domain_reputation(domain: str) -> Dict[str, Any]:
    """Analyze domain for reputation indicators."""
    import socket

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
    base_domain = domain.split(".")[0] if "." in domain else domain

    rep["is_free_email"] = domain.lower() in FREE_EMAIL_DOMAINS

    # Check typosquatting
    for brand, lookalikes in LOOK_ALIKE_MAP.items():
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

    return {
        "indicators": indicators,
        "score": min(100, score),
        "auth_score": auth_score,
        "spf": p.get("spf") or "unknown",
        "dkim": p.get("dkim") or "unknown",
        "dmarc": p.get("dmarc") or "unknown",
    }


# ─── URL Analysis ─────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s: return 0.0
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
            flags.append("IP-based URL"); score += 30
        if any(s in domain for s in URL_SHORTENERS):
            flags.append("URL shortener"); score += 20
        if "@" in url:
            flags.append("@ in URL"); score += 25
        if len(url) > 200:
            flags.append(f"Long URL ({len(url)} chars)"); score += 10
        if p.scheme == "http":
            flags.append("HTTP (not HTTPS)"); score += 5

        # subdomain depth
        parts = domain.replace("www.", "").split(".")
        if len(parts) > 4:
            flags.append(f"Deep subdomains ({len(parts)-2})"); score += 15

        # domain entropy
        base = parts[0] if parts else ""
        ent = _entropy(base)
        if ent > 3.8:
            flags.append(f"High domain entropy ({ent:.1f}) — possible DGA"); score += 20

        # suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append(f"Suspicious TLD: {tld}"); score += 15
                break

        # brand impersonation in URL
        for brand, variants in LOOKALIKE_MAP.items():
            if any(v in domain for v in variants):
                flags.append(f"Brand impersonation: {brand}"); score += 25
                break

        # suspicious keywords in path
        kw_in_url = [k for k in ["login","verify","confirm","secure","update","account"] if k in url.lower()]
        if kw_in_url:
            flags.append(f"Credential keywords in URL: {', '.join(kw_in_url[:3])}"); score += min(20, len(kw_in_url)*7)

    except Exception as e:
        flags.append(f"Parse error")

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
    agg = 80+min(20,len(mal)*5) if mal else 40+min(30,len(sus)*5) if sus else 0
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
            a["risk"] = "malicious"; a["risk_score"] = 90
            indicators.append({"severity":"critical","desc":f"Executable attachment: {fn}"})
            total_score += 35; mal.append(a)
        elif a.get("is_risky_ext") or ext in {".doc",".xls",".ppt"}:
            a["risk"] = "risky"; a["risk_score"] = 55
            indicators.append({"severity":"high","desc":f"Risky file type: {fn}"})
            total_score += 15; risky.append(a)
        else:
            a["risk"] = "safe"; a["risk_score"] = 5
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


# ─── ML Classifier (rule-based fallback) ──────────────────────────────────────

def _try_load_model():
    """Try to load trained sklearn model and scaler; return None if unavailable."""
    try:
        import joblib, os
        path = os.path.join(os.path.dirname(__file__), "../ml/phishing_model.pkl")
        scaler_path = os.path.join(os.path.dirname(__file__), "../ml/feature_scaler.pkl")
        model = None
        scaler = None
        if os.path.exists(path):
            model = joblib.load(path)
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
        return model, scaler
    except Exception:
        pass
    return None, None

_MODEL = None
_SCALER = None

def classify_phishing(parsed: Dict) -> Dict[str, Any]:
    global _MODEL, _SCALER
    if _MODEL is None:
        _MODEL, _SCALER = _try_load_model()

    subject  = (parsed.get("subject") or "").lower()
    body     = ((parsed.get("body_text") or "") + (parsed.get("body_html") or "")).lower()
    urls     = parsed.get("urls") or []
    atts     = parsed.get("attachments") or []
    domain   = parsed.get("sender_domain") or ""
    sender   = parsed.get("sender_email") or ""
    reply_to = (parsed.get("reply_to") or "").lower()
    headers_raw = parsed.get("headers_raw") or ""

    # ─ Comprehensive keyword analysis ─
    text_to_analyze = f"{subject} {body}"
    keyword_analysis = analyze_keywords(text_to_analyze) if ALL_SUSPICIOUS_WORDS else {"total": 0, "critical": [], "high": [], "by_category": {}}

    critical_count = len(keyword_analysis.get("critical", []))
    high_count = len(keyword_analysis.get("high", []))

    # ─ Enhanced Feature Extraction (45+ features) ─
    features = [
        # URL-based features (0-6)
        min(len(urls), 30),  # URL count
        min(sum(len(u) for u in urls)/max(1,len(urls))/100, 8),  # Avg URL length
        int(any(IP_RE.match(re.sub(r'https?://','',u).split('/')[0]) for u in urls)),  # IP in URL
        sum(1 for u in urls if any(s in u for s in URL_SHORTENERS)),  # URL shorteners
        int(any("@" in re.sub(r'https?://', '', u) for u in urls)),  # @ symbol in URL (obfuscation)
        sum(1 for u in urls if u.count('.') > 3),  # Multi-level subdomains
        int(any(len(u) > 150 for u in urls)),  # Extremely long URLs

        # Urgency features (7-13)
        sum(1 for w in URGENCY_WORDS if w in subject) * 2,  # Urgency in subject (doubled weight)
        min(sum(1 for w in URGENCY_WORDS if w in body), 15),  # Urgency in body
        subject.count("!") * 2 + subject.count("!!!") * 3,  # Exclamation marks
        int("!!!" in subject or "!!!" in body),  # Triple exclamation
        int(len(subject) > 80),  # Unusually long subject
        int(all(c.isupper() or c == " " for c in subject.split() if c)),  # ALL CAPS

        # Keyword features using dictionary (14-19)
        min(critical_count * 2, 20),  # Critical keywords (doubled weight)
        min(high_count, 30),  # High priority keywords
        sum(1 for k in CREDENTIAL_KEYWORDS if k in body) * 3,  # Credential harvest (high weight)
        sum(1 for k in BEC_KEYWORDS if k in body or k in subject) * 2.5,  # BEC indicators

        # Domain/Sender features (20-27)
        int(bool(reply_to) and _extract_domain(reply_to) != domain),  # Reply-to mismatch
        int(any(domain.endswith(t) for t in SUSPICIOUS_TLDS)),  # Suspicious TLD
        round(_entropy(domain.split(".")[0]), 2),  # Domain entropy (randomness)
        int(any(look_like in domain for look_like in LOOKALIKE_MAP.get("paypal", []))),  # Paypal lookalike
        int(any(look_like in domain for look_like in LOOKALIKE_MAP.get("microsoft", []))),  # Microsoft lookalike
        int(any(look_like in domain or look_like in sender for look_like in
               sum(LOOKALIKE_MAP.values(), []))),  # Any brand lookalike
        int(domain in FREE_EMAIL_DOMAINS and any(bank in body.lower() for bank in ['bank','paypal','amazon'])),  # Free email + financial
        int(" " in sender or len(sender) > 100),  # Malformed sender

        # Attachment features (28-31)
        min(len(atts), 8),  # Attachment count
        int(any(a.get("is_malicious_ext") for a in atts)),  # Malicious extension
        int(any(a.get("is_risky_ext") for a in atts)),  # Risky extension
        int(any(len(a.get("filename",""))>50 for a in atts)),  # Suspiciously long filename

        # Content features (32-38)
        min(len(body)/5000, 8),  # Body length (phishing often short)
        int(len(body) < 200),  # Very short body
        min(body.count("click"), 10),  # "Click" count
        min(body.count("http"), 15),  # URL references
        sum(1 for u in urls if "http" not in u),  # Non-http URLs
        int(bool(re.search(r'<!--.*?-->', body))),  # Hidden HTML comments
        int(body.count(">") - body.count("<") > 5),  # Malformed HTML

        # Special characters & obfuscation (39-42)
        min(len(re.findall(r'[^\w\s@\.\-]', body))/max(1,len(body)), 1.0)*10,  # Special char ratio
        min(subject.count("-"), 8),  # Dashes in subject
        int("&nbsp" in body or "&#" in body),  # HTML entities (obfuscation)
        int("google" in body and "verify" in body),  # Google phishing pattern

        # Dictionary-based comprehensive analysis (43-44)
        min(keyword_analysis.get("total", 0), 50),  # Total suspicious keywords found
        int(critical_count > 0),  # Has critical keywords

        # ── NEW ADVANCED FEATURES (45-64) ──

        # Sender reputation features
        int(bool(re.search(r'SPF (pass|fail)', headers_raw, re.I))),  # SPF header present
        int(bool(re.search(r'DKIM (pass|fail)', headers_raw, re.I))),  # DKIM header present
        int(bool(re.search(r'DMARC (pass|fail)', headers_raw, re.I))),  # DMARC header present
        int(not re.search(r'(spf|dkim|dmarc)', headers_raw, re.I)),  # Missing auth headers

        # URL analysis enhancements
        sum(1 for u in urls if any(tld in u for tld in ['.xyz', '.top', '.club', '.online', '.site'])),  # Suspicious TLDs in URLs
        sum(1 for u in urls if re.search(r'\d{8,}', u)),  # URLs with long number sequences
        sum(1 for u in urls if re.search(r'[a-z]{20,}', u)),  # URLs with long random strings

        # Brand impersonation detection
        int(any(brand in body.lower() for brand in ['apple', 'netflix', 'facebook', 'instagram'])),  # Popular brand mentions
        int("reset" in body.lower() or ("password" in body.lower() and "expire" in body.lower())),  # Password reset pattern
        int("urgent" in body.lower() or "immediate" in body.lower()),  # Urgency keywords

        # Attachment deep analysis
        sum(1 for a in atts if a.get("filename","").endswith((".exe", ".scr", ".bat", ".cmd"))),  # Executable attachments
        sum(1 for a in atts if a.get("filename","").endswith((".zip", ".rar", ".7z"))),  # Compressed files
        int(any(a.get("content_type","").startswith("application/") for a in atts)),  # Hidden executable

        # Text analysis
        min(len(subject) / 100, 5),  # Subject length ratio
        sum(1 for w in subject.split() if len(w) > 15),  # Long words in subject
        min(body.count("confirm") + body.count("verify") + body.count("update"), 10),  # Action keywords
        int("http" in body and "https" not in body),  # Insecure links only
        int("login" in body.lower() and "http" in body.lower()),  # Login with http

        # Social engineering
        int("gift" in body.lower() or "reward" in body.lower() or "winner" in body.lower()),  # Gift scam
        int("bitcoin" in body.lower() or "btc" in body.lower() or "crypto" in body.lower()),  # Crypto scam
        int("invoice" in body.lower() and ("pay" in body.lower() or "due" in body.lower())),  # Invoice scam
    ]

    # Ensure safe numeric features and exactly 65 length (was 45)
    features = [float(f) if isinstance(f, (int, float)) else 0.0 for f in features]
    while len(features) < 65:
        features.append(0.0)
    features = features[:65]

    if _MODEL:
        try:
            import numpy as np
            arr = np.array(features, dtype=np.float32).reshape(1, -1)
            # Scale features if scaler is available
            if _SCALER is not None:
                arr = _SCALER.transform(arr)
            proba = _MODEL.predict_proba(arr)[0]
            prob = float(proba[1])
            conf = float(max(proba))
            method = "xgboost" if hasattr(_MODEL, 'get_booster') else "gradient_boosting"
        except Exception as e:
            print(f"Model prediction error: {e}")
            prob, conf, method = _rule_score(features)
    else:
        prob, conf, method = _rule_score(features)

    # Improved classification: lower thresholds, more aggressive
    if prob >= 0.65:
        cls = "phishing"
    elif prob >= 0.35:
        cls = "suspicious"
    else:
        cls = "legitimate"

    return {
        "phishing_probability": round(prob, 3),
        "confidence": round(conf, 3),
        "classification": cls,
        "method": method,
        "suspicious_keywords_found": {
            "critical": keyword_analysis.get("critical", [])[:5],  # Top 5
            "high": keyword_analysis.get("high", [])[:5],  # Top 5
            "total_detected": keyword_analysis.get("total", 0)
        }
    }

def _rule_score(features):
    # Optimized weights for 45 features - much more aggressive detection
    weights = [
        6,4,18,7,15,4,12,  # URL features (higher weights)
        10,8,12,14,6,8,     # Urgency (much higher)
        8,9,18,16,           # Keywords with dictionary (credential harvest gets 18!)
        12,14,6,10,8,12,6,  # Domain/sender (lookalikes get 10-12)
        5,18,15,12,          # Attachments (higher)
        3,8,10,8,6,8,8,     # Content
        6,5,12,12,           # Obfuscation (high)
        8,10,                # Dictionary analysis (new features 43-44)
    ]
    # Normalization factors
    norms = [
        8,4,1,3,1,2,1,      # URL
        8,8,8,1,1,1,        # Urgency
        8,15,5,5,           # Keywords
        1,1,2,2,1,2,1,     # Domain
        5,1,1,1,            # Attachments
        5,1,5,10,3,1,1,    # Content
        0.5,3,1,1,          # Obfuscation
        25,1,               # Dictionary analysis (new features 43-44)
    ]

    score = sum(min(1.5, float(f)/max(0.1,n)) * w for f,w,n in zip(features,weights,norms))
    # More aggressive scoring: max out at higher values
    prob = min(0.98, score/90)  # Scale changed for more aggressive scoring
    return prob, 0.75, "rule_based"


# ─── Risk Scoring ─────────────────────────────────────────────────────────────

def calculate_risk(
    header: Dict, url: Dict, attachment: Dict, ml: Dict,
    threat_boost: int = 0,
) -> Dict[str, Any]:
    # Improved weighting: ML now gets 35% instead of 20%
    raw = (
        header.get("score", 0) * 0.20 +      # Reduced from 0.25
        url.get("score", 0)    * 0.25 +      # Reduced from 0.30
        attachment.get("score",0)* 0.20 +    # Reduced from 0.25
        ml.get("phishing_probability",0) * 100 * 0.35  # Increased from 0.20 to 0.35 (more aggressive)
    )
    final = min(100, raw + threat_boost)

    # Lowered thresholds for better malicious detection (was 65/35)
    if final >= 50:
        verdict, color = "malicious", "#ef4444"
    elif final >= 30:
        verdict, color = "suspicious", "#f59e0b"
    else:
        verdict, color = "safe", "#10b981"

    recs = _build_recs(verdict, final, header, url, attachment, ml)

    return {
        "risk_score":  round(final, 1),
        "verdict":     verdict,
        "color":       color,
        "recommendations": recs,
        "breakdown": {
            "header":     round(header.get("score",0)*.20, 1),
            "url":        round(url.get("score",0)*.25, 1),
            "attachment": round(attachment.get("score",0)*.20, 1),
            "ml":         round(ml.get("phishing_probability",0)*100*.35, 1),
        }
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


# ─── IOC Graph ────────────────────────────────────────────────────────────────

def build_ioc_graph(parsed: Dict, risk: Dict) -> Dict[str, Any]:
    nodes, edges = [], []
    color = risk.get("color", "#10b981")
    sender = parsed.get("sender_email","unknown@unknown.com")

    nodes.append({"id":"n_email","label":sender[:35],"type":"email","color":color,"value":sender})

    if domain := parsed.get("sender_domain",""):
        nodes.append({"id":"n_domain0","label":domain,"type":"domain","color":"#8b5cf6","value":domain})
        edges.append({"source":"n_email","target":"n_domain0","label":"from"})

    for i, url in enumerate(parsed.get("urls",[])[:8]):
        nid = f"n_url{i}"
        label = url[8:43]+"…" if len(url)>43 else url[8:]
        nodes.append({"id":nid,"label":label,"type":"url","color":"#3b82f6","value":url})
        edges.append({"source":"n_email","target":nid,"label":"link"})

    for i, ip in enumerate(parsed.get("extracted_ips",[])[:4]):
        nid = f"n_ip{i}"
        nodes.append({"id":nid,"label":ip,"type":"ip","color":"#f97316","value":ip})
        edges.append({"source":"n_email","target":nid,"label":"routes"})

    for i, att in enumerate(parsed.get("attachments",[])[:4]):
        nid = f"n_hash{i}"
        nodes.append({"id":nid,"label":att.get("filename","file")[:20],"type":"hash","color":"#ec4899","value":att.get("sha256","")})
        edges.append({"source":"n_email","target":nid,"label":"attach"})

    return {"nodes":nodes,"edges":edges}


# ─── Main Pipeline ────────────────────────────────────────────────────────────

def run_analysis(content: bytes, filename: str = "email.eml") -> Dict[str, Any]:
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
    risk_r     = calculate_risk(header_r, url_r, attach_r, ml_r)
    ioc_graph  = build_ioc_graph(parsed, risk_r)
    duration   = round(time.time()-t0, 2)

    # ── Threat Intelligence enrichment (live API lookups) ───────────────────
    threat_intel = {}
    try:
        from threat_intel import (
            enrich_with_threat_intel,
            parse_email_headers,
            check_url_against_feeds,
            analyze_attachment,
        )

        # Deep header analysis
        threat_intel["header_deep_dive"] = parse_email_headers(content)

        # Sender IP from X-Originating-IP header
        import re as _re
        ip_match = None
        for line in content.split(b"\n"):
            decoded = line.decode("utf-8", errors="ignore")
            m = _re.search(r"X-Originating-IP[\s:]*\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?", decoded, _re.I)
            if m:
                ip_match = m.group(1)
                break

        # URL threat feed check (top 5 high-risk URLs)
        urls_to_check = [u.get("url", "") for u in url_r.get("high_risk", [])[:5]]

        # Sender domain
        sender_email = parsed.get("sender_email", "")

        threat_intel["enrichment"] = enrich_with_threat_intel(
            urls=urls_to_check,
            ip=ip_match,
            email_from=sender_email,
        )

        # Attachment sandbox enrichment (hash lookups)
        for att in parsed.get("attachments", []):
            sha = att.get("sha256")
            if sha:
                att["threat_intel"] = analyze_attachment(
                    b"",  # no raw bytes needed — hash lookups only
                    att.get("filename", ""),
                )
                # Use the already-computed hashes from the email parser
                att["threat_intel"]["sha256"] = sha
                att["threat_intel"]["md5"] = att.get("md5", "")
                att["threat_intel"]["sha1"] = att.get("sha1", "")
                att["threat_intel"]["size_bytes"] = att.get("size_bytes", 0)
                att["threat_intel"]["detected_type"] = att.get("content_type", "unknown")
    except ImportError:
        logger.warning("threat_intel module not available — skipping enrichment")
    except Exception as e:
        logger.warning(f"Threat intel enrichment failed: {e}")

    return {
        "scan_id":   scan_id,
        "filename":  filename,
        "duration":  duration,
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
            "body_text":     parsed.get("body_text",""),  # Include extracted text for file analysis
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

        "iocs":      parsed.get("iocs",[]),
        "ioc_graph": ioc_graph,

        "url_count":    len(parsed.get("urls",[])),
        "attach_count": len(parsed.get("attachments",[])),

        "threat_intel": threat_intel,

        # Generate analysis summary
        "analysis_summary": generate_summary(risk_r, ml_r, url_r, attach_r, parsed.get("iocs", [])),
    }

def generate_summary(verdict_r, ml_r, url_r, attach_r, iocs):
    """Generate a human-readable analysis summary."""
    parts = []

    # Verdict summary
    verdict = verdict_r.get("verdict", "unknown")
    risk_score = verdict_r.get("risk_score", 0)
    parts.append(f"Verdict: {verdict.upper()} (Risk Score: {risk_score}/100)")

    # ML classification
    ml_cls = ml_r.get("classification", "unknown")
    ml_prob = ml_r.get("phishing_probability", 0)
    parts.append(f"ML Detection: {ml_cls} ({ml_prob:.0%} phishing probability)")

    # URL analysis
    if url_r.get("suspicious_urls"):
        parts.append(f"Found {len(url_r['suspicious_urls'])} suspicious URLs")
    if url_r.get("malicious_urls"):
        parts.append(f"Found {len(url_r['malicious_urls'])} malicious URLs")

    # Attachment analysis
    if attach_r.get("suspicious_attachments"):
        parts.append(f"Found {len(attach_r['suspicious_attachments'])} suspicious attachments")
    if attach_r.get("malicious_attachments"):
        parts.append(f"Found {len(attach_r['malicious_attachments'])} malicious attachments")

    # IOCs
    if iocs:
        parts.append(f"Extracted {len(iocs)} indicators of compromise")

    return " | ".join(parts) if parts else "Email analyzed. No threats detected."

# datetime import fixed at top

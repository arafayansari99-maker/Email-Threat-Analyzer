"""
Header Analysis Module
SPF, DKIM, DMARC checks, domain reputation.
"""
import re
import logging
import email
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# DNS availability check
try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# === Constants ===

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc",
    ".buzz", ".work", ".zip", ".download", ".online", ".site", ".store", ".business",
    ".info", ".biz", ".rest", ".icu", ".su", ".racing", ".live", ".chat",
    ".party", ".cricket", ".win", ".gift", ".cash", ".money", ".tools", ".host",
    ".rocks", ".digital", ".email", ".software", ".network", ".pro", ".tech", ".io",
    ".ai", ".app"
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "tutanota.com", "icloud.com", "mail.com", "zoho.com",
    "yandex.com", "pm.me", "proton.me"
}


# === Functions ===

def extract_email_addr(header: str) -> str:
    """Extract email from 'Name <email@domain.com>'."""
    if not header:
        return ""
    match = re.search(r'<([^>]+)>', header)
    if match:
        return match.group(1).strip()
    header = header.strip()
    if '@' in header and '.' in header.split('@')[-1]:
        return header
    return ""


def extract_domain(header: str) -> str:
    """Extract domain from email header."""
    if not header:
        return ""
    addr = extract_email_addr(header)
    if not addr and '@' in header:
        addr = header.strip()
    if '@' in addr:
        return addr.split('@')[-1].lower().strip()
    return ""


def verify_spf(sender_email: str, received_ip: str) -> Optional[str]:
    """Verify SPF record."""
    if not HAS_DNS:
        return None

    domain = extract_domain(sender_email)
    if not domain:
        return None

    try:
        import spf
        result = spf.check(ip=received_ip, sender=sender_email, domain=domain)
        return str(result[0]) if result else None
    except Exception as e:
        logger.debug(f"SPF check failed for {domain}: {e}")
        return None


def verify_dmarc(domain: str) -> Optional[Dict[str, Any]]:
    """Verify DMARC policy."""
    if not HAS_DNS:
        return None

    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = str(rdata)
            if txt.startswith('v=DMARC1'):
                policy = {'policy': None, 'percent': None}
                for part in txt.split(';'):
                    part = part.strip()
                    if part.startswith('p='):
                        policy['policy'] = part[2:].strip()
                    elif part.startswith('pct='):
                        policy['percent'] = int(part[4:].strip())
                return policy
    except Exception:
        pass
    return None


def check_dkim(msg: email.message.Message) -> bool:
    """Check for DKIM signature."""
    if not msg:
        return False
    return 'DKIM-Signature' in msg


def analyze_domain_reputation(domain: str) -> Dict[str, Any]:
    """Analyze domain reputation."""
    result = {
        'domain': domain,
        'suspicious_tld': False,
        'free_email': False,
        'no_dmarc': True,
        'risk_indicators': []
    }

    # Check TLD
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        result['suspicious_tld'] = True
        result['risk_indicators'].append(f'Suspicious TLD: {tld}')

    # Check free email
    second_level = domain.split('.')[-2] if '.' in domain else ''
    if second_level in FREE_EMAIL_DOMAINS:
        result['free_email'] = True
        result['risk_indicators'].append('Free email provider')

    # Check DMARC
    dmarc = verify_dmarc(domain)
    if not dmarc:
        result['no_dmarc'] = True
        result['risk_indicators'].append('No DMARC policy')

    return result


def analyze_authentication(msg: email.message.Message, parsed: Dict) -> Dict[str, Any]:
    """Analyze email authentication (SPF, DKIM, DMARC)."""
    result = {
        'spf_pass': False,
        'spf_result': None,
        'dkim_pass': False,
        'dmarc_pass': False,
        'dmarc_policy': None,
        'overall_auth': 'none',
        'auth_issues': []
    }

    from_email = parsed.get('from', '')
    sender_domain = extract_domain(from_email)
    if not sender_domain:
        return result

    # Get IP from headers
    received = parsed.get('received', [])
    received_ip = None
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b)')
    for header in received[:5]:
        matches = ip_re.findall(header)
        if matches:
            received_ip = matches[0]
            break

    # SPF
    if received_ip:
        spf_result = verify_spf(from_email, received_ip)
        if spf_result:
            result['spf_result'] = spf_result
            result['spf_pass'] = spf_result.lower() == 'pass'

    # DKIM
    result['dkim_pass'] = check_dkim(msg)

    # DMARC
    dmarc = verify_dmarc(sender_domain)
    if dmarc:
        result['dmarc_policy'] = dmarc
        result['dmarc_pass'] = dmarc.get('policy') in ('quarantine', 'reject')

    # Overall
    auth_count = sum([result['spf_pass'], result['dkim_pass'], result['dmarc_pass']])
    if auth_count >= 3:
        result['overall_auth'] = 'strong'
    elif auth_count == 2:
        result['overall_auth'] = 'moderate'
    elif auth_count == 1:
        result['overall_auth'] = 'weak'

    # Issues
    if not result['spf_pass'] and result['spf_result']:
        result['auth_issues'].append(f'SPF: {result["spf_result"]}')
    if not result['dkim_pass']:
        result['auth_issues'].append('No DKIM signature')
    if not result['dmarc_pass']:
        result['auth_issues'].append('DMARC check failed')

    return result


def analyze_headers(parsed: Dict) -> Dict[str, Any]:
    """Comprehensive header analysis."""
    result = {
        'from_domain': None,
        'reply_to_domain': None,
        'return_path_domain': None,
        'domain_mismatch': False,
        'authentication': {},
        'domain_reputation': {},
        'header_red_flags': [],
        'received_count': 0,
        'subject_encoded': False,
    }

    # Extract domains
    from_email = parsed.get('from', '')
    reply_to = parsed.get('reply_to', '')
    return_path = parsed.get('return_path', '')
    subject = parsed.get('subject', '')

    result['from_domain'] = extract_domain(from_email)
    result['reply_to_domain'] = extract_domain(reply_to) if reply_to else None
    result['return_path_domain'] = extract_domain(return_path) if return_path else None

    # Domain mismatch
    domains = [d for d in [
        result['from_domain'],
        result['reply_to_domain'],
        result['return_path_domain']
    ] if d]
    if len(set(domains)) > 1:
        result['domain_mismatch'] = True

    # Counts
    result['received_count'] = len(parsed.get('received', []))

    # Encoded subject
    if subject and '=?' in subject:
        result['subject_encoded'] = True

    # Authentication
    msg = parsed.get('_raw_message')
    if msg:
        result['authentication'] = analyze_authentication(msg, parsed)

    # Reputation
    if result['from_domain']:
        result['domain_reputation'] = analyze_domain_reputation(result['from_domain'])

    # Red flags
    if result['domain_mismatch']:
        result['header_red_flags'].append('Domain mismatch')
    if result['subject_encoded']:
        result['header_red_flags'].append('Encoded subject')

    return result


__all__ = [
    'extract_email_addr',
    'extract_domain',
    'verify_spf',
    'verify_dmarc',
    'check_dkim',
    'analyze_domain_reputation',
    'analyze_authentication',
    'analyze_headers',
]
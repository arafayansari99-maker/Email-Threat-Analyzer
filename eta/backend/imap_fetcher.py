"""IMAP email fetcher - connects to a mail server and yields raw email bytes."""
import imaplib
import logging
from typing import Generator

logger = logging.getLogger(__name__)

# Common provider defaults keyed by email domain
COMMON_PROVIDERS: dict[str, tuple[str, int]] = {
    "gmail.com":     ("imap.gmail.com", 993),
    "googlemail.com":("imap.gmail.com", 993),
    "outlook.com":   ("outlook.office365.com", 993),
    "hotmail.com":   ("outlook.office365.com", 993),
    "live.com":      ("outlook.office365.com", 993),
    "yahoo.com":     ("imap.mail.yahoo.com", 993),
    "yahoo.co.uk":   ("imap.mail.yahoo.com", 993),
    "icloud.com":    ("imap.mail.me.com", 993),
    "me.com":        ("imap.mail.me.com", 993),
    "protonmail.com":("127.0.0.1", 1143),  # requires ProtonMail Bridge
    "proton.me":     ("127.0.0.1", 1143),
}


def resolve_provider(username: str) -> tuple[str, int]:
    """Return (host, port) inferred from the email domain, or ('', 993) if unknown."""
    domain = username.split("@")[-1].lower() if "@" in username else ""
    return COMMON_PROVIDERS.get(domain, ("", 993))


def fetch_unseen_emails(
    host: str,
    port: int,
    username: str,
    password: str,
    folder: str = "INBOX",
    limit: int = 20,
) -> Generator[tuple[bytes, str], None, None]:
    """
    Connect via IMAP SSL and yield (raw_rfc822_bytes, server_msg_id) for each
    unseen message (newest first, up to `limit`).

    Raises:
        ValueError  — auth failure or bad folder name
        ConnectionError — network / TLS error
    """
    try:
        with imaplib.IMAP4_SSL(host, port) as mail:
            mail.login(username, password)
            status, _ = mail.select(folder, readonly=True)
            if status != "OK":
                raise ValueError(f"Cannot select folder '{folder}'")

            _, data = mail.search(None, "UNSEEN")
            ids: list[bytes] = data[0].split() if data[0] else []

            for msg_id in reversed(ids[-limit:]):
                try:
                    _, msg_data = mail.fetch(msg_id, "(RFC822)")
                    if msg_data and msg_data[0] and isinstance(msg_data[0], tuple):
                        yield msg_data[0][1], msg_id.decode()
                except Exception as exc:
                    logger.warning("Skipping message %s: %s", msg_id, exc)

    except imaplib.IMAP4.error as exc:
        raise ValueError(f"IMAP error: {exc}") from exc
    except OSError as exc:
        raise ConnectionError(f"Cannot reach {host}:{port} — {exc}") from exc


def test_connection(host: str, port: int, username: str, password: str) -> bool:
    """Login and immediately logout to verify credentials. Returns True on success."""
    try:
        with imaplib.IMAP4_SSL(host, port) as mail:
            mail.login(username, password)
        return True
    except Exception as exc:
        logger.debug("IMAP test_connection failed: %s", exc)
        return False


def list_folders(host: str, port: int, username: str, password: str) -> list[str]:
    """Return a list of mailbox folder names for the account."""
    try:
        with imaplib.IMAP4_SSL(host, port) as mail:
            mail.login(username, password)
            _, folders = mail.list()
            names = []
            for f in folders or []:
                if isinstance(f, bytes):
                    parts = f.decode().split('"."')
                    name = parts[-1].strip().strip('"')
                    names.append(name)
            return names
    except Exception as exc:
        logger.warning("list_folders failed: %s", exc)
        return ["INBOX"]

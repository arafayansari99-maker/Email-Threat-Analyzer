"""
Loads the local email corpus for DistilBERT fine-tuning.

Primary source: ml/data/ham/ and ml/data/phishing/ (.eml files already on disk).
Fallback: downloads SpamAssassin public corpus archives if local dirs are empty.

All data stays on-prem — nothing is sent to any external service.
"""
import email
import logging
import tarfile
import urllib.request
from pathlib import Path
from typing import List, Tuple

logger = logging.getLogger("data_loader")

DATA_DIR     = Path(__file__).parent / "data"
HAM_DIR      = DATA_DIR / "ham"
PHISHING_DIR = DATA_DIR / "phishing"

# Fallback: SpamAssassin public corpus archives
CORPUS_FILES = [
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
        "spam_1.tar.bz2",
        1,
    ),
    (
        "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2",
        "spam_2.tar.bz2",
        1,
    ),
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "easy_ham.tar.bz2",
        0,
    ),
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "hard_ham.tar.bz2",
        0,
    ),
]


def _parse_email(raw: bytes) -> str:
    """Extract [SUBJECT] ... [BODY] ... string from raw email bytes."""
    try:
        msg = email.message_from_bytes(raw)
        subject = msg.get("Subject", "") or ""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                        break
                    except Exception:
                        pass
        else:
            try:
                body = (msg.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
            except Exception:
                body = str(msg.get_payload() or "")
        subject = subject.strip()
        body    = body.strip()
        return f"[SUBJECT] {subject} [SUBJECT] {subject} [BODY] {body[:800]}"
    except Exception:
        return ""


def _load_eml_dir(directory: Path, label: int) -> Tuple[List[str], List[int]]:
    """Read all .eml files from a directory and return (texts, labels)."""
    texts: List[str] = []
    labels: List[int] = []
    files = list(directory.glob("*.eml")) + list(directory.glob("*"))
    seen: set = set()
    for path in files:
        if not path.is_file() or path in seen:
            continue
        seen.add(path)
        try:
            raw  = path.read_bytes()
            text = _parse_email(raw)
            if len(text) > 60:
                texts.append(text)
                labels.append(label)
        except Exception:
            pass
    return texts, labels


def load_local_corpus() -> Tuple[List[str], List[int]]:
    """
    Load emails directly from ml/data/ham/ and ml/data/phishing/.
    Returns (texts, labels) where label 1=phishing, 0=ham.
    """
    texts:  List[str] = []
    labels: List[int] = []

    if PHISHING_DIR.is_dir():
        t, l = _load_eml_dir(PHISHING_DIR, label=1)
        texts.extend(t); labels.extend(l)
        logger.info("Local phishing dir: %d emails", len(t))
    else:
        logger.warning("No phishing dir at %s", PHISHING_DIR)

    if HAM_DIR.is_dir():
        t, l = _load_eml_dir(HAM_DIR, label=0)
        texts.extend(t); labels.extend(l)
        logger.info("Local ham dir: %d emails", len(t))
    else:
        logger.warning("No ham dir at %s", HAM_DIR)

    n_spam = sum(labels)
    logger.info(
        "Local corpus: %d total  (%d phishing, %d ham)",
        len(texts), n_spam, len(labels) - n_spam,
    )
    return texts, labels


def download_corpus() -> None:
    """Download SpamAssassin archives if not already cached."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for url, fname, _ in CORPUS_FILES:
        dest = DATA_DIR / fname
        if dest.exists():
            logger.info("Cache hit: %s (%.1f MB)", fname, dest.stat().st_size / 1e6)
            continue
        logger.info("Downloading %s …", fname)
        try:
            urllib.request.urlretrieve(url, dest)
            logger.info("Saved %s → %.1f MB", fname, dest.stat().st_size / 1e6)
        except Exception as exc:
            logger.error("Download failed for %s: %s", fname, exc)


def _load_from_archives() -> Tuple[List[str], List[int]]:
    """Load from downloaded SpamAssassin .tar.bz2 archives."""
    texts: List[str] = []
    labels: List[int] = []
    for _, fname, label in CORPUS_FILES:
        path = DATA_DIR / fname
        if not path.exists():
            logger.warning("Missing %s — skipping", fname)
            continue
        try:
            with tarfile.open(path, "r:bz2") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    if member.name.endswith("cmds"):
                        continue
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    text = _parse_email(f.read())
                    if len(text) > 60:
                        texts.append(text)
                        labels.append(label)
        except Exception as exc:
            logger.error("Error reading %s: %s", fname, exc)
    return texts, labels


def load_spamassassin() -> Tuple[List[str], List[int]]:
    """
    Load corpus: uses local ml/data/ham+phishing dirs first (fast, no download).
    Falls back to downloading SpamAssassin archives if local dirs have < 100 emails.
    Returns (texts, labels) where label 1=spam/phishing, 0=ham.
    """
    texts, labels = load_local_corpus()

    if len(texts) >= 100:
        return texts, labels

    logger.info("Local corpus too small (%d) — falling back to SpamAssassin download", len(texts))
    download_corpus()
    texts, labels = _load_from_archives()

    n_spam = sum(labels)
    logger.info(
        "SpamAssassin loaded: %d total  (%d spam, %d ham)",
        len(texts), n_spam, len(labels) - n_spam,
    )
    return texts, labels

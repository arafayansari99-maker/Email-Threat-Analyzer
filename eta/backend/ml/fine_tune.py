#!/usr/bin/env python3
"""
Fine-tune DistilBERT for phishing email detection.

Dataset strategy (prevents memorisation / 1.0 accuracy):
  1. Real emails  — SpamAssassin public corpus (~4600 emails, real-world variance)
  2. Augmented synthetic — same generators as train_model.py, with noise applied
     so the model can't memorise fixed templates
  3. Label smoothing 0.1 — prevents overconfident logits
  4. EarlyStopping patience=2 — halts when val_loss stops improving

Run from eta/backend/:
    python ml/fine_tune.py

Output: ml/semantic_model/  (tokenizer + weights, ~260 MB)
"""
import os
import sys
import random
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("fine_tune")

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR  = os.path.join(SCRIPT_DIR, "semantic_model")
sys.path.insert(0, BACKEND_DIR)

# ── Dependencies ───────────────────────────────────────────────────────────────
try:
    import torch
    from transformers import (
        DistilBertTokenizerFast,
        DistilBertForSequenceClassification,
        Trainer,
        TrainingArguments,
        EarlyStoppingCallback,
        DataCollatorWithPadding,
    )
    from torch.utils.data import Dataset
    logger.info("torch %s | transformers loaded", torch.__version__)
except ImportError as exc:
    logger.error("Missing dependency: %s", exc)
    logger.error("pip install torch --index-url https://download.pytorch.org/whl/cpu")
    logger.error("pip install transformers accelerate")
    sys.exit(1)

try:
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, f1_score
except ImportError:
    logger.error("scikit-learn not found — pip install scikit-learn")
    sys.exit(1)

# ── Synthetic data generators ──────────────────────────────────────────────────
try:
    from ml.train_model import (
        _make_phishing_parsed,
        _make_legitimate_parsed,
        URGENCY_SUBJECTS, LOTTERY_SUBJECTS, LEGITIMATE_SUBJECTS,
        CREDENTIAL_BODY, GIFT_BODY, LEGITIMATE_BODY,
    )
    logger.info("Imported synthetic generators from train_model.py")
except ImportError as exc:
    logger.error("Cannot import train_model: %s", exc)
    sys.exit(1)

RANDOM_SEED = 42
random.seed(RANDOM_SEED)


# ── Noise augmentation ─────────────────────────────────────────────────────────
# Breaks template memorisation by introducing realistic variance.

_CHAR_SUBS = {"o": "0", "l": "1", "i": "!", "e": "3", "a": "@", "s": "$"}

_FILLER_WORDS = [
    "please", "kindly", "immediately", "urgent", "important",
    "verify", "confirm", "update", "action", "required",
    "account", "security", "alert", "notification", "service",
    "dear", "customer", "valued", "team", "support",
]

_LEGIT_FILLERS = [
    "thank", "regards", "sincerely", "hello", "hi",
    "greetings", "following", "attached", "enclosed", "below",
]


def _char_noise(word: str, rng: random.Random) -> str:
    """Swap one character using leet-speak subs, or drop one char."""
    if len(word) < 3:
        return word
    chars = list(word)
    idx = rng.randint(0, len(chars) - 1)
    c = chars[idx].lower()
    if c in _CHAR_SUBS and rng.random() < 0.5:
        chars[idx] = _CHAR_SUBS[c]
    elif rng.random() < 0.3:
        chars[idx] = ""
    return "".join(chars)


def augment(text: str, rng: random.Random, label: int, intensity: float = 0.12) -> str:
    """
    Apply word/character-level noise to break template memorisation.
    Intensity 0.12 = ~12% of tokens affected — enough to add variance
    without destroying the phishing/legit signal.
    """
    fillers = _FILLER_WORDS if label == 1 else _LEGIT_FILLERS
    words = text.split()
    result = []
    for word in words:
        r = rng.random()
        if r < intensity * 0.25:            # word deletion
            continue
        if r < intensity * 0.55:            # character substitution
            word = _char_noise(word, rng)
        if rng.random() < intensity * 0.15: # filler word insertion
            result.append(rng.choice(fillers))
        # Random case variation on short words
        if len(word) <= 6 and rng.random() < 0.08:
            word = word.upper() if rng.random() < 0.5 else word.capitalize()
        result.append(word)
    return " ".join(result)


# ── Synthetic styles ───────────────────────────────────────────────────────────

PHISHING_STYLES = [
    "brand_impersonation", "brand_impersonation",
    "urgency_credential",
    "gift_lottery",
    "bec",
    "crypto_scam",
    "malicious_attachment",
    "random_domain",
]

LEGITIMATE_STYLES = [
    "transactional", "newsletter", "notification",
    "security_legitimate", "other",
]


def _text(parsed: dict) -> str:
    subj = parsed.get("subject", "")
    body = parsed.get("body_text", "") or parsed.get("body_html", "")
    return f"[SUBJECT] {subj} [SUBJECT] {subj} [BODY] {body[:800]}"


def generate_synthetic(n_phishing: int, n_legit: int, rng: random.Random):
    """Generate augmented synthetic samples."""
    texts, labels = [], []
    for _ in range(n_phishing):
        style = rng.choice(PHISHING_STYLES)
        try:
            raw = _text(_make_phishing_parsed(style, rng))
            texts.append(augment(raw, rng, label=1))
            labels.append(1)
        except Exception:
            continue
    for _ in range(n_legit):
        style = rng.choice(LEGITIMATE_STYLES)
        try:
            raw = _text(_make_legitimate_parsed(style, rng))
            texts.append(augment(raw, rng, label=0))
            labels.append(0)
        except Exception:
            continue
    return texts, labels


def build_dataset(seed: int = RANDOM_SEED):
    """
    Build a mixed dataset:
      - SpamAssassin real corpus, capped at 1800/class to keep training fast
      - ~300 augmented synthetic per class to add template-based phishing signals
    Total: ~4200 samples — fast on CPU (~1.5 hr), real-world variance.
    """
    rng = random.Random(seed)
    texts, labels = [], []

    # ── Real data ──────────────────────────────────────────────────────────────
    real_loaded = False
    PER_CLASS_CAP = 2500   # use all available local data per class
    try:
        from ml.data_loader import load_spamassassin
        real_texts, real_labels = load_spamassassin()
        # Balance real data at PER_CLASS_CAP per class
        spam_pool = [(t, l) for t, l in zip(real_texts, real_labels) if l == 1]
        ham_pool  = [(t, l) for t, l in zip(real_texts, real_labels) if l == 0]
        rng.shuffle(spam_pool); rng.shuffle(ham_pool)
        chosen = spam_pool[:PER_CLASS_CAP] + ham_pool[:PER_CLASS_CAP]
        for t, l in chosen:
            texts.append(t); labels.append(l)
        real_loaded = True
        logger.info("Real corpus (capped): %d spam + %d ham", min(len(spam_pool), PER_CLASS_CAP), min(len(ham_pool), PER_CLASS_CAP))
    except Exception as exc:
        logger.warning("Real data unavailable (%s) — using synthetic only", exc)

    # ── Augmented synthetic — adds phishing-specific template signals ──────────
    N_SYN = 300 if real_loaded else 2500
    syn_t, syn_l = generate_synthetic(N_SYN, N_SYN, rng)
    texts.extend(syn_t); labels.extend(syn_l)
    logger.info("Synthetic (augmented): %d phishing + %d legit", N_SYN, N_SYN)

    # ── Shuffle ────────────────────────────────────────────────────────────────
    combined = list(zip(texts, labels))
    rng.shuffle(combined)
    texts, labels = zip(*combined)
    logger.info(
        "Final dataset: %d total  (%d phishing, %d legit)",
        len(texts), sum(labels), len(labels) - sum(labels),
    )
    return list(texts), list(labels)


# ── PyTorch Dataset ────────────────────────────────────────────────────────────

class EmailDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels    = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        # encodings are plain lists (no return_tensors="pt") — DataCollator handles tensors
        item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
        return item


# ── Metrics ────────────────────────────────────────────────────────────────────

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = logits.argmax(axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1":       f1_score(labels, preds, average="binary"),
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    texts, labels = build_dataset()

    train_texts, val_texts, train_labels, val_labels = train_test_split(
        texts, labels, test_size=0.15, random_state=RANDOM_SEED, stratify=labels
    )
    logger.info("Train: %d | Val: %d", len(train_texts), len(val_texts))

    logger.info("Loading tokenizer …")
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

    # max_length=256: captures full subject + 1500-char body window for deeper semantic context
    # padding=False — DataCollatorWithPadding pads each batch dynamically (no wasted compute)
    logger.info("Tokenising (max_length=256, dynamic padding) …")
    train_enc = tokenizer(train_texts, truncation=True, max_length=256, padding=False)
    val_enc   = tokenizer(val_texts,   truncation=True, max_length=256, padding=False)

    train_ds = EmailDataset(train_enc, train_labels)
    val_ds   = EmailDataset(val_enc,   val_labels)

    logger.info("Loading DistilBERT …")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=2
    )

    collator = DataCollatorWithPadding(tokenizer)

    training_args = TrainingArguments(
        output_dir                  = OUTPUT_DIR,
        num_train_epochs            = 4,
        per_device_train_batch_size = 16,   # smaller batch with AdamW for stable gradient updates
        per_device_eval_batch_size  = 32,
        learning_rate               = 2e-5,  # standard AdamW LR for DistilBERT fine-tuning
        warmup_ratio                = 0.1,   # 10% of steps for LR warmup (scales with dataset size)
        weight_decay                = 0.01,
        label_smoothing_factor      = 0.1,   # prevents overconfident logits
        optim                       = "adamw_torch",  # Adam with decoupled weight decay
        lr_scheduler_type           = "linear",       # linear decay after warmup
        eval_strategy               = "epoch",
        save_strategy               = "epoch",
        load_best_model_at_end      = True,
        metric_for_best_model       = "eval_loss",
        greater_is_better           = False,
        logging_steps               = 50,
        seed                        = RANDOM_SEED,
        use_cpu                     = True,   # CPU-only, no data leaves this server
        report_to                   = "none", # no telemetry
        dataloader_num_workers      = 0,
    )

    trainer = Trainer(
        model            = model,
        args             = training_args,
        train_dataset    = train_ds,
        eval_dataset     = val_ds,
        compute_metrics  = compute_metrics,
        data_collator    = collator,
        callbacks        = [EarlyStoppingCallback(early_stopping_patience=2)],
    )

    logger.info("Fine-tuning started (CPU) …")
    trainer.train()

    logger.info("Saving model to %s", OUTPUT_DIR)
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    metrics = trainer.evaluate()
    logger.info(
        "Final  accuracy=%.4f  f1=%.4f  val_loss=%.4f",
        metrics.get("eval_accuracy", 0),
        metrics.get("eval_f1",       0),
        metrics.get("eval_loss",     0),
    )
    logger.info("Done — model saved to ml/semantic_model/")


if __name__ == "__main__":
    main()

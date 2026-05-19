"""
Semantic NLP classifier using RoBERTa.

Runs entirely on-prem — no data ever leaves this server.
Model weights live in ml/semantic_model/ (produced by fine_tune.py).
Loaded once at first call and cached in memory for the process lifetime.
"""
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

_MODEL_DIR = os.path.join(os.path.dirname(__file__), "semantic_model")

_tokenizer = None
_model = None
_device = None
_load_attempted = False
_HAS_DEPS = False

try:
    import torch
    from transformers import RobertaTokenizerFast
    _HAS_DEPS = True
except ImportError:
    _HAS_DEPS = False


def _load():
    """Load the RoBERTa tokenizer and quantized model from ml/semantic_model/."""
    global _tokenizer, _model, _device, _load_attempted

    if _load_attempted:
        return _model is not None

    _load_attempted = True

    if not _HAS_DEPS:
        logger.warning("[semantic] Dependencies not available (torch/transformers)")
        return False

    if not os.path.isdir(_MODEL_DIR):
        logger.warning("[semantic] Model directory not found: %s", _MODEL_DIR)
        return False

    # Check for the quantized model file (faster loading, smaller memory)
    pt_path = os.path.join(_MODEL_DIR, "model_quantized.pt")
    safetensors_path = os.path.join(_MODEL_DIR, "model.safetensors")
    if not os.path.exists(pt_path) and not os.path.exists(safetensors_path):
        logger.warning("[semantic] No supported model file found: %s or %s", pt_path, safetensors_path)
        return False

    try:
        # Set device to CPU
        _device = torch.device("cpu")

        # Load tokenizer — RobertaTokenizerFast uses the tokenizers Rust backend
        # which is fast and reliable with transformers 5.8.0
        logger.info("[semantic] Loading tokenizer …")
        _tokenizer = RobertaTokenizerFast.from_pretrained(
            _MODEL_DIR,
            local_files_only=True,
        )
        logger.info("[semantic] Tokenizer loaded (vocab_size=%d)", _tokenizer.vocab_size)

        if os.path.exists(pt_path):
            logger.info("[semantic] Loading quantized model …")
            _model = torch.load(
                pt_path,
                map_location=_device,
                weights_only=False,
            )
        else:
            from transformers import RobertaForSequenceClassification
            logger.info("[semantic] Loading model from safetensors …")
            _model = RobertaForSequenceClassification.from_pretrained(
                _MODEL_DIR,
                local_files_only=True,
            )

        _model.eval()
        _model.to(_device)
        logger.info(
            "[semantic] Model loaded (type=%s, labels=%d)",
            type(_model).__name__,
            _model.config.num_labels,
        )
        return True

    except Exception as exc:
        logger.error("[semantic] Model loading failed: %s", exc, exc_info=True)
        _tokenizer = None
        _model = None
        return False


def classify_semantic(subject: str, body: str) -> Dict[str, Any]:
    """
    Run RoBERTa phishing classification on subject + body text.
    Returns semantic_prob (0-1) — higher = more likely phishing.
    Gracefully returns 0.0 / method='unavailable' if model not ready.
    """
    if not _load():
        return {"semantic_prob": 0.0, "method": "unavailable", "top_tokens": []}

    import torch

    text = f"[SUBJECT] {subject} [SUBJECT] {subject} [BODY] {body[:1200]}"

    try:
        inputs = _tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=256,
            padding=True,
        )
        inputs = {k: v.to(_device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = _model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)[0]
            phishing_prob = float(probs[1])

        top_tokens: list[str] = []

        return {
            "semantic_prob": round(phishing_prob, 4),
            "method": "roberta",
            "top_tokens": top_tokens,
        }

    except Exception as exc:
        logger.error("[semantic] Inference error: %s", exc)
        return {"semantic_prob": 0.0, "method": "error", "top_tokens": []}

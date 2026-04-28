"""
ML Classifier Module
TF-IDF + Logistic Regression phishing classifier with metrics.
"""
import os
import logging
import json
import pickle
import numpy as np
from typing import Dict, Any, List, Tuple, Optional

logger = logging.getLogger(__name__)

# Try to use sklearn
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, classification_report
    )
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logger.warning("sklearn not available, using fallback classifier")


# === Constants ===
MODEL_DIR = os.path.join(os.path.dirname(__file__), "ml")
MODEL_PATH = os.path.join(MODEL_DIR, "tfidf_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "tfidf_scaler.pkl")
META_PATH = os.path.join(MODEL_DIR, "tfidf_meta.json")

# TF-IDF settings
MAX_FEATURES = 5000
NGRAM_RANGE = (1, 2)  # unigrams and bigrams
MIN_DF = 2  # minimum document frequency


def load_model() -> Tuple[Optional[Any], Optional[Any], Optional[Any]]:
    """Load the trained TF-IDF model, vectorizer, and scaler."""
    if not HAS_SKLEARN:
        return None, None, None

    model = None
    vectorizer = None
    scaler = None

    # Load model
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, 'rb') as f:
                model = pickle.load(f)
            logger.info("Loaded TF-IDF model")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")

    # Load vectorizer
    if os.path.exists(VECTORIZER_PATH):
        try:
            with open(VECTORIZER_PATH, 'rb') as f:
                vectorizer = pickle.load(f)
            logger.info("Loaded TF-IDF vectorizer")
        except Exception as e:
            logger.error(f"Failed to load vectorizer: {e}")

    # Load scaler
    if os.path.exists(SCALER_PATH):
        try:
            with open(SCALER_PATH, 'rb') as f:
                scaler = pickle.load(f)
            logger.info("Loaded feature scaler")
        except Exception as e:
            logger.error(f"Failed to load scaler: {e}")

    return model, vectorizer, scaler


def save_model(model: Any, vectorizer: Any, scaler: Any, metrics: Dict[str, float]) -> None:
    """Save the trained model, vectorizer, and scaler."""
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

    # Save vectorizer
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)

    # Save scaler
    with open(SCALER_PATH, 'wb') as f:
        pickle.dump(scaler, f)

    # Save metadata
    meta = {
        "version": "1.0.0",
        "max_features": MAX_FEATURES,
        "ngram_range": NGRAM_RANGE,
        "metrics": metrics,
    }
    with open(META_PATH, 'w') as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Model saved to {MODEL_DIR}")


def generate_training_data(n_samples: int = 10000, seed: int = 42) -> Tuple[List[str], List[int]]:
    """Generate synthetic training data for TF-IDF model."""
    rng = np.random.RandomState(seed)
    texts = []
    labels = []

    # Phishing email templates
    phishing_templates = [
        "Your account has been compromised. Verify your identity immediately to avoid suspension.",
        "Urgent: Update your payment method to continue using our service.",
        "Congratulations! You've won a prize. Click here to claim your reward.",
        "Verify your email address now or your account will be suspended.",
        "Your password expires in 24 hours. Reset it now to stay secure.",
        "Suspicious activity detected. Confirm your identity now.",
        "Your account has been limited. Please verify your information.",
        "Invoice overdue. Update your payment details immediately.",
        "Your account is frozen. Verify to restore access.",
        "Security alert: New device login. Confirm if this was you.",
    ]

    legitimate_templates = [
        "Thanks for signing up. Here is your confirmation code.",
        "Your order has shipped. Track it here.",
        "Weekly newsletter: Top stories from this week.",
        "Your password was reset successfully.",
        "Meeting scheduled for tomorrow at 2pm.",
        "Your report is ready for download.",
        "Thanks for your purchase. Order confirmation.",
        "Your subscription has been renewed.",
        "New comment on your post.",
        "Password change confirmation.",
    ]

    # Generate phishing samples
    for _ in range(n_samples // 2):
        template = rng.choice(phishing_templates)
        # Add variations
        text = template.lower()
        if rng.random() > 0.5:
            text += " " + rng.choice(["verify now", "click here", "urgent", "immediate action required"])
        texts.append(text)
        labels.append(1)  # phishing

    # Generate legitimate samples
    for _ in range(n_samples // 2):
        template = rng.choice(legitimate_templates)
        text = template.lower()
        if rng.random() > 0.5:
            text += " " + rng.choice(["thank you", "best regards", "please let us know"])
        texts.append(text)
        labels.append(0)  # legitimate

    # Shuffle
    idx = rng.permutation(len(texts))
    return [texts[i] for i in idx], [labels[i] for i in idx]


def train_tfidf_model(n_samples: int = 10000) -> Dict[str, Any]:
    """Train TF-IDF + Logistic Regression model."""
    if not HAS_SKLEARN:
        return {"error": "sklearn not available"}

    logger.info(f"Generating {n_samples} training samples...")
    texts, labels = generate_training_data(n_samples)

    # Create TF-IDF vectorizer
    vectorizer = TfidfVectorizer(
        max_features=MAX_FEATURES,
        ngram_range=NGRAM_RANGE,
        min_df=MIN_DF,
        stop_words='english'
    )

    # Fit and transform
    X = vectorizer.fit_transform(texts)
    y = np.array(labels)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train model
    logger.info("Training Logistic Regression...")
    model = LogisticRegression(
        max_iter=1000,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)

    # Predictions
    y_pred = model.predict(X_test)

    # Metrics
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
    }

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    metrics["confusion_matrix"] = {
        "true_negative": int(cm[0, 0]),
        "false_positive": int(cm[0, 1]),
        "false_negative": int(cm[1, 0]),
        "true_positive": int(cm[1, 1]),
    }

    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    metrics["cv_accuracy_mean"] = float(cv_scores.mean())
    metrics["cv_accuracy_std"] = float(cv_scores.std())

    logger.info(f"Metrics: {metrics}")

    # Save model
    save_model(model, vectorizer, None, metrics)

    return metrics


def classify_text_tfidf(text: str, model: Any = None, vectorizer: Any = None) -> Dict[str, Any]:
    """Classify text using TF-IDF model."""
    if not HAS_SKLEARN:
        return {
            "classification": "unknown",
            "phishing_prob": 0.5,
            "method": "fallback",
        }

    # Load model if not provided
    if model is None or vectorizer is None:
        model, vectorizer, _ = load_model()

    if model is None or vectorizer is None:
        return {
            "classification": "unknown",
            "phishing_prob": 0.5,
            "method": "model_not_loaded",
        }

    try:
        # Transform text
        X = vectorizer.transform([text])

        # Predict
        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]

        phishing_prob = float(probabilities[1])  # probability of phishing

        return {
            "classification": "phishing" if prediction == 1 else "legitimate",
            "phishing_prob": phishing_prob,
            "confidence": max(probabilities),
            "method": "tfidf",
        }
    except Exception as e:
        logger.error(f"Classification error: {e}")
        return {
            "classification": "unknown",
            "phishing_prob": 0.5,
            "error": str(e),
        }


def get_model_metrics() -> Dict[str, Any]:
    """Get metrics from saved model."""
    if os.path.exists(META_PATH):
        with open(META_PATH, 'r') as f:
            return json.load(f)
    return {}


# === Main ===
if __name__ == "__main__":
    print("=" * 50)
    print("TF-IDF Phishing Classifier Training")
    print("=" * 50)

    metrics = train_tfidf_model(n_samples=10000)

    print("\n" + "=" * 50)
    print("METRICS")
    print("=" * 50)
    print(f"Accuracy:      {metrics.get('accuracy', 0):.4f}")
    print(f"Precision:     {metrics.get('precision', 0):.4f}")
    print(f"Recall:        {metrics.get('recall', 0):.4f}")
    print(f"F1 Score:     {metrics.get('f1', 0):.4f}")

    cm = metrics.get("confusion_matrix", {})
    print(f"\nConfusion Matrix:")
    print(f"  TN={cm.get('true_negative', 0)}, FP={cm.get('false_positive', 0)}")
    print(f"  FN={cm.get('false_negative', 0)}, TP={cm.get('true_positive', 0)}")

    print(f"\nCV Accuracy:  {metrics.get('cv_accuracy_mean', 0):.4f} (+/- {metrics.get('cv_accuracy_std', 0):.4f})")

    print("\n" + "=" * 50)
    print("Training complete!")
    print("=" * 50)
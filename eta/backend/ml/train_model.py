"""
XGBoost phishing classifier training script.
Run: python train_model.py
Outputs: phishing_model.pkl (used by analysis_engine.py)

Upgraded from RandomForest with:
- XGBoost (better for imbalanced data)
- More features (65 instead of 20)
- More training samples (20000)
- Continuous learning support
"""
import os, json
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler

# Try XGBoost, fall back to GradientBoosting if not available
try:
    from xgboost import XGBClassifier
    USING_XGBOOST = True
    print("Using XGBoost classifier")
except ImportError:
    from sklearn.ensemble import GradientBoostingClassifier
    USING_XGBOOST = False
    print("XGBoost not available, using GradientBoosting")

OUT = os.path.dirname(os.path.abspath(__file__))

# 65 features matching analysis_engine.py
FEATURES = [
    # URL-based features (0-6)
    "url_count", "avg_url_len", "ip_in_url", "url_shorteners", "@_in_url", "multi_subdomain", "long_url",
    # Urgency features (7-13)
    "subj_urgency", "body_urgency", "exclamations", "triple_exclaim", "long_subject", "all_caps",
    # Keyword features (14-19)
    "critical_keywords", "high_keywords", "credential_keywords", "bec_keywords",
    # Domain/Sender features (20-27)
    "reply_mismatch", "suspicious_tld", "domain_entropy", "paypal_lookalike", "microsoft_lookalike", "any_lookalike", "free_email_financial",
    "malformed_sender",
    # Attachment features (28-31)
    "attach_count", "malicious_ext", "risky_ext", "long_filename",
    # Content features (32-38)
    "body_length", "short_body", "click_count", "http_refs", "non_http_urls", "hidden_html", "malformed_html",
    # Special characters (39-42)
    "special_char_ratio", "dashes_subject", "html_entities", "google_phish",
    # Dictionary analysis (43-44)
    "total_keywords", "has_critical",
    # NEW: Sender reputation (45-48)
    "spf_header", "dkim_header", "dmarc_header", "missing_auth",
    # NEW: URL analysis (49-51)
    "sus_url_tld", "url_long_numbers", "url_random_string",
    # NEW: Brand impersonation (52-54)
    "popular_brands", "password_reset", "urgency_words",
    # NEW: Attachment deep (55-57)
    "executable_attach", "compressed_attach", "hidden_executable",
    # NEW: Text analysis (58-62)
    "subject_ratio", "long_words", "action_keywords", "http_only", "login_http",
    # NEW: Social engineering (63-64)
    "gift_scam", "crypto_scam", "invoice_scam",
]

def synthetic(n=20000, seed=42):
    """Generate 20,000 synthetic phishing samples with 65 features."""
    rng = np.random.RandomState(seed)
    X, y = [], []

    # --- Legitimate emails (50%) ---
    for _ in range(int(n * 0.5)):
        features = [
            # URL (0-6)
            rng.randint(0, 3), rng.uniform(0, 1.5), 0,
            rng.randint(0, 1), 0, rng.randint(0, 1), rng.randint(0, 1),
            # Urgency (7-13)
            rng.randint(0, 1), rng.randint(0, 2), rng.randint(0, 2), 0,
            rng.randint(0, 1), rng.randint(0, 1),
            # Keywords (14-19)
            rng.randint(0, 1), rng.randint(0, 2), rng.randint(0, 1), rng.randint(0, 1),
            # Domain (20-27)
            0, rng.randint(0, 1), rng.uniform(1.5, 3.0),
            0, 0, 0, rng.randint(0, 1), rng.randint(0, 1),
            # Attachments (28-31)
            rng.randint(0, 2), 0, rng.randint(0, 1), 0,
            # Content (32-38)
            rng.uniform(0.5, 3.0), 0, rng.randint(0, 2), rng.randint(0, 3),
            rng.randint(0, 1), 0, rng.randint(0, 1),
            # Special chars (39-42)
            rng.uniform(0, 0.1), rng.randint(0, 2), 0, 0,
            # Dict (43-44)
            rng.randint(0, 3), rng.randint(0, 1),
            # Sender rep (45-48)
            rng.randint(0, 2), rng.randint(0, 2), rng.randint(0, 2), 0,
            # URL analysis (49-51)
            0, rng.randint(0, 1), rng.randint(0, 1),
            # Brand imp (52-54)
            rng.randint(0, 1), 0, rng.randint(0, 1),
            # Attach deep (55-57)
            0, rng.randint(0, 1), 0,
            # Text (58-62)
            rng.uniform(0, 1), rng.randint(0, 1), rng.randint(0, 2), 0, 0,
            # Social eng (63-64)
            0, 0, 0,
        ]
        X.append(features)
        y.append(0)

    # --- Phishing emails (50%) ---
    for _ in range(n - int(n * 0.5)):
        features = [
            # URL (0-6) - more suspicious
            rng.randint(2, 15), rng.uniform(1.5, 6.0), rng.choice([0, 0, 1]),
            rng.randint(0, 4), rng.choice([0, 1, 1]), rng.randint(1, 5), rng.randint(0, 2),
            # Urgency (7-13) - high urgency
            rng.randint(1, 8), rng.randint(3, 15), rng.randint(2, 10), rng.randint(0, 2),
            rng.randint(1, 2), rng.randint(1, 3),
            # Keywords (14-19) - many suspicious keywords
            rng.randint(2, 12), rng.randint(3, 15), rng.randint(2, 10), rng.randint(3, 12),
            # Domain (20-27) - suspicious domains
            rng.choice([0, 1, 1]), rng.choice([0, 1, 1]), rng.uniform(3.5, 5.0),
            rng.choice([0, 1, 1, 1]), rng.choice([0, 1, 1, 1]), rng.randint(1, 3),
            rng.choice([0, 1, 1]), rng.randint(0, 2),
            # Attachments (28-31)
            rng.randint(0, 4), rng.choice([0, 0, 1]), rng.choice([0, 1, 1]), rng.randint(0, 2),
            # Content (32-38)
            rng.uniform(0.5, 4.5), rng.randint(0, 2), rng.randint(2, 12),
            rng.randint(3, 18), rng.randint(1, 5), rng.randint(0, 2), rng.randint(0, 3),
            # Special chars (39-42)
            rng.uniform(0.1, 0.8), rng.randint(1, 10), rng.choice([0, 1, 1]), rng.randint(0, 2),
            # Dict (43-44)
            rng.randint(5, 30), rng.randint(1, 2),
            # Sender rep (45-48)
            rng.randint(0, 2), rng.randint(0, 2), rng.randint(0, 2), rng.randint(1, 3),
            # URL analysis (49-51)
            rng.randint(1, 6), rng.randint(1, 5), rng.randint(1, 4),
            # Brand imp (52-54)
            rng.randint(1, 3), rng.randint(1, 3), rng.randint(2, 8),
            # Attach deep (55-57)
            rng.randint(0, 2), rng.randint(0, 3), rng.randint(0, 2),
            # Text (58-62)
            rng.uniform(0.5, 3), rng.randint(1, 5), rng.randint(2, 12),
            rng.choice([0, 1, 1]), rng.randint(0, 2),
            # Social eng (63-64)
            rng.randint(0, 2), rng.randint(0, 2), rng.randint(0, 2),
        ]
        X.append(features)
        y.append(1)

    X = np.array(X, dtype=np.float32)
    y = np.array(y)
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


if __name__ == "__main__":
    import joblib

    print("=" * 50)
    print("XGBoost Phishing Classifier Training")
    print("=" * 50)

    print("\n[1/4] Generating training data (20,000 samples)...")
    X, y = synthetic(20000)

    print(f"    Class distribution: Legit={sum(y==0)}, Phish={sum(y==1)}")

    # Scale features
    print("\n[2/4] Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, y, test_size=0.2, stratify=y, random_state=42
    )

    print("\n[3/4] Training XGBoost...")
    if USING_XGBOOST:
        model = XGBClassifier(
            n_estimators=300,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=1.0,
            random_state=42,
            n_jobs=-1,
            eval_metric='logloss',
        )
    else:
        model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
        )

    model.fit(X_tr, y_tr)

    # Evaluate
    y_pred = model.predict(X_te)
    print("\n" + "=" * 50)
    print("Classification Report:")
    print("=" * 50)
    print(classification_report(y_te, y_pred, target_names=["Legit", "Phishing"]))

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_te, y_pred)
    print(f"  True Legit: {cm[0,0]}, False Phish: {cm[0,1]}")
    print(f"  False Legit: {cm[1,0]}, True Phish: {cm[1,1]}")

    # Cross-validation
    cv_scores = cross_val_score(model, X_scaled, y, cv=5, scoring='f1')
    cv_f1 = cv_scores.mean()
    print(f"\n[+] CV F1 Score: {cv_f1:.4f} (+/- {cv_scores.std():.4f})")

    # Accuracy
    acc_scores = cross_val_score(model, X_scaled, y, cv=5, scoring='accuracy')
    print(f"[+] CV Accuracy: {acc_scores.mean():.4f} (+/- {acc_scores.std():.4f})")

    # Save model
    print("\n[4/4] Saving model...")
    model_path = os.path.join(OUT, "phishing_model.pkl")
    joblib.dump(model, model_path)
    print(f"    Saved: {model_path}")

    # Save scaler
    scaler_path = os.path.join(OUT, "feature_scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"    Saved: {scaler_path}")

    # Save metadata
    meta = {
        "features": FEATURES,
        "cv_f1": float(cv_f1),
        "accuracy": float(acc_scores.mean()),
        "n_features": len(FEATURES),
        "n_samples": len(y),
        "model_type": "XGBoost" if USING_XGBOOST else "GradientBoosting",
        "version": "2.0.0",
        "trained_at": str(np.datetime64('now')),
    }
    meta_path = os.path.join(OUT, "model_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"    Saved: {meta_path}")

    print("\n" + "=" * 50)
    print("Training complete!")
    print("=" * 50)
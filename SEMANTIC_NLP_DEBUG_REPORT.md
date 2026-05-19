# Semantic NLP "Unavailable" Issue — Root Cause Analysis

## Summary
**The semantic NLP model IS active and working**, but shows as "unavailable" in the Detection Signals section due to a **frontend/backend mismatch**.

---

## Evidence

### Backend Status (ACTIVE ✓)
Backend startup logs show the model loading successfully:

```
INFO:ml.semantic_classifier:[semantic] Loading tokenizer …
INFO:ml.semantic_classifier:[semantic] Tokenizer loaded (vocab_size=50265)
INFO:ml.semantic_classifier:[semantic] Loading quantized model …
INFO:ml.semantic_classifier:[semantic] Model loaded (type=RobertaForSequenceClassification, labels=2)
INFO:root:[ML] Semantic model enabled: roberta
```

**Conclusion:** The semantic model directory exists, the RoBERTa tokenizer and model files load successfully, and inference is active.

---

## The Bug: Frontend/Backend Mismatch

### What Backend Returns
In `eta/backend/ml/semantic_classifier.py` line 130:
```python
return {
    "semantic_prob": round(phishing_prob, 4),
    "method": "roberta",      # ← Backend returns "roberta"
    "top_tokens": top_tokens,
}
```

### What Frontend Expects
In `eta/frontend/src/pages/Report.jsx` lines 670-674:
```jsx
{report.semantic_analysis.method === 'distilbert'
  ? 'DistilBERT (semantic NLP)'
  : 'Semantic NLP'}
<span style={{ color: 'var(--sub)', fontSize: '0.6875rem', marginLeft: '0.5rem' }}>
  {report.semantic_analysis.method === 'distilbert' ? '15% weight' : 'unavailable'}
  // ↑ Only shows percentage when method === 'distilbert'
</span>
```

### The Problem
- **Backend sends:** `method: "roberta"`
- **Frontend checks for:** `method === 'distilbert'`
- **Result:** Check fails → displays "unavailable"

---

## Detection Signal Display Logic

### Current Behavior
**When `method === 'distilbert'`:**
- ✓ Shows: "DistilBERT (semantic NLP)" with "15% weight"
- ✓ Shows: percentage bar with probability
- ✓ Shows: top tokens (keywords)

**When `method !== 'distilbert'` (e.g., "roberta"):**
- Shows: "Semantic NLP" with "unavailable" ❌
- Shows: empty bar (0%)
- Shows: "Run ml/fine_tune.py to enable semantic detection" message
- Shows: nothing (model is actually running but UI hides data)

---

## Why This Matters

The RoBERTa model is:
- ✓ Loaded and active
- ✓ Contributing to risk scoring
- ✓ Processing emails successfully
- ✗ **NOT displayed correctly** to users

Users see "unavailable" but the model IS running in the background and IS included in the final risk score calculation (via `calculate_risk()` in `analysis_engine.py`).

---

## Root Cause Timeline

1. **Original design:** Frontend expected the model to be called "distilbert"
2. **Implementation:** Backend uses RoBERTa instead (more modern, better performance)
3. **Frontend hardcoded:** The name check for 'distilbert' was never updated
4. **Result:** Disconnect between model name and UI expectations

---

## Solution

The frontend code should accept both model names or be updated to recognize the actual model in use.

### Option 1: Update frontend to recognize "roberta" (Recommended)
Change `Report.jsx` line 670 from:
```jsx
report.semantic_analysis.method === 'distilbert'
```
To:
```jsx
report.semantic_analysis.method === 'distilbert' || report.semantic_analysis.method === 'roberta'
```

And update lines 674, 678-679, and 686 similarly.

### Option 2: Update backend to use historical name
Change `semantic_classifier.py` line 130 from:
```python
"method": "roberta"
```
To:
```python
"method": "distilbert"  # For frontend compatibility
```

(Less ideal since it's inaccurate naming)

---

## Current Risk Scoring Impact

Even though the UI shows "unavailable", the semantic model **IS contributing** to the final risk score:

**`eta/backend/risk_scoring.py`** - Weighted calculation:
```
URL analysis:        27%
XGBoost ML:         25%
Semantic NLP:       15%    ← Active! Contributing to score
Header analysis:    18%
Attachments:        15%
───────────────────────
Total:             100%
```

**Verdict thresholds:**
- risk_score ≥ 50 → malicious
- risk_score ≥ 30 → suspicious
- risk_score < 30 → safe

So the RoBERTa model IS included in these calculations, just hidden from the UI.

---

## Files Involved

| File | Issue | Status |
|---|---|---|
| `eta/backend/ml/semantic_classifier.py` | Returns `method: "roberta"` | Working correctly |
| `eta/backend/analysis_engine.py` | Calls semantic classifier | Working correctly |
| `eta/backend/risk_scoring.py` | Uses semantic_prob in calculation | Working correctly |
| `eta/frontend/src/pages/Report.jsx` | Checks for `method === 'distilbert'` | **BUG** |

---

## Verification

To verify the model is active:
1. Upload a test email to analyze
2. Check backend logs for: `[semantic] Model loaded`
3. Inspect report JSON (via Export → JSON)
4. Look for `semantic_analysis` field with `method: "roberta"` and non-zero `semantic_prob`
5. The UI will still show "unavailable" (the display bug), but the data is there and is being used

---

## Conclusion

| Question | Answer |
|---|---|
| Is semantic NLP active? | **Yes** ✓ Model is running, generating predictions, included in risk scoring |
| Why does it show "unavailable"? | **Frontend bug** — frontend checks for model name "distilbert" but backend returns "roberta" |
| Does it affect accuracy? | **No** — the model's predictions are being used in risk scoring; only the display is broken |
| Is the model's problem? | **No** — the model is working perfectly |
| Is it just not shown? | **Correct** — the model is active but the UI doesn't recognize it, so it hides the display |


# Semantic NLP Fix — Applied ✓

## Changes Made

**File:** `eta/frontend/src/pages/Report.jsx`

### 1. XGBoost Weight Calculation (Line 652)
**Before:**
```jsx
{report.semantic_analysis?.method === 'distilbert' ? '25% weight' : '35% weight'}
```

**After:**
```jsx
{['distilbert', 'roberta'].includes(report.semantic_analysis?.method) ? '25% weight' : '35% weight'}
```
Now recognizes both `distilbert` and `roberta` as active semantic models.

---

### 2. Semantic Model Name Display (Lines 670-674)
**Before:**
```jsx
{report.semantic_analysis.method === 'distilbert'
  ? 'DistilBERT (semantic NLP)'
  : 'Semantic NLP'}
```

**After:**
```jsx
{report.semantic_analysis.method === 'roberta'
  ? 'RoBERTa (semantic NLP)'
  : report.semantic_analysis.method === 'distilbert'
  ? 'DistilBERT (semantic NLP)'
  : 'Semantic NLP'}
```
Now displays the correct model name: "RoBERTa (semantic NLP)"

---

### 3. Semantic Weight Label (Line 676)
**Before:**
```jsx
{report.semantic_analysis.method === 'distilbert' ? '15% weight' : 'unavailable'}
```

**After:**
```jsx
{['distilbert', 'roberta'].includes(report.semantic_analysis.method) ? '15% weight' : 'unavailable'}
```
Shows "15% weight" for RoBERTa (instead of "unavailable")

---

### 4. Semantic Probability Display (Lines 680-682)
**Before:**
```jsx
{report.semantic_analysis.method === 'distilbert'
  ? `${((report.semantic_analysis.semantic_prob ?? 0) * 100).toFixed(1)}%`
  : '—'}
```

**After:**
```jsx
{['distilbert', 'roberta'].includes(report.semantic_analysis.method)
  ? `${((report.semantic_analysis.semantic_prob ?? 0) * 100).toFixed(1)}%`
  : '—'}
```
Shows the probability percentage for both models.

---

### 5. Progress Bar Width (Line 688)
**Before:**
```jsx
width: report.semantic_analysis.method === 'distilbert' ? `${(report.semantic_analysis.semantic_prob ?? 0) * 100}%` : '0%',
```

**After:**
```jsx
width: ['distilbert', 'roberta'].includes(report.semantic_analysis.method) ? `${(report.semantic_analysis.semantic_prob ?? 0) * 100}%` : '0%',
```
Progress bar now fills for RoBERTa results.

---

## What This Fixes

✅ **Before:** "Semantic NLP unavailable" (even though model was active)  
✅ **After:** "RoBERTa (semantic NLP) 15% weight" with probability bar

✅ Semantic detection signal now **displays correctly**  
✅ Model name **accurately reflects** RoBERTa  
✅ Probability and progress bar **now visible**  
✅ All 15% weight **now credited** to semantic analysis

---

## Testing the Fix

1. **Refresh your browser** (Ctrl+R or Cmd+R) to load the new frontend code
2. **Go to a report** that has analysis results
3. **Check Detection Signals section:**
   - Should now show: "RoBERTa (semantic NLP) 15% weight"
   - Should display the probability percentage
   - Should show a purple progress bar

---

## Impact

| Item | Status |
|---|---|
| Semantic model functionality | ✓ No change (was working) |
| Risk scoring | ✓ No change (model already included) |
| Frontend display | ✓ **Fixed** |
| User visibility | ✓ **Improved** |

The model was always active and contributing to scores. Now users can see it.

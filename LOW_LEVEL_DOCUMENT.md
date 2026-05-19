# ETA Email Threat Analyzer — Low-Level Project Document

> Generated from repository inspection.

## 1. Overview
ETA Email Threat Analyzer detects potentially malicious emails using:
- RFC822 email parsing + extraction of headers/body/attachments/URLs/IOCs
- Heuristic header analysis (SPF/DKIM/DMARC + reply-to mismatch + lookalikes)
- URL and attachment scoring
- ML phishing classification (TF-IDF+LogReg and optional heavier model)
- Semantic phishing signal (local DistilBERT/semantics model)
- Optional external threat intelligence enrichment (Tier-2 consent gated)
- Weighted risk aggregation -> verdict + recommendations
- Persistence to SQLite/Postgres with privacy redaction (body_text not stored)

Repository layout:
- `eta/backend`: FastAPI backend
- `eta/frontend`: React frontend
- `docker-compose.yml`: container orchestration

## 2. Backend: Execution Topology

### 2.1 FastAPI app bootstrap (`eta/backend/main.py`)
Creates FastAPI app and registers middlewares:
- CORS (`ALLOWED_ORIGINS` env-based)
- gzip compression
- custom security headers, request logging, and IP blocking
- cache control for static assets

Lifecycle (`lifespan`) on startup:
1. `Base.metadata.create_all(bind=engine)`
2. `run_migrations(engine)` (SQLite schema patching)
3. `create_default_admin()` based on `ADMIN_EMAIL` + `ADMIN_PASSWORD`
4. `_check_ml_models()`:
   - verifies presence of ML artifacts
   - attempts a semantic classifier startup check
5. starts `health_monitor`
6. starts `_retention_cleanup_loop()` hourly to enforce privacy retention policies

Router registration (all under `/api` prefix):
- `auth`, `analysis`, `history`, `reports`, `privacy`, `users`, `settings`, `collaboration`
- `threat_intel`, `admin`, `team_roles`, `feedback`, `analytics`, `chat`, `notifications`, `imap`

Non-`/api` endpoints:
- `GET /` online status
- `GET /health` lightweight liveness
- `GET /health/detailed` admin-only metrics
- `GET /ml/metrics` admin-only ML metrics
- `GET /health-monitor`, `POST /health-monitor/check`
- `POST /ml/train` retrains TF-IDF model (superadmin only)

### 2.2 Authentication subsystem (`eta/backend/routers/auth.py`)
Implements:
- Access tokens: JWT (HS256) with 60 minute expiry
- Refresh tokens:
  - stored in DB (`RefreshToken` rows)
  - also written to `httpOnly` cookie `eta_refresh_token`
- 2FA (admin-only): TOTP + backup codes (backup codes returned once; hashed stored)
- Brute-force protection:
  - `LoginAttempt` table tracks failed attempts by email+IP
  - slowapi limiter uses client IP

Key auth endpoints:
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `PATCH /api/auth/profile`
- `POST /api/auth/2fa/setup`, `POST /api/auth/2fa/enable`, `POST /api/auth/2fa/disable`, `GET /api/auth/2fa/status`
- Session management:
  - `POST /api/auth/sessions`
  - `GET /api/auth/sessions`
  - `DELETE /api/auth/sessions/{session_id}`
  - `POST /api/auth/sessions/revoke-all`
- Password reset:
  - `POST /api/auth/password-reset-request`
  - `POST /api/auth/password-reset-confirm`

### 2.3 Email analysis endpoints (`eta/backend/routers/analysis.py`)
Router endpoints:
- `POST /api/analyze-email`
  - multipart upload: file
  - size/type validation
  - calls `run_analysis(content, filename, tier2_consent=privacy_setting)`
  - stores scan + report
- `POST /api/analyze-batch`
  - list of uploaded files
  - processes sequentially, returns per-file errors in response
  - stores scan + report per processed file
- `POST /api/extension-scan`
  - JSON payload from browser extension:
    - `email_content`, optional `subject/sender/recipient/gmail_message_id`
  - builds minimal raw headers + body text, then calls `run_analysis(raw.encode(), ...)`
  - saves report if possible; failures to save do not fail the endpoint

Tier-2 consent gating:
- `_get_tier2_consent(db, user_id)` checks `PrivacySettings.tier2_consent`
- if user unauthenticated or consent is false, external enrichment is skipped

Persistence redaction:
- `_save()` removes `safe_result['meta']['body_text']` before writing `ThreatReport.report_json`
  - ensures client email body content not persisted

### 2.4 Database schema (`eta/backend/database.py`)
SQLAlchemy models (SQLite default; Postgres compatible):
- `User`
- `ScanRecord`:
  - scan metadata + verdict/risk score + counters + source
- `ThreatReport`:
  - JSON report payload (full analysis output)
- `PrivacySettings`:
  - retention policy (`data_retention_days`, `auto_delete`)
  - consent toggle (`tier2_consent`)
- Additional tables for app features (comments, notifications, favorites, sessions, 2FA, IMAP accounts, etc.)

### 2.5 Core analysis engine (`eta/backend/analysis_engine.py`)
Primary entry:
- `run_analysis(content: bytes, filename: str, tier2_consent: bool) -> dict`

High-level pipeline inside `run_analysis`:
1. `parse_email_bytes(content, filename)`
2. Extract authentication verification inputs (email.message object)
3. `analyze_email_authentication(msg, parsed)`
4. `analyze_headers(parsed)` -> header score + derived auth labels
5. `analyze_urls(parsed['urls'])` -> URL heuristics
6. `analyze_attachments(parsed['attachments'])` -> attachment heuristics
7. `classify_phishing(parsed)` -> ML features (58 features) + model inference + rule override
8. `ml.semantic_classifier.classify_semantic(subject, body_text)`
9. Optional Tier-2 external enrichment (threat_intel module) if consent
10. `calculate_risk(...)` -> verdict, recommendations, breakdown
11. `build_ioc_graph(...)` -> nodes/edges (email->domain/url/ip/hash)
12. `generate_summary(...)` -> human-readable summary
13. `narrative = _enrich_with_llm(...)` -> local rule-based narrative + social engineering tactics

#### 2.5.1 Parsing + extraction (`parse_email_bytes`)
Supported modes:
- Outlook `.msg`:
  - tries `extract_msg` if installed
  - otherwise falls back to text extraction
- Email `.eml/.txt/.mbox`:
  - parses bytes with `email.message_from_bytes`
  - extracts headers and walks multipart payload
- Other file types:
  - `_extract_text_from_file()` extracts content based on extension

Multipart walk behavior:
- `text/plain` => append to `body_text`
- `text/html` => append to `body_html` and add stripped text for analysis
- attachments:
  - metadata via `_parse_attachment(part)` (hashes + ext risk flags)
  - payload bytes decoded/extracted via `_extract_text_from_file(payload, filename)`
  - extracted payload text appended to `attachment_text`

URL/domain extraction:
- `_extract_urls(text)` extracts http(s) URLs using regex
- domains computed from URLs

Public IP extraction:
- parses `Received:` headers
- extracts IPs but excludes private/reserved by regex

#### 2.5.2 ML phishing classifier (`classify_phishing` + `extract_ml_features`)
- `extract_ml_features(parsed)` builds exactly **58** numeric features (see FEATURE_NAMES in code).
- Runs:
  - TF-IDF pipeline classification via `ml_classifier.py`
  - optional primary model loading via `phishing_model.pkl` + `feature_scaler.pkl`
  - if missing, uses TF-IDF or `_rule_score()` fallback
- Applies `_rule_based_override()` to force higher probabilities when strong combinations occur (missing auth + lookalikes + urgency, credential keywords + http-only, gift/crypto scams, etc.).

Outputs:
- `phishing_probability`, `confidence`
- `classification`: phishing/suspicious/legitimate
- explanation (optional SHAP top-5 features)
- `suspicious_keywords_found` buckets

#### 2.5.3 Risk scoring (`calculate_risk`)
Weighted aggregation:
- header score (incl. IOC boost): 15%
- URL score: 25%
- attachment score: 10%
- ML phishing probability: 40%
- semantic probability: 10%

Additional boosts:
- scam/BEC pattern boost (`scam_boost`)
- critical IOC bonus when threat-intel tier indicates high confidence
- high-confidence ML bonus

Final verdict thresholds:
- default malicious_score=50
- default suspicious_score=30

Returns:
- risk_score (0..100)
- verdict + color
- recommendations list
- breakdown by component
- semantic analysis passthrough

#### 2.5.4 IOC graph (`build_ioc_graph`)
Creates graph nodes/edges:
- email node
- domain node (derived risk from auth)
- URL nodes (derived from URL heuristic verdict tiers)
- IP nodes (private/reserved -> threat)
- attachment hash nodes (exec/risky extension => threat)

#### 2.5.5 JSON report shape
The report JSON stored in `ThreatReport.report_json` includes keys such as:
- `scan_id`, `filename`, `timestamp`, `duration`
- `meta` (includes sender/subject/date/reply_to; body_text omitted)
- `risk_score`, `verdict`, `color`, `recommendations`, `breakdown`
- `header_analysis`, `authentication`, `url_analysis`, `attachment_analysis`
- `ml_analysis`, `semantic_analysis`
- `iocs`, `ioc_graph`
- `threat_intel` (if tier2 consent)
- `analysis_summary`
- `narrative` (local rule-based)

### 2.6 Threat intelligence (`eta/backend/threat_intel.py`)
Not fully opened in this session, but integrated as:
- called only when `tier2_consent == true`
- enriches:
  - URLs/IP/domain reputation/tiers
  - attachments via hash lookup
- results are stored under both:
  - `ioc_intel` (structured scores for risk computation)
  - `threat_intel` (raw enriched data for UI rendering)

## 3. Frontend: React Architecture

### 3.1 App shell and routes (`eta/frontend/src/App.jsx`)
- Uses React Router.
- `ProtectedRoute` gates authenticated pages.
- Lazy loads many pages.
- Includes support chat FAB (shown only when `user` exists).

### 3.2 API client (`eta/frontend/src/services/api.js`)
- axios instance with:
  - `withCredentials: true` to send refresh cookie
  - access token stored in module variable (not localStorage)
- Intercepts responses:
  - on 401, calls `/api/auth/refresh` silently
  - sets new access token in memory and retries original request

Exposed analysis endpoints used by UI:
- `analyzeEmail(files, ...)` => `/api/analyze-email` or `/api/analyze-batch`
- `analyzeEmailText(data)` => `/api/extension-scan`
- report loading:
  - `getReport(id)` => `/api/reports/report/{id}`
  - `getHistory(...)` => `/api/history/scan-history`
- export:
  - `downloadJSON(id)` => `/api/reports/report/${id}/json`
  - `generatePDF(id)` => `/api/reports/report/${id}/pdf`

### 3.3 Report page (`eta/frontend/src/pages/Report.jsx`)
Main UI responsibilities:
- fetches scan list + selected scan report by route param `id`
- renders:
  - risk score, verdict, phishing probability
  - AI narrative (`report.narrative`)
  - detection signals:
    - `report.ml_analysis` probability
    - `report.semantic_analysis` probability
  - threat intel:
    - `report.threat_intel.header_deep_dive`
    - `report.threat_intel.enrichment` sections (IP reputation + URL checks)
    - attachment sandbox preview based on `attachment_analysis.attachments[].threat_intel`
  - IOC list (`report.iocs`), with normalization function `getIOCStatus()`
  - collaboration comments and flagging
  - exports (JSON and PDF)

IOC normalization strategy:
- converts backend verdict/risk labels into UI buckets:
  - safe / suspicious / malicious / unknown
- resolves URL/domain/hash/ip statuses by consulting:
  - `report.url_analysis.urls`
  - `report.attachment_analysis.attachments`
  - `report.threat_intel` (where available)

## 4. End-to-End Flow Summary
1. User authenticates (JWT + httpOnly refresh cookie).
2. User triggers analysis (file upload, batch upload, or extension scan).
3. Backend parses email and extracts artifacts (headers/body/urls/attachments/IOCs).
4. Backend computes:
   - header heuristics
   - URL/attachment heuristics
   - ML phishing probability (58 features + model/rules)
   - semantic probability (local model)
   - optional tier2 external threat intel enrichment
5. Backend aggregates into risk score -> verdict -> recommendations.
6. Backend saves metadata + report JSON with privacy redaction.
7. Frontend loads scan history and renders the report view with threat intel and exports.

## 5. Key Design/Behavior Notes
- **Privacy**: body_text is extracted but not persisted to DB.
- **Tier2 Consent**: external reputation APIs are only enabled if user sets `PrivacySettings.tier2_consent=true`.
- **Resilience**: if ML artifacts are missing, classifier falls back to TF-IDF or rule-based scoring.
- **Explainability**: SHAP explanation attempts when available.
- **Risk philosophy**: IOC-derived signals (URLs/attachments/hashes) are strong drivers; ML probability is weighted heavily; scam/BEC patterns provide additional boosts.


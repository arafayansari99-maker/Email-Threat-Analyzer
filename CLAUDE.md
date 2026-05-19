# ETA — Email Threat Analyzer: Project Context for AI Agents

This file provides complete context so any AI agent can work on the codebase without needing a project re-explanation. Read this before making any changes.

---

## Project Overview

ETA (Email Threat Analyzer) is a full-stack cybersecurity web application for detecting phishing, malware, BEC (Business Email Compromise), and other email-based threats. Users upload email files or connect IMAP accounts; the backend runs a multi-model ML pipeline to score and classify each email; results are stored and surfaced through a rich React dashboard.

**Version:** 2.0.0  
**Status:** Active development, running on Windows (dev), deployable to Linux/Docker.

---

## Repository Layout

```
eta-email-threat-analyzer/
├── CLAUDE.md                    ← this file
├── .env.example                 ← root-level env example (points to eta/.env.example)
├── eta/
│   ├── .env.example             ← canonical env var template
│   ├── backend/
│   │   ├── main.py              ← FastAPI app entrypoint, lifespan, middleware, health routes
│   │   ├── database.py          ← SQLAlchemy models + SQLite/PostgreSQL engine + migrations
│   │   ├── analysis_engine.py   ← core analysis pipeline, ML feature extraction (58 features)
│   │   ├── ml_classifier.py     ← TF-IDF + Logistic Regression fallback classifier
│   │   ├── url_analysis.py      ← URL extraction and scoring
│   │   ├── header_analysis.py   ← Email header authentication parsing
│   │   ├── risk_scoring.py      ← Weighted risk score calculator
│   │   ├── threat_intel.py      ← VirusTotal / AbuseIPDB / Shodan enrichment
│   │   ├── imap_fetcher.py      ← imaplib-based email fetcher, provider auto-resolve
│   │   ├── security_middleware.py ← rate limiting, IP blocklist, request logging, CSP headers
│   │   ├── health_monitor.py    ← background health checks + alert callbacks
│   │   ├── notifications.py     ← email (SMTP) notification service
│   │   ├── webhooks.py          ← outbound webhook delivery
│   │   ├── suspicious_dictionary.py ← curated keyword lists used by analysis_engine
│   │   ├── requirements.txt
│   │   ├── eta.db               ← SQLite database (dev; not committed)
│   │   ├── ml/
│   │   │   ├── train_model.py       ← XGBoost training pipeline (v4.0)
│   │   │   ├── phishing_model.pkl   ← trained XGBoost model
│   │   │   ├── feature_scaler.pkl   ← StandardScaler for 58 features
│   │   │   ├── model_meta.json      ← feature names, thresholds, metrics
│   │   │   ├── data/
│   │   │   │   ├── phishing/        ← real phishing .eml samples
│   │   │   │   └── ham/             ← real legitimate .eml samples
│   │   │   └── semantic_model/      ← optional DistilBERT model (create dir to enable)
│   │   └── routers/
│   │       ├── auth.py              ← /api/auth/*
│   │       ├── analysis.py          ← /api/analyze-email, /api/analyze-batch
│   │       ├── history.py           ← /api/history/*
│   │       ├── reports.py           ← /api/reports/*
│   │       ├── admin.py             ← /api/admin/*
│   │       ├── imap.py              ← /api/imap/*
│   │       ├── analytics.py         ← /api/analytics/*
│   │       ├── chat.py              ← /api/chat/* + WebSocket
│   │       ├── notifications.py     ← /api/notifications/*
│   │       ├── collaboration.py     ← /api/collaborate/*
│   │       ├── privacy.py           ← /api/privacy/*
│   │       ├── settings.py          ← /api/settings/*
│   │       ├── users.py             ← /api/users/*
│   │       ├── team_roles.py        ← /api/team/*
│   │       ├── feedback.py          ← /api/feedback/*
│   │       └── threat_intel.py      ← /api/threat-intel/*
│   └── frontend/
│       ├── package.json             ← React 18, Vite, Recharts, Axios, React Router v6
│       ├── vite.config.js           ← proxy /api → localhost:8000 in dev
│       └── src/
│           ├── App.jsx              ← Router, AuthProvider, SupportChat FAB, ProtectedRoute
│           ├── index.css            ← CSS variables, component styles (dark/light themes)
│           ├── pages/
│           │   ├── Login.jsx
│           │   ├── Register.jsx
│           │   ├── Dashboard.jsx
│           │   ├── Analyze.jsx      ← file upload + drag-and-drop
│           │   ├── History.jsx
│           │   ├── Analytics.jsx    ← Recharts charts
│           │   ├── Report.jsx       ← scan detail + comparison + share links
│           │   ├── IOCGraph.jsx     ← force-directed SVG IOC graph
│           │   ├── Admin.jsx        ← admin dashboard
│           │   ├── UserManagement.jsx
│           │   ├── Settings.jsx
│           │   ├── Privacy.jsx
│           │   ├── Sessions.jsx
│           │   ├── Collaborate.jsx
│           │   ├── News.jsx
│           │   ├── APIDocumentation.jsx
│           │   └── CheckStatus.jsx
│           ├── hooks/
│           │   ├── useAuth.jsx      ← AuthContext, JWT in-memory, httpOnly refresh cookie
│           │   ├── useTheme.jsx     ← dark/light theme context
│           │   └── useToast.jsx     ← toast notification context
│           ├── services/
│           │   └── api.js           ← Axios instance, silent token refresh interceptor
│           └── components/
│               ├── layout/Layout.jsx
│               ├── ErrorBoundary.jsx
│               └── ui/
│                   ├── SupportChat.jsx  ← real-time support chat (WebSocket)
│                   ├── SearchBar.jsx    ← global search (Ctrl+K / Cmd+K)
│                   └── index.jsx        ← shared UI exports
```

---

## How to Run (Development)

### Backend

```bash
cd eta/backend
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt

# Copy and fill env vars:
cp ../env.example .env
# Edit .env: set JWT_SECRET_KEY, ADMIN_EMAIL, ADMIN_PASSWORD at minimum

python main.py
# Starts uvicorn on http://localhost:8000
# API docs available at http://localhost:8000/docs (dev only)
```

### Frontend

```bash
cd eta/frontend
npm install
npm run dev
# Vite dev server on http://localhost:3000
# Proxies /api/* to http://localhost:8000
```

### Retrain XGBoost Model (after changing training data or features)

```bash
cd eta/backend
python ml/train_model.py
# Writes: ml/phishing_model.pkl, ml/feature_scaler.pkl, ml/model_meta.json
# Restart backend after retraining
```

---

## Environment Variables

All variables live in `eta/backend/.env` (copy from `eta/.env.example`).

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET_KEY` | **Yes** | 64-char hex string for signing JWTs and encrypting IMAP passwords |
| `DATABASE_URL` | No | SQLite default: `sqlite:///./eta.db`. Use `postgresql://...` in prod |
| `IMAP_ENCRYPT_KEY` | No | Separate Fernet encryption key for IMAP passwords; falls back to `JWT_SECRET_KEY` |
| `ADMIN_EMAIL` | No | Auto-creates superadmin on first startup |
| `ADMIN_PASSWORD` | No | Initial superadmin password (change immediately after first login) |
| `ALLOWED_ORIGINS` | No | Comma-separated CORS origins; defaults to localhost:5173 and :3000 |
| `ENVIRONMENT` | No | Set `production` to disable `/docs`, `/redoc`, `/openapi.json` |
| `VIRUSTOTAL_API_KEY` | No | Enables URL/file hash checking via VirusTotal |
| `ABUSEIPDB_API_KEY` | No | Enables IP reputation lookups |
| `SHODAN_API_KEY` | No | Enables Shodan host intelligence |
| `HYBRID_ANALYSIS_API_KEY` | No | Hybrid Analysis sandbox |
| `URLSCAN_API_KEY` | No | URLScan.io |
| `SAFE_BROWSING_API_KEY` | No | Google Safe Browsing |
| `SMTP_HOST/PORT/USER/PASSWORD` | No | For password reset emails and scheduled reports |
| `FRONTEND_URL` | No | Used in email notification links |

**Frontend env** (optional `eta/frontend/.env.local`):
- `VITE_API_URL` — full backend URL for production builds (empty = Vite proxy handles it)

---

## Authentication Flow

1. **Login**: `POST /api/auth/login` (form-encoded) → returns `access_token` (JWT, 1h) + sets `httpOnly` refresh cookie (30d).
2. **In-memory token**: The access token is stored in a JS module variable (`api.js`), NOT localStorage. Survives navigation but cleared on hard refresh.
3. **Silent refresh**: On page load and on any 401 response, `axios` posts `POST /api/auth/refresh` with the httpOnly cookie to get a new access token without user interaction.
4. **Logout**: `POST /api/auth/logout` revokes the refresh token DB record + clears the cookie.
5. **2FA**: Optional TOTP via `pyotp`. Users set it up in Settings; verified on login.
6. **User profile** (non-sensitive) cached in `localStorage` as `eta_user` for instant render, refreshed from `/api/auth/me` on load.

**Roles**: `superadmin` > `admin` > `analyst` > `viewer` > `user`  
New registrations default to `user` and require admin approval (`is_approved=False` initially).

---

## ML Pipeline

### Three-layer architecture

| Layer | Model | File | Always Active |
|---|---|---|---|
| 1 | XGBoost (58 features) | `ml/phishing_model.pkl` | Yes (primary) |
| 2 | TF-IDF + LogisticRegression | `ml_classifier.py` | Yes (secondary/fallback) |
| 3 | DistilBERT semantic | `ml/semantic_model/` | Yes |

### Feature extraction (`analysis_engine.py` → `extract_ml_features`)

All 58 features are extracted in a single function that both training and inference call identically:

**URL features** (13): `url_count`, `avg_url_len`, `ip_in_url`, `url_shorteners`, `at_in_url`, `multi_subdomain`, `long_url`, `sus_url_tld`, `url_long_numbers`, `url_random_string`, `http_only`, `login_http`, `google_phish`

**Subject/header features** (8): `subj_urgency`, `long_subject`, `dashes_subject`, `reply_mismatch`, `suspicious_tld`, `malformed_sender`, `free_email_financial`, `domain_entropy`

**Body/content features** (10): `body_urgency`, `exclamations`, `triple_exclaim`, `body_length`, `short_body`, `click_count`, `http_refs`, `non_http_urls`, `hidden_html`, `malformed_html`

**Keyword features** (8): `critical_keywords`, `high_keywords`, `credential_keywords`, `bec_keywords`, `total_keywords`, `action_keywords`, `special_char_ratio`, `html_entities`

**Auth/header features** (5): `spf_header`, `dkim_header`, `dmarc_header`, `missing_auth`, `subject_ratio`

**Attachment features** (6): `attach_count`, `malicious_ext`, `risky_ext`, `long_filename`, `executable_attach`, `compressed_attach`, `hidden_executable`

**Scam-type features** (6): `popular_brands`, `password_reset`, `gift_scam`, `crypto_scam`, `invoice_scam`, `long_words`, `any_lookalike`

### Thresholds and scoring

```
XGBoost probability ≥ 0.70  → phishing (contributes to malicious verdict)
XGBoost probability ≥ 0.55  → suspicious

Weighted risk score (DistilBERT always active):
  URL analysis:      27%
  XGBoost ML:       25%
  DistilBERT:       15%
  Header analysis:  18%
  Attachments:      15%

Final verdict:
  risk_score ≥ 50 → malicious
  risk_score ≥ 30 → suspicious
  risk_score < 30 → safe
```

### Rule-based override layer (`_rule_based_override` in `analysis_engine.py`)

Applied **after** ML scoring to handle known edge cases:

- **De-boost** (multiply ML probability by `0.82`): When email has valid auth headers (SPF/DKIM/DMARC pass) AND no `high_risk_combo`.
- **`high_risk_combo`** is `True` when ANY of: `any_lookalike`, `gift_scam`, `crypto_scam`, or (`credential_keywords` AND `subj_urgency`).
- This prevents false positives on legitimate 2FA/security emails from Google, GitHub, etc. that mention "verify", "password", "account" but have valid auth.

### URL scoring: known-safe domain skip

In `analyze_single_url`, URL path keywords ("login", "verify", "confirm", "secure", "update", "account") do NOT add risk points for domains in the known-safe list:
```
google.com, accounts.google.com, github.com, microsoft.com, live.com, outlook.com,
apple.com, amazon.com, paypal.com, stripe.com, shopify.com, slack.com, zoom.us,
dropbox.com, linkedin.com, twitter.com, x.com, facebook.com, instagram.com
```

### Current model metrics (v4.0, trained 2026-05-05)

- ROC-AUC: 0.9920
- F1: 0.9311, Precision: 0.9629, Recall: 0.9077
- Samples: 26,000 (8,000 real + 18,000 synthetic)
- Top features: `subj_urgency` (19.2%), `suspicious_tld` (14.8%), `executable_attach` (10.6%)

---

## Database (SQLAlchemy + SQLite/PostgreSQL)

Default: SQLite at `eta/backend/eta.db`. SQLite uses WAL journal mode for concurrent reads. Switch to PostgreSQL for production by setting `DATABASE_URL=postgresql://...`.

### Key tables

| Table | Purpose |
|---|---|
| `users` | User accounts. Roles: superadmin/admin/analyst/viewer/user |
| `scan_records` | One row per email scan. Has `source` field: "upload" or "imap" |
| `threat_reports` | Full JSON analysis result, linked to scan_records by scan_id |
| `email_accounts` | IMAP accounts per user. `password_enc` is Fernet-encrypted |
| `chat_messages` | Support chat messages (user ↔ admin) |
| `refresh_tokens` | Active sessions. SHA-256 hashed token stored |
| `model_feedback` | User corrections to ML verdicts (for future retraining) |
| `privacy_settings` | Per-user data retention, analytics consent, `tier2_consent` |
| `notifications` | In-app notification queue |
| `audit_logs` | Admin action log (role changes, deletions, etc.) |
| `favourites` | Starred/bookmarked scan reports |
| `share_links` | Expiring one-time report share tokens |
| `workspaces` / `workspace_members` | Team collaboration groupings |
| `report_comments` | Per-scan comments/flags |
| `activity_logs` | User activity stream |
| `branding_config` | Per-user PDF report branding |
| `scheduled_reports` | Recurring PDF email delivery |
| `login_attempts` | Brute-force tracking per IP+email |

`run_migrations()` in `database.py` handles additive SQLite schema migrations (ALTER TABLE ADD COLUMN) without a migration framework.

---

## API Routes Reference

All routes are prefixed with `/api`. Authentication: `Authorization: Bearer <token>` header (except endpoints that explicitly use the httpOnly cookie).

### `/api/auth` — Authentication
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | None | Register new user |
| POST | `/auth/login` | None | Login (form-encoded), returns JWT + sets refresh cookie |
| POST | `/auth/logout` | Bearer | Revoke refresh token |
| POST | `/auth/refresh` | Cookie | Get new access token from refresh cookie |
| GET | `/auth/me` | Bearer | Current user profile |
| PUT | `/auth/me` | Bearer | Update profile (username, email, password) |
| POST | `/auth/2fa/setup` | Bearer | Generate TOTP QR code |
| POST | `/auth/2fa/verify` | Bearer | Verify TOTP and enable 2FA |
| POST | `/auth/2fa/disable` | Bearer | Disable 2FA |
| POST | `/auth/password-reset/request` | None | Send reset email |
| POST | `/auth/password-reset/confirm` | None | Apply new password using token |
| GET | `/auth/sessions` | Bearer | List active sessions |
| DELETE | `/auth/sessions/{id}` | Bearer | Revoke specific session |

### `/api` — Analysis
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/analyze-email` | Optional | Upload and analyze single email file |
| POST | `/analyze-batch` | Bearer | Upload multiple files (batch) |

Accepted file types: `.eml`, `.msg`, `.txt`, `.mbox`, `.csv`, `.pdf`, `.json`, `.xml`, `.html`, `.htm`, `.log`, `.md`  
Max size: 300 MB. Tier-2 (external API enrichment) requires `tier2_consent=True` in privacy settings.

### `/api/history` — Scan History
| Method | Path | Description |
|---|---|---|
| GET | `/history/scan-history` | Paginated scan list (search, verdict filter) |
| GET | `/history/scan/{scan_id}` | Full report for one scan |
| DELETE | `/history/scan/{scan_id}` | Delete scan and report |
| GET | `/history/favourites` | List starred scans |
| POST | `/history/favourites/{scan_id}` | Star a scan |
| DELETE | `/history/favourites/{scan_id}` | Unstar a scan |

### `/api/reports` — Report Management
| Method | Path | Description |
|---|---|---|
| GET | `/reports/` | All user reports |
| GET | `/reports/{scan_id}` | Single report |
| GET | `/reports/{scan_id}/pdf` | Generate PDF export |
| GET | `/reports/{scan_id}/json` | JSON export |
| POST | `/reports/share/{scan_id}` | Create share link |
| GET | `/reports/shared/{token}` | Access via share token |
| POST | `/reports/schedule` | Schedule recurring PDF email |
| GET | `/reports/branding` | Get branding config |
| PUT | `/reports/branding` | Update branding config |

### `/api/imap` — IMAP Accounts
| Method | Path | Description |
|---|---|---|
| GET | `/imap/accounts` | List connected IMAP accounts |
| POST | `/imap/accounts` | Add IMAP account (password Fernet-encrypted) |
| DELETE | `/imap/accounts/{id}` | Remove account |
| POST | `/imap/accounts/{id}/test` | Test connection |
| POST | `/imap/accounts/{id}/sync` | Fetch and analyze unseen emails |
| GET | `/imap/accounts/{id}/folders` | List mailbox folders |

### `/api/admin` — Admin Panel
| Method | Path | Description |
|---|---|---|
| GET | `/admin/audit-logs` | Paginated audit trail |
| GET | `/admin/users` | All users |
| PUT | `/admin/users/{id}/approve` | Approve registration |
| PUT | `/admin/users/{id}/role` | Change user role |
| DELETE | `/admin/users/{id}` | Delete user |
| GET | `/admin/stats` | System stats (scan counts, users, etc.) |
| GET | `/admin/scans` | All scans (admin view) |
| GET | `/admin/config` | App config key/value store |
| PUT | `/admin/config/{key}` | Update config value |

### `/api/chat` — Support Chat
| Method | Path | Description |
|---|---|---|
| GET | `/chat/messages` | Get message history |
| POST | `/chat/messages` | Send message |
| PUT | `/chat/read` | Mark messages as read |
| GET | `/chat/unread-count` | Unread message count |
| WS | `/chat/ws/{role}` | WebSocket (`role`: "user" or "admin"). Token via `?token=` query param |

WebSocket messages are JSON: `{ type: "message"|"status", message, topic, sender_role, sender_name, created_at, admin_online }`

### `/api/analytics` — Analytics
| Method | Path | Description |
|---|---|---|
| GET | `/analytics/overview` | Summary stats for dashboard |
| GET | `/analytics/trends` | Time-series scan data |
| GET | `/analytics/threat-types` | Breakdown by threat category |
| GET | `/analytics/top-senders` | Most scanned senders |

### Other routers
- `/api/notifications/*` — in-app notification CRUD
- `/api/collaborate/*` — workspace and member management
- `/api/privacy/*` — privacy settings, tier2 consent, data export
- `/api/settings/*` — user preferences
- `/api/users/*` — user management (admin)
- `/api/team/*` — team roles
- `/api/feedback/*` — ML feedback submission
- `/api/threat-intel/*` — manual threat intel lookup

### Non-router health routes
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | None | Basic liveness probe |
| GET | `/health/detailed` | Admin | System metrics (CPU, memory, disk, ML) |
| GET | `/ml/metrics` | Admin | ML model metrics |
| POST | `/ml/train` | Admin | Retrain TF-IDF model |
| GET | `/health-monitor` | Admin | Health monitor status |
| POST | `/health-monitor/check` | Admin | Trigger immediate health check |

---

## Frontend Pages and Routes

| Route | Page | Description |
|---|---|---|
| `/login` | Login.jsx | Login form with 2FA support |
| `/register` | Register.jsx | Registration form |
| `/check-status` | CheckStatus.jsx | Public backend status page |
| `/dashboard` | Dashboard.jsx | Overview widgets (stats, recent scans, charts) |
| `/analyze` | Analyze.jsx | File upload, drag-and-drop, analysis trigger |
| `/history` | History.jsx | Paginated scan history with search |
| `/analytics` | Analytics.jsx | Charts and trend visualizations |
| `/reports` | Report.jsx | Scan detail viewer + comparison + PDF export |
| `/reports/:id` | Report.jsx | Direct link to a scan report |
| `/graph` | IOCGraph.jsx | Force-directed SVG IOC visualization |
| `/settings` | Settings.jsx | User preferences — tabbed layout: Account, Integrations, Reports, Privacy (all former Privacy.jsx features merged here) |
| `/privacy` | ~~Privacy.jsx~~ | **Deleted** — merged into Settings → Privacy tab |
| `/users` | UserManagement.jsx | User list + approval (admin) |
| `/admin` | Admin.jsx | Admin dashboard + audit logs |
| `/sessions` | Sessions.jsx | Active session management |
| `/collaborate` | Collaborate.jsx | Workspace management |
| `/news` | News.jsx | Threat intelligence news feed |
| `/api-docs` | APIDocumentation.jsx | In-app API reference |
| `/*` | — | Redirects to `/dashboard` |

All routes except `/login`, `/register`, `/check-status` require authentication (`ProtectedRoute` wraps them in `Layout`).

---

## IOC Graph (IOCGraph.jsx)

Force-directed SVG graph built with a custom physics simulation (no D3).

- Center node = scan subject/filename
- IOC nodes placed in concentric rings: ring 1 (r=150, max 8 nodes), ring 2 (r=250, max 12), ring 3 (r=340, max 16), ring 4+ (r=420)
- Physics: repulsion force 4500, spoke spring target 180px, gravity 0.006, damping 0.76
- No ring-to-ring edges between IOC nodes (prevents clustering)
- Center → IOC edges only
- Report name uses `scan.subject || scan.filename` (handles IMAP-fetched emails)
- Export filename is sanitized from subject or filename

---

## Support Chat (SupportChat.jsx + chat router)

- FAB button in bottom-right corner (`App.jsx`), shown to authenticated users only
- Topics: Technical Issue, Bug Report, Feature Request, Account Help, User Guide, Other
- Real-time via WebSocket (`/api/chat/ws/user?token=<jwt>`)
- Auto-reconnects every 3s on disconnect
- Image upload (`UploadBar` component) is only available in the chat step, which is reached via Technical Issue, Bug Report, Feature Request, Account Help, and Other topics. The menu, guide list, and guide detail steps do **not** show the upload option.
- Chat panel: fixed `height: 530px` (not `max-height`) to prevent size changes between menu/chat steps
- FAB icon: headset SVG when closed, X SVG when open (no emoji)

---

## Settings Page (Settings.jsx)

Tabbed layout matching the Admin Panel pattern. Four tabs:

| Tab | Sections |
|---|---|
| **Account** | Profile Information (username, email, role), Account Stats (scan count, created date, user ID), Security (Change Password — currently disabled) |
| **Integrations** | API Keys (8 default services in 2-column grid + custom key support), Connected Email Accounts (IMAP add/sync/remove + setup guide) |
| **Reports** | Branded Reports (company name, logo URL, primary color, footer text for PDF exports), Scheduled Report Exports (daily/weekly PDF email delivery), Export Data (CSV/XLSX/analytics download) |
| **Privacy** | External Threat Intelligence consent toggle (`tier2_consent`), Auto-delete toggle + retention slider (1–365 days), manual cleanup trigger |

- Active tab indicated by `2px solid var(--cyan)` bottom border, matching the Admin Panel tab style.
- A shared `Toggle` inline component is used for all boolean toggles in the Privacy tab to avoid duplicate button markup.
- IMAP section lives under Integrations (not a separate page) since it is a connectivity/credential concern.

---

## Key Patterns and Conventions

### Backend
- All DB access via SQLAlchemy ORM with `get_db()` dependency injection.
- `run_migrations()` in `database.py` handles additive SQLite migrations at startup without Alembic.
- Sensitive credentials (IMAP passwords) stored Fernet-encrypted using a key derived from `JWT_SECRET_KEY` via PBKDF2.
- `tier2_consent` in `PrivacySettings` must be `True` before any scan data (URLs, IPs, hashes) is sent to external APIs (VirusTotal, AbuseIPDB, etc.).
- Rate limiting via `slowapi` on auth endpoints.
- Feature extraction (`extract_ml_features`) is imported directly into `train_model.py` to guarantee training/inference consistency.
- `ScanRecord.source` field: `"upload"` for file uploads, `"imap"` for IMAP-fetched emails.
- `ScanRecord.subject` stores the decoded email subject (critical for IMAP emails where filename is not meaningful).

### Frontend
- Vite proxy: in dev, all `/api/*` requests go to `localhost:8000`. Set `VITE_API_URL` for production.
- JWT access token stored in JS module variable (`_token` in `api.js`), not localStorage.
- Silent refresh: 401 responses automatically retry after refreshing token via cookie.
- User display profile cached in `localStorage` as `eta_user` (non-sensitive, just for instant render).
- CSS theming via CSS custom properties (`var(--text)`, `var(--bg)`, `var(--border)`, etc.) defined in `index.css`. Dark/light mode toggled by `useTheme`.
- All pages are lazy-loaded (Vite code splitting) except Login, Dashboard, Analyze, CheckStatus.
- Global keyboard shortcut `Ctrl+K` opens `SearchBar`.

---

## IMAP Integration

- Users add accounts via Settings page → `POST /api/imap/accounts`.
- Host auto-resolves from email domain (Gmail → `imap.gmail.com:993`, Outlook → `outlook.office365.com:993`, etc.).
- Password encrypted with Fernet before storing in `email_accounts.password_enc`.
- Sync fetches unseen emails from configured folder (default: INBOX), runs `run_analysis()` on each, stores results with `source="imap"`.
- `ScanRecord.subject` is populated from the email's `Subject` header for IMAP scans.
- IMAP badges shown in Report page sidebar and IOC Graph when `scan.source === "imap"`.

---

## Known Architecture Decisions

1. **SQLite in dev, PostgreSQL in prod**: The `_is_sqlite` flag in `database.py` conditionally enables WAL mode and uses `StaticPool`. In prod, switch to PostgreSQL and set `workers=4` in `main.py`.
2. **No Alembic**: Migrations are manual `ALTER TABLE ADD COLUMN` calls in `run_migrations()`. Fine for SQLite dev; use Alembic for production schema changes.
3. **XGBoost trained on synthetic + real data**: 8,000 real samples (from `ml/data/`) + 18,000 synthetic. Synthetic covers modern phishing patterns that real datasets miss (auth'd phishing, HTTPS phishing URLs, brand impersonation).
4. **DistilBERT always active**: The semantic model at `ml/semantic_model/` is always used. Its presence is verified at startup; if missing, `main.py` logs an error and analysis falls back to heuristics only.
5. **No Google OAuth**: `googleAuth.js` was deleted. Standard email/password auth only.
6. **Admin created from env vars**: No separate setup script. Set `ADMIN_EMAIL` + `ADMIN_PASSWORD` before first run; admin is created automatically by `create_default_admin()`.

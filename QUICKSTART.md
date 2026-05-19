# ETA Email Threat Analyzer — Quick Start Guide

## ✅ Setup Complete!

Your ETA Email Threat Analyzer is ready to run. All dependencies have been installed.

## 🚀 Running the Application

### Option 1: Batch Files (Windows) — Easiest

From the project root (`eta-email-threat-analyzer/`), run these in separate terminal windows:

**Terminal 1 — Backend:**
```bash
START_BACKEND.bat
```

**Terminal 2 — Frontend:**
```bash
START_FRONTEND.bat
```

### Option 2: Manual (Windows PowerShell/Command Prompt)

**Terminal 1 — Backend:**
```bash
cd eta\backend
venv\Scripts\activate.bat
python main.py
```

**Terminal 2 — Frontend:**
```bash
cd eta\frontend
npm run dev
```

### Option 3: Manual (Linux/Mac)

**Terminal 1 — Backend:**
```bash
cd eta/backend
source venv/bin/activate
python main.py
```

**Terminal 2 — Frontend:**
```bash
cd eta/frontend
npm run dev
```

---

## 📍 Access the Application

Once both servers are running:

- **Frontend (React UI):** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs (Swagger UI)

## 🔐 Default Credentials

```
Email:    admin@eta.local
Password: AdminPassword123!
```

⚠️ **Change these immediately after first login!**

---

## 📋 What's Included

| Component | Technology | Port | Purpose |
|-----------|-----------|------|---------|
| Backend | FastAPI + SQLAlchemy | 8000 | ML analysis, APIs, authentication |
| Frontend | React 18 + Vite | 3000 | Web UI, dashboard, analysis interface |
| Database | SQLite (dev) | — | Email scans, user data, analytics |
| ML Pipeline | XGBoost + DistilBERT + TF-IDF | — | 3-layer threat detection |

---

## 🔍 Project Structure

```
eta-email-threat-analyzer/
├── eta/backend/          ← FastAPI server + ML pipeline
│   ├── main.py          ← Entry point
│   ├── analysis_engine.py ← Core threat detection
│   ├── ml/              ← ML models (XGBoost, DistilBERT)
│   └── routers/         ← API endpoints
├── eta/frontend/         ← React/Vite application
│   └── src/
│       ├── pages/       ← Dashboard, Analysis, History, etc.
│       └── components/  ← Reusable UI components
└── CLAUDE.md            ← Full project documentation
```

---

## 🎯 Key Features

✅ **Email Threat Detection** — File upload or IMAP integration  
✅ **ML-Powered Classification** — XGBoost (primary) + DistilBERT (semantic) + TF-IDF (fallback)  
✅ **Rich Dashboard** — Analytics, trends, threat visualization  
✅ **IOC Graph** — Force-directed visualization of Indicators of Compromise  
✅ **Report Generation** — PDF export with custom branding  
✅ **User Management** — Roles: superadmin, admin, analyst, viewer, user  
✅ **Team Collaboration** — Workspaces and shared reports  
✅ **Real-time Chat** — In-app support via WebSocket  

---

## 🐛 Troubleshooting

### Backend won't start

```bash
# Check Python version (need 3.8+)
python --version

# Activate venv and verify imports
venv\Scripts\activate
python -c "import fastapi; print('✓ FastAPI installed')"

# Check port 8000 is free
netstat -ano | findstr :8000
```

### Frontend build issues

```bash
# Clear node_modules and reinstall
cd eta/frontend
rm -r node_modules package-lock.json
npm install
npm run dev
```

### Database locked error

```bash
# SQLite WAL files may exist; remove them
rm -f eta/backend/eta.db-wal eta/backend/eta.db-shm
```

---

## 📚 Full Documentation

For detailed architecture, API reference, and advanced setup:
- See **`CLAUDE.md`** in the project root

---

## 🎓 What's Next?

1. Log in with the default admin credentials
2. Explore the Dashboard for overview
3. Go to **Analyze** to upload a test email
4. Check **History** to see past scans
5. Visit **Settings** to configure integrations and privacy options

Enjoy! 🚀

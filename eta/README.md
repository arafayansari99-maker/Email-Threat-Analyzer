# 🛡 ETA — Email Threat Intelligence Analyzer v2

Production-ready full-stack cybersecurity platform deployed **free** on the internet.

---

## 🌐 Free Deployment Stack

| Service | Platform | Free Tier |
|---------|----------|-----------|
| **Frontend** | [Vercel](https://vercel.com) | Unlimited static sites |
| **Backend API** | [Render](https://render.com) | 750 hrs/month free web service |
| **Database** | [Neon](https://neon.tech) | 512 MB free PostgreSQL |

---

## 🚀 Deploy in 15 Minutes

### Step 1 — Database (Neon, 2 min)

1. Sign up at [neon.tech](https://neon.tech)
2. Create a new project → copy the **Connection String**
3. It looks like: `postgresql://user:pass@ep-xxx.us-east-1.aws.neon.tech/neondb?sslmode=require`

### Step 2 — Backend (Render, 5 min)

1. Sign up at [render.com](https://render.com)
2. New → **Web Service** → connect your GitHub repo
3. Settings:
   - **Root Directory:** `backend`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add **Environment Variables:**
   ```
   DATABASE_URL       = (your Neon connection string)
   JWT_SECRET_KEY     = (generate: python -c "import secrets; print(secrets.token_hex(32))")
   FRONTEND_URL       = (your Vercel URL — add after Step 3)
   VIRUSTOTAL_API_KEY = (optional)
   ABUSEIPDB_API_KEY  = (optional)
   ```
5. Deploy → copy your Render URL: `https://eta-backend.onrender.com`

> ⚠️ Free Render services sleep after 15 min of inactivity — first request takes ~30s to wake.

### Step 3 — Frontend (Vercel, 3 min)

1. Sign up at [vercel.com](https://vercel.com)
2. Import your GitHub repo
3. Settings:
   - **Root Directory:** `frontend`
   - **Framework:** Vite
   - **Build Command:** `npm run build`
   - **Output:** `dist`
4. Add **Environment Variable:**
   ```
   VITE_API_URL = https://eta-backend.onrender.com
   ```
5. Deploy → get URL: `https://eta-app.vercel.app`

### Step 4 — Connect them

- Go back to Render → update `FRONTEND_URL` = `https://eta-app.vercel.app`
- Redeploy Render service

### Step 5 — Chrome Extension

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Open `popup.js` → update line 3:
   ```js
   let API = 'https://eta-backend.onrender.com'
   ```

---

## 🏃 Local Development

```bash
# Backend
cd backend
python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example .env   # edit with your values
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev   # → http://localhost:3000
```

---

## 📁 Project Structure

```
eta/
├── backend/
│   ├── main.py              # FastAPI app + CORS
│   ├── database.py          # SQLAlchemy models (SQLite/PostgreSQL)
│   ├── analysis_engine.py   # Full analysis pipeline
│   ├── requirements.txt
│   └── routers/
│       ├── auth.py          # JWT register/login
│       ├── analysis.py      # /analyze-email, /extension-scan
│       ├── history.py       # /scan-history, /stats
│       └── reports.py       # /report/{id}, PDF, JSON
│
├── frontend/
│   ├── src/
│   │   ├── pages/           # Dashboard, Analyze, History, Report, IOCGraph, Analytics
│   │   ├── components/      # Layout (responsive sidebar), UI primitives
│   │   ├── hooks/useAuth    # JWT auth context
│   │   └── services/api.js  # Axios with auto-token & 401 redirect
│   ├── vercel.json          # SPA routing
│   └── vite.config.js
│
├── extension/               # Chrome MV3 extension
│   ├── manifest.json
│   ├── popup.html/js        # Threat popup UI
│   ├── content.js           # Gmail injection + badge
│   └── background.js        # Service worker
│
├── render.yaml              # Render IaC config
└── .env.example
```

---

## 🔑 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Get JWT token |
| GET  | `/auth/me` | Current user |
| POST | `/api/analyze-email` | Upload `.eml`/`.msg`/`.txt` |
| POST | `/api/extension-scan` | Chrome extension scan |
| GET  | `/api/scan-history` | Paginated history |
| GET  | `/api/stats` | Dashboard statistics |
| GET  | `/api/report/{id}` | Full JSON report |
| GET  | `/api/report/{id}/json` | Download JSON |
| POST | `/api/report/{id}/pdf` | Download PDF |
| DELETE | `/api/scan/{id}` | Delete scan |

---

## 🔒 Environment Variables

```env
# Required
DATABASE_URL=sqlite:///./eta.db          # or Neon PostgreSQL URL
JWT_SECRET_KEY=your-strong-secret-key

# Optional (enable live threat intel)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SAFE_BROWSING_API_KEY=

# CORS
FRONTEND_URL=https://your-vercel-app.vercel.app
```

---

## 📱 Responsive Design

- **Mobile** (< 640px): bottom nav hidden, compact layouts, touch-friendly
- **Tablet** (640–1024px): adaptive grid, collapsible sidebar
- **Desktop** (> 1024px): full sidebar, multi-column layouts

---

## ⚡ Performance

- Code splitting (vendor/charts chunks)
- Gzip middleware on backend
- Lazy route loading
- Optimistic UI updates
- SQLAlchemy connection pooling

---

## 🐛 Troubleshooting

**CORS errors:** Add your Vercel URL to `FRONTEND_URL` in Render env vars

**Render cold starts:** First request after inactivity takes ~30s — this is normal on free tier

**Extension not scanning:** Make sure you've opened a specific email (not just inbox) in Gmail

**PDF fails:** ReportLab must be installed — it's in `requirements.txt`

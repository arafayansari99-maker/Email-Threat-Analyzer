# ETA Email Threat Analyzer - Cloud Deployment Guide

This guide covers deploying the ETA application to major cloud platforms.

---

## Platform Overview

| Platform | Backend | Frontend | Free Tier | Notes |
|----------|---------|----------|----------|-------|
| **Render** | ✅ | ❌ | ✅ | Best for Python backends |
| **Railway** | ✅ | ✅ | ✅ | Easiest full-stack |
| **Vercel** | ❌ | ✅ | ✅ | Best for frontend |
| **Fly.io** | ✅ | ✅ | ✅ | Good for containers |
| **Heroku** | ✅ | ✅ | ❌ | Paid after hobby |

**Recommended**: Deploy backend to **Render** + frontend to **Vercel**

---

## Option 1: Render (Backend) + Vercel (Frontend)

### Part A: Deploy Backend to Render

#### Step 1: Prepare Repository
```bash
# Ensure code is pushed to GitHub
git add .
git commit -m "Ready for deployment"
git push origin main
```

#### Step 2: Create Render Account
1. Go to https://render.com
2. Sign up with GitHub

#### Step 3: Create Backend Service
1. Click **New** → **Web Service**
2. Connect your GitHub repository
3. Configure:
   - **Name**: `eta-backend`
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT`

#### Step 4: Environment Variables
Add these in Render dashboard:
```
DATABASE_URL=sqlite:///./eta.db
SECRET_KEY=your-super-secret-key-change-this
JWT_SECRET=your-jwt-secret-change-this
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=admin123
```

#### Step 5: Deploy
Click **Create Web Service**. Wait 2-3 minutes for build.

**Backend URL**: `https://eta-backend.onrender.com`

---

### Part B: Deploy Frontend to Vercel

#### Step 1: Create Vercel Account
1. Go to https://vercel.com
2. Sign up with GitHub

#### Step 2: Import Project
1. Click **Add New** → **Project**
2. Import your repository
3. Select the `eta/frontend` folder

#### Step 3: Configure
- **Framework Preset**: `Vite`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`

#### Step 4: Environment Variables
Add:
```
VITE_API_URL=https://eta-backend.onrender.com
```

#### Step 5: Deploy
Click **Deploy**. Wait 1-2 minutes.

**Frontend URL**: `https://eta-email-threat-analyzer.vercel.app`

---

## Option 2: Railway (Full Stack)

### Step 1: Install Railway CLI
```bash
# Install via npm
npm install -g @railway/cli

# Or via npm
npm i -g @railway/cli
```

### Step 2: Login
```bash
railway login
```

### Step 3: Initialize Project
```bash
cd eta-email-threat-analyzer
railway init
# Select "Empty Project" when prompted
```

### Step 4: Deploy Backend (Linux/Mac)
```bash
cd eta/backend
railway service add backend

# Set environment
railway variables set DATABASE_URL=sqlite:///./eta.db
railway variables set SECRET_KEY=your-secret-key

# Deploy
railway up
```

**Alternative: Deploy via GitHub**
1. Connect GitHub repo in Railway dashboard
2. Select the backend folder
3. Configure:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:$PORT`

### Step 5: Deploy Frontend
```bash
cd eta/frontend
railway service add frontend

# Set API URL
railway variables set VITE_API_URL=https://your-backend.railway.app

# Build & Deploy
railway up
```

---

## Option 3: Fly.io (Containerized)

### Step 1: Install Fly CLI
```bash
# macOS
brew install flyctl

# Linux
curl -L https://fly.io/install.sh | sh

# Windows (PowerShell)
irm https://fly.io/install.ps1 | iex
```

### Step 2: Login
```bash
fly auth login
```

### Step 3: Create Dockerfile for Backend
Create `eta/backend/Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "main:app", "--bind", "0.0.0.0:8001"]
```

### Step 4: Deploy Backend
```bash
cd eta/backend
fly launch --name eta-backend
# Follow prompts, select closest region

# Set secrets
fly secrets set DATABASE_URL=sqlite:///./eta.db
fly secrets set SECRET_KEY=your-secret-key

# Deploy
fly deploy
```

### Step 5: Deploy Frontend
```bash
cd eta/frontend
fly launch --name eta-frontend
# Select "Frontend Only" when prompted
# Set VITE_API_URL to your backend URL
```

---

## Option 4: PythonAnywhere (Backend Only)

### Step 1: Create Account
1. Go to https://pythonanywhere.com
2. Create free account

### Step 2: Upload Code
1. Go to **Files** tab
2. Upload your `eta/backend` folder

### Step 3: Setup Virtual Environment
```bash
# In PythonAnywhere bash console
mkvirtualenv eta
pip install -r requirements.txt
```

### Step 4: Configure WSGI
Edit `/var/www/yourusername_pythonanywhere_com_wsgi.py`:
```python
import sys
_path = '/home/yourusername/eta/backend'
if _path not in sys.path:
    sys.path.insert(0, _path)

from main import app as application
```

### Step 5: Configure API Endpoint
In the Web tab:
- Set **WSGI configuration file**
- Point to your WSGI file

---

## Option 5: Hetzner (Self-Hosted VPS)

### Step 1: Create Server
1. Sign up at https://hetzner.com/cloud
2. Create new project
3. Add server (ubuntu 22.04)

### Step 2: SSH and Install Docker
```bash
ssh root@your-server-ip

# Install Docker
apt update
apt install -y docker.io docker-compose
```

### Step 3: Deploy
```bash
# Clone repository
git clone https://github.com/yourusername/eta-email-threat-analyzer.git
cd eta-email-threat-analyzer

# Edit docker-compose.yml for production
# Update Environment variables

# Start services
docker-compose up -d
```

### Step 4: Setup Nginx + SSL
```bash
# Install nginx and certbot
apt install nginx certbot python3-certbot-nginx

# Configure nginx
nano /etc/nginx/sites-available/eta
```

NGINX config:
```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
    }

    location /api {
        proxy_pass http://localhost:8001;
        proxy_set_header Host $host;
    }
}
```

```bash
# Enable site and SSL
ln -s /etc/nginx/sites-available/eta /etc/nginx/sites-enabled/
certbot --nginx -d yourdomain.com
```

---

## Production Checklist

### Security
- [ ] Change all default passwords
- [ ] Use strong `SECRET_KEY` and `JWT_SECRET`
- [ ] Enable HTTPS/SSL
- [ ] Configure CORS for production domain
- [ ] Set up firewall rules

### Database
- [ ] Use PostgreSQL for production (not SQLite)
- [ ] Set up automated backups
- [ ] Configure connection pooling

### Monitoring
- [ ] Set up error logging
- [ ] Configure health checks
- [ ] Set up alerts

### Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection | `postgresql://user:pass@host/db` |
| `SECRET_KEY` | Application secret | `random-32-char-string` |
| `JWT_SECRET` | JWT signing | `random-32-char-string` |
| `VITE_API_URL` | Backend URL | `https://api.yourapp.com` |

---

## Troubleshooting

### CORS Errors
Add to backend `main.py`:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-vercel-app.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 502 Bad Gateway
- Check if backend is running
- Verify environment variables
- Check logs: `railway logs` or Render dashboard

### Database Connection Failed
- Verify `DATABASE_URL` format
- Check if database service is running
- For SQLite: ensure write permissions

### Static Assets Not Loading
- Rebuild frontend: `npm run build`
- Check Vite config output directory
- Verify `VITE_API_URL` is correct
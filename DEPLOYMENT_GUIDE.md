# ETA Email Threat Analyzer - Deployment Guide

## Overview

ETA (Email Threat Analyzer) is a full-stack application with:
- **Frontend**: React + Vite (port 3000)
- **Backend**: FastAPI/Python (port 8001)
- **Database**: SQLite (file-based)

---

## Prerequisites

- Node.js 18+ and npm
- Python 3.9+ with pip
- Git

---

## Local Development

### 1. Clone the Repository

```bash
git clone <repository-url>
cd eta-email-threat-analyzer
```

### 2. Backend Setup

```bash
cd eta/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the backend server
python main.py
```

The backend will start on `http://localhost:8001`

### 3. Frontend Setup

Open a new terminal:

```bash
cd eta/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will start on `http://localhost:3000`

---

## Production Deployment

### Option 1: Docker Compose (Recommended)

```bash
cd eta

# Build and run all services
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

Services:
- Frontend: `http://localhost`
- Backend API: `http://localhost:8001`
- API Docs: `http://localhost:8001/docs`

### Option 2: Manual Production Build

#### Backend

```bash
cd eta/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Set environment variable for production
export ETA_ENV=production

# Run with gunicorn
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8001
```

#### Frontend

```bash
cd eta/frontend

# Build for production
npm run build

# Preview the build
npm run preview

# Or serve with nginx (example nginx.conf provided)
```

---

## Environment Variables

### Backend (.env)

```env
# Database
DATABASE_URL=sqlite:///./eta.db

# Security
SECRET_KEY=your-secret-key-change-in-production
JWT_SECRET=your-jwt-secret-change-in-production

# Admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme123
```

### Frontend (.env)

```env
VITE_API_URL=http://localhost:8001
# For production: VITE_API_URL=https://your-api-domain.com
```

---

## Deployment to Cloud Platforms

### Vercel (Frontend)

```bash
cd eta/frontend

# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

Note: Set `VITE_API_URL` in Vercel dashboard to your backend URL.

### Render (Backend)

1. Create a new Web Service on Render
2. Connect your GitHub repository
3. Set:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app`
4. Add environment variables

### Railway

```bash
# Install Railway CLI
npm i -g @railway/cli

railway login
railway init

# Deploy backend
cd eta/backend
railway deploy

# Deploy frontend
cd eta/frontend
railway deploy
```

---

## SSL/HTTPS Setup

### Using Nginx

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    # Frontend
    location / {
        root /var/www/eta-frontend/dist;
        try_files $uri /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://localhost:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### Using Certbot

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Generate SSL certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

---

## Troubleshooting

### CORS Issues

If you get CORS errors in production, update the backend CORS settings in `main.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Production domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Database Migration

```bash
# Initialize database
cd eta/backend
python -c "from database import init_db; init_db()"
```

### Check Logs

```bash
# Docker
docker-compose logs -f

# Backend (gunicorn)
tail -f /var/log/eta-backend.log

# Frontend (nginx)
tail -f /var/log/nginx/error.log
```

---

## Performance Optimization

- Enable gzip/brotli compression (included in Vite config)
- Use CDN for static assets in production
- Enable caching headers
- Consider using Redis for caching (optional)

---

## Health Check Endpoints

- Backend: `GET /api/health`
- Frontend: Serve index.html (SPA fallback handles routing)

---

## Default Credentials

After first deployment, login with:
- **Email**: `admin@example.com`
- **Password**: `admin123` (change immediately!)

Or create new users via the registration page.
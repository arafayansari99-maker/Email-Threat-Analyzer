# Docker Compose Run Guide

This guide explains how to run the ETA Email Threat Analyzer using Docker Compose (single-machine). It assumes you have Docker and Docker Compose installed.

Prerequisites
- Docker (Engine) and Docker Compose (Compose V2 or Docker Desktop)
- Git checkout of the repo (you already have it)

1) Prepare environment variables
- Create a `.env` file in the repo root (next to this `docker-compose.yml`). Example values are in `eta/.env.example`.
- At minimum set:
  - `JWT_SECRET_KEY` — generate a 64-char hex string:
    ```bash
    python -c "import secrets; print(secrets.token_hex(32))"
    ```
  - `ADMIN_EMAIL` and `ADMIN_PASSWORD` — for the initial admin user (change password after first login)
  - `DB_PASSWORD` — used by the `db` service (or rely on the default in `docker-compose.yml`)

Example `.env` (minimal):
```
DB_PASSWORD=your_db_password_here
JWT_SECRET_KEY=<64-char-hex>
ADMIN_EMAIL=admin@yourorg.com
ADMIN_PASSWORD=ChangeThisImmediately!AtLeast16Chars
ENVIRONMENT=production
```

2) Verify model files
- The backend expects ML artifacts under `eta/backend/ml`. The compose mounts `./backend/ml` into the container. Ensure the following exist if you rely on ML features:
  - `eta/backend/ml/phishing_model.pkl`
  - `eta/backend/ml/feature_scaler.pkl`
  - `eta/backend/ml/model_meta.json`
  - `eta/backend/ml/semantic_model/` (optional but recommended)

3) Build and run (development / production)
- From the repo root run to build and start all services:
```bash
docker-compose up --build
```
- To run in the background (detached):
```bash
docker-compose up -d --build
```

4) Service names, ports and URLs
- PostgreSQL: service `db` → host port `5432` (mapped)
- Backend API: service `backend` → http://localhost:8000 (OpenAPI docs at `/docs` when `ENVIRONMENT!=production`)
- Frontend: service `frontend` → http://localhost:3000

5) Logs and troubleshooting
- View combined logs:
```bash
docker-compose logs -f
```
- Tail a single service logs:
```bash
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f db
```
- If the backend fails to start, inspect `backend` logs and ensure the DB is healthy and model files are readable.

6) Rebuild after code changes
- If you change Python dependencies or Dockerfiles, rebuild:
```bash
docker-compose build --no-cache backend frontend
docker-compose up -d
```

7) Stop and remove containers
- Stop (detached or foreground):
```bash
docker-compose down
```
- Remove volumes (data will be lost):
```bash
docker-compose down -v
```

8) Useful tips
- Use `ENVIRONMENT=development` in `.env` to enable `/docs` and OpenAPI during development.
- The backend mounts `./backend/ml` into the container — you can add model files there on the host and the container will use them immediately (no rebuild required).
- For production, ensure `JWT_SECRET_KEY` and `DB_PASSWORD` are strong and managed by a secrets manager.

9) Accessing the app
- Frontend UI: http://localhost:3000
- API root: http://localhost:8000
- API docs (if enabled): http://localhost:8000/docs

If you want, I can also add a `docker-compose.override.yml` with development-friendly mounts (source code mounts, hot-reload) or a small README section updating the project README with these steps. Which would you prefer? 

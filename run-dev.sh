#!/usr/bin/env bash
# Run backend and frontend in background (logs written to files)
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting ETA backend..."
cd "$ROOT_DIR/eta/backend"
if [ ! -d "venv" ]; then
  python3 -m venv venv
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
else
  source venv/bin/activate
fi
[ -f .env ] || cp ../.env.example .env
nohup python main.py > "$ROOT_DIR/backend_out.txt" 2>&1 &
echo "Backend started (logs: $ROOT_DIR/backend_out.txt)"

echo "Starting ETA frontend..."
cd "$ROOT_DIR/eta/frontend"
[ -d node_modules ] || npm install
nohup npm run dev > "$ROOT_DIR/frontend_out.txt" 2>&1 &
echo "Frontend started (logs: $ROOT_DIR/frontend_out.txt)"

echo "All services started."

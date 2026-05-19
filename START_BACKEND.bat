@echo off
cd /d "%~dp0eta\backend"
echo Starting ETA Backend (FastAPI on http://localhost:8000)...
echo API Docs available at http://localhost:8000/docs
echo.
call venv\Scripts\activate.bat
python main.py

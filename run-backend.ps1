<#
Run backend in current PowerShell terminal.
Usage: Open a VS Code terminal and run: .\run-backend.ps1
#>
Write-Host 'Starting ETA backend...' -ForegroundColor Cyan
Push-Location 'eta\backend'

if (-not (Test-Path './venv')) {
    python -m venv venv
    Write-Host 'Created virtualenv venv' -ForegroundColor Green
    & .\venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
} else {
    & .\venv\Scripts\Activate.ps1
}

if (-not (Test-Path '.env')) {
    Copy-Item '..\.env.example' '.env' -Force
    Write-Host 'Copied ../.env.example to .env - edit eta/backend/.env to set ADMIN_EMAIL, ADMIN_PASSWORD, JWT_SECRET_KEY' -ForegroundColor Yellow
}

Write-Host 'Running backend (Python/uvicorn) - logs stream to console.' -ForegroundColor Cyan
python main.py
Pop-Location

<#
Run frontend (Vite) in current PowerShell terminal.
Usage: Open a VS Code terminal and run: .\run-frontend.ps1
#>
Write-Host 'Starting ETA frontend...' -ForegroundColor Cyan
Push-Location 'eta\frontend'

if (-not (Test-Path 'node_modules')) {
    npm install
}

Write-Host 'Running frontend (Vite) - logs stream to console.' -ForegroundColor Cyan
npm run dev
Pop-Location

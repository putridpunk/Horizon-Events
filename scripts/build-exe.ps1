# Builds dist\HorizonEvents.exe: a single-file Windows app that serves the API and dashboard locally.
# Prerequisites: .venv with requirements.txt and requirements-build.txt installed, and frontend\dist built
# (cd frontend; npm install; npm run build).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path "frontend\dist\index.html")) { throw "frontend\dist not found. Build the frontend first." }

& ".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile `
  --name HorizonEvents `
  --paths backend `
  --add-data "frontend\dist;static" `
  --add-data "sample_logs;sample_logs" `
  --collect-submodules uvicorn `
  --collect-submodules app `
  --collect-submodules sklearn `
  --hidden-import multipart `
  backend\run_app.py

Write-Host "Built: $root\dist\HorizonEvents.exe"

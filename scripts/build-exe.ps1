# Builds dist\HorizonEvents.exe: a single-file Windows desktop app (native window, no console).
# Prerequisites: .venv with requirements.txt, requirements-desktop.txt and requirements-build.txt installed,
# and frontend\dist built (cd frontend; npm install; npm run build).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path "frontend\dist\index.html")) { throw "frontend\dist not found. Build the frontend first." }
if (-not (Test-Path "assets\horizon.ico")) { & ".venv\Scripts\python.exe" scripts\make_icon.py }

& ".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --noconsole `
  --name HorizonEvents `
  --icon "assets\horizon.ico" `
  --paths backend `
  --add-data "frontend\dist;static" `
  --add-data "sample_logs;sample_logs" `
  --collect-submodules uvicorn `
  --collect-submodules app `
  --collect-submodules sklearn `
  --collect-all webview `
  --collect-all pythonnet `
  --collect-all clr_loader `
  --hidden-import multipart `
  backend\run_app.py

Write-Host "Built: $root\dist\HorizonEvents.exe"

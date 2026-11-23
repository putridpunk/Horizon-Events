# Builds dist\HorizonEvents-Setup.exe (the installer) from dist\HorizonEvents.exe.
# Prerequisite: Inno Setup 6 (winget install JRSoftware.InnoSetup). Run scripts\build-exe.ps1 first.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Test-Path "dist\HorizonEvents.exe")) { throw "dist\HorizonEvents.exe not found. Run scripts\build-exe.ps1 first." }
$candidates = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe")
$iscc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup" }
& $iscc "installer\HorizonEvents.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
Write-Host "Built: $root\dist\HorizonEvents-Setup.exe"

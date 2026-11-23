# Signs the given file(s) with the code-signing certificate in SIGN_PFX_BASE64 (a base64-encoded .pfx)
# and SIGN_PFX_PASSWORD, and timestamps them so the signature outlives the certificate.
# Used by the release workflow; does nothing useful without those two environment variables.
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Files)
$ErrorActionPreference = "Stop"
if (-not $env:SIGN_PFX_BASE64) { throw "SIGN_PFX_BASE64 is not set" }
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)" }
$pfx = Join-Path $env:RUNNER_TEMP "codesign.pfx"
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIGN_PFX_BASE64))
try {
  foreach ($f in $Files) {
    & $signtool.FullName sign /f $pfx /p $env:SIGN_PFX_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $f
    if ($LASTEXITCODE -ne 0) { throw "signing $f failed" }
    & $signtool.FullName verify /pa $f
    if ($LASTEXITCODE -ne 0) { throw "signature on $f did not verify" }
  }
} finally { Remove-Item $pfx -Force -ErrorAction SilentlyContinue }

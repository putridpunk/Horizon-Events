# Refuses to release a version that has no hand-written patch notes.
# Usage: check-release-notes.ps1 v1.5.0   (looks for docs/release-notes/v1.5.0.md)
param([Parameter(Mandatory)][string]$Tag)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$file = Join-Path $root "docs\release-notes\$Tag.md"

if ($Tag -notmatch '^v\d+\.\d+\.\d+$') { throw "'$Tag' is not a version tag like v1.5.0." }
if (-not (Test-Path $file)) {
  throw "No patch notes for $Tag. Write docs/release-notes/$Tag.md (start from TEMPLATE.md), commit it, and push the tag again."
}
$text = Get-Content $file -Raw -Encoding UTF8
if ($text.Trim().Length -lt 80) { throw "docs/release-notes/$Tag.md is too short to be real patch notes." }
if ($text -match '<!--\s*TODO|\[TODO\]|\{\{') { throw "docs/release-notes/$Tag.md still contains template placeholders." }
Write-Host "Patch notes found: docs/release-notes/$Tag.md ($($text.Length) characters)"

# WSL wrapper for the security-audit validators.
# The bundled validators require POSIX O_NOFOLLOW/O_NONBLOCK, which native
# Windows Node.js does not expose. This wrapper runs them inside WSL Ubuntu.
#
# Usage:
#   powershell -File validate-wsl.ps1 findings <path-to-findings.json>
#   powershell -File validate-wsl.ps1 coverage <path-to-coverage-ledger.json>

param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet('findings', 'coverage')]
  [string]$Kind,

  [Parameter(Mandatory = $true, Position = 1)]
  [string]$Path
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
  Write-Error "File not found: $Path"
  exit 2
}

$skillWin = $PSScriptRoot
$scriptName = if ($Kind -eq 'findings') { 'validate-findings.cjs' } else { 'validate-coverage-ledger.cjs' }

$winFile = (Resolve-Path -LiteralPath $Path).Path -replace '\\', '/'
$winSkill = $skillWin -replace '\\', '/'

$linuxFile = (wsl.exe -d Ubuntu -- wslpath -a $winFile).Trim()
$linuxSkill = (wsl.exe -d Ubuntu -- wslpath -a $winSkill).Trim()

wsl.exe -d Ubuntu -- bash -lc "node '$linuxSkill/$scriptName' '$linuxFile'"
exit $LASTEXITCODE

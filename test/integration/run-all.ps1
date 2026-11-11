# Runs every integration phase in order and stops at the first failure.
# See README.md in this folder for runner prerequisites and safety notes.
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$InstallerPath = ''
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path $RepoRoot).Path
if (-not $InstallerPath) {
    $InstallerPath = Join-Path $RepoRoot 'dist\Cheat.Guard-Setup.exe'
}
$outDir = Join-Path $RepoRoot 'integration-output'
New-Item -ItemType Directory -Force $outDir | Out-Null

$phases = @(
    '00-prereqs.ps1',
    '01-install.ps1',
    '02-app-startup.ps1',
    '03-network-lockdown.ps1',
    '04-emergency-restore.ps1',
    '05-uninstall.ps1'
)

$results = @()
$failed = $false
foreach ($phase in $phases) {
    Write-Host ''
    Write-Host "================ $phase ================" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot $phase) -RepoRoot $RepoRoot -InstallerPath $InstallerPath -OutputDir $outDir
    if ($LASTEXITCODE -eq 0) {
        $results += "PASS  $phase"
    } else {
        $results += "FAIL  $phase (exit $LASTEXITCODE)"
        $failed = $true
        break
    }
}

Write-Host ''
$results | ForEach-Object { Write-Host $_ }
$results | Set-Content -LiteralPath (Join-Path $outDir 'summary.txt')
if ($failed) {
    Write-Host 'INTEGRATION HARNESS: FAILED' -ForegroundColor Red
    exit 1
}
Write-Host 'INTEGRATION HARNESS: ALL PHASES PASSED' -ForegroundColor Green
exit 0

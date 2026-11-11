# Phase 4: simulate an interrupted-session leftover (DNS pinned to the local
# filter, stale firewall rules) and verify the shipped emergency-restore tool
# repairs the machine while Cheat.Guard is not running.
param(
    [string]$RepoRoot,
    [string]$InstallerPath,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'
$fail = 0
function Assert([string]$label, [bool]$condition) {
    if ($condition) { Write-Host "  PASS  $label" }
    else { Write-Host "  FAIL  $label" -ForegroundColor Red; $script:fail = 1 }
}

$installedRestore = Join-Path $env:ProgramFiles 'CheatGuardCentral\support\emergency-restore.ps1'
$checkoutRestore = Join-Path $RepoRoot 'support\emergency-restore.ps1'
$tool = if (Test-Path -LiteralPath $installedRestore) { $installedRestore } else { $checkoutRestore }
Assert 'emergency-restore tool available' (Test-Path -LiteralPath $tool)

$app = Get-Process -Name 'CheatGuardCentral','CheatGuard' -ErrorAction SilentlyContinue
Assert 'no CheatGuard process running (tool refuses otherwise)' (-not $app)

# Simulate the leftover of a crashed session: pin DNS to the local filter.
$adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
if (-not $adapter) {
    Write-Host '  FAIL  no connected network adapter to test with' -ForegroundColor Red
    exit 1
}
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses '127.0.0.1'
Write-Host "Pinned DNS on adapter '$($adapter.Name)' to 127.0.0.1 (simulated leftover)..."

$pinned = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
Assert 'leftover state is really in place (DNS = 127.0.0.1)' ($pinned -contains '127.0.0.1')

Write-Host 'Running emergency-restore...'
& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File $tool
Start-Sleep -Seconds 3

$after = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
Assert 'emergency restore removed the pinned DNS' (-not ($after -contains '127.0.0.1'))

$rules = Get-NetFirewallRule -Group 'Cheat.Guard Strict Exam' -ErrorAction SilentlyContinue
Assert 'no leftover Cheat.Guard firewall rules remain' ($null -eq $rules -or @($rules).Count -eq 0)

exit $fail

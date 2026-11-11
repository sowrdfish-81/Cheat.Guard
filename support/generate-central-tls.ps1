# Generates the central monitor's TLS material on the INVIGILATOR PC:
#
#   1. a PKCS12 keystore with a self-signed certificate whose Subject
#      Alternative Names cover the LAN IP/hostnames students will type
#   2. a PKCS12 truststore containing exactly that certificate
#
# The truststore file is the ONLY thing that gets copied to student PCs
# (see the app's settings or docs/CENTRAL_TLS.md). The keystore and its
# password stay on the invigilator PC.
#
# Usage (from an elevated PowerShell on the invigilator PC):
#   powershell -ExecutionPolicy Bypass -File generate-central-tls.ps1 `
#       -LanIp 192.168.0.10 -ExtraDnsNames "exampc.lab.local"
#
# The password is prompted for or generated; it is needed again by the app
# (config value central.tls.storepass or the CHEATGUARD_CENTRAL_TLS_STOREPASS
# environment variable) and is never written to a file by this script.
param(
    [Parameter(Mandatory = $true)]
    [string]$LanIp,
    [string[]]$ExtraDnsNames = @(),
    [string]$OutputDirectory = (Join-Path $env:ProgramData 'CheatGuard\config'),
    [string]$StorePassword = ''
)

$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as Administrator (the keystore must land in ProgramData).'
}

$keytool = Join-Path (Split-Path -Parent (Split-Path -Parent (Get-Command java).Source)) 'bin\keytool.exe'
if (-not (Test-Path $keytool)) { throw "keytool.exe not found next to java ($keytool)" }

if (-not $StorePassword) {
    $secure = Read-Host 'Keystore password (min 8 chars)' -AsSecureString
    $StorePassword = (New-Object System.Net.NetworkCredential('', $secure)).Password
    if ($StorePassword.Length -lt 8) { throw 'Password too short (min 8 chars).' }
}

New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$keystore = Join-Path $OutputDirectory 'central-monitor-keystore.p12'
$truststore = Join-Path $OutputDirectory 'central-monitor-truststore.p12'
$certificate = Join-Path $env:TEMP 'cheatguard-central.cer'

if (Test-Path $keystore) {
    throw "Keystore already exists: $keystore. Delete it first if you really want a new identity."
}

$san = "SAN=dns:localhost,ip:127.0.0.1,ip:$LanIp"
foreach ($name in $ExtraDnsNames) {
    if ($name.Trim()) { $san += ",dns:$($name.Trim())" }
}

Write-Host 'Generating the monitor certificate (self-signed, 10 years)...'
& $keytool -genkeypair -alias central -keyalg RSA -keysize 2048 -validity 3650 `
    -dname "CN=Cheat.Guard Monitor" -ext $san `
    -keystore $keystore -storetype PKCS12 -storepass $StorePassword -keypass $StorePassword
if ($LASTEXITCODE -ne 0) { throw 'keytool -genkeypair failed' }

& $keytool -exportcert -alias central -rfc -keystore $keystore `
    -storepass $StorePassword -file $certificate
if ($LASTEXITCODE -ne 0) { throw 'keytool -exportcert failed' }

& $keytool -importcert -alias central -file $certificate -keystore $truststore `
    -storetype PKCS12 -storepass 'changeit' -noprompt
if ($LASTEXITCODE -ne 0) { throw 'keytool -importcert failed' }
Remove-Item -Force $certificate -ErrorAction SilentlyContinue

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host "  Keystore   (INVIGILATOR PC only): $keystore"
Write-Host "  Truststore (copy to STUDENT PCs):   $truststore"
Write-Host ''
Write-Host 'Tell the app the password ONE of these ways (never a command line, never a log):'
Write-Host ("  - environment variable CHEATGUARD_CENTRAL_TLS_STOREPASS, or")
Write-Host ("  - the app's own config value central.tls.storepass")
Write-Host ''
Write-Host 'Copy ONLY central-monitor-truststore.p12 to every student PC'
Write-Host 'under their CheatGuard config directory (or set central.tls.truststore).'

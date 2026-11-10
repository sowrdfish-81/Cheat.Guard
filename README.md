# CheatGuard Central

CheatGuard Central is a Windows desktop application for supervised online
exams: process control, DNS-layer website allowlisting, file-access walls,
device monitoring, tamper-evident sealed audit logs, and a live central
monitor the invigilator watches. Student PCs stream their audit events to the
invigilator's screen over **TLS** with an HMAC exam-code proof on top.

## Current release

Version: **1.9.31**
Release: [v1.9.31](https://github.com/sowrdfish-81/CheatGuard-Central/releases/tag/v1.9.31)

Release assets (see the release page for the exact SHA-256 of the current
installer; the in-app updater verifies it before installing):

- `CheatGuardCentral-Setup.exe`
- `CheatGuardCentral-Setup.exe.sha256`

## Features

- Process monitoring with startup cleanup and unauthorized-process enforcement.
- DNS-layer website allowlisting with IPv4/IPv6 handling and DoH restrictions.
- Exam-folder boundaries for supported applications and interpreters.
- NTFS-based file-access restrictions during an active session.
- USB, network-adapter, and portable-device monitoring.
- Protected audit logs: authenticated AES-256-GCM vaults for new seals,
  backward-compatible reading of legacy vaults.
- **Automatic encrypted vault backups** with atomic writes, configurable
  retention (count/age) and interrupted-copy self-healing -
  [docs/BACKUPS_AND_LOGS.md](docs/BACKUPS_AND_LOGS.md).
- **TLS 1.2/1.3 central-monitor transport** with full certificate
  validation (PKCS12 keystore/truststore, SAN check) plus the HMAC
  challenge-response exam-code proof - [docs/CENTRAL_TLS.md](docs/CENTRAL_TLS.md).
- **UDP beacon auto-discovery** of the invigilator PC (typed IP optional, even
  when a hotspot changes addresses), **automatic certificate pairing** on
  student PCs (no truststore copying), and automatic certificate rotation when
  the network changes.
- Diagnostic logs that rotate by size and age, separate from audit vaults.
- PBKDF2-HMAC-SHA256 administrator credentials with lockout protection.
- Proxy, VPN, remote-control, tunnel-port, and raw-egress protections.
- Recovery support for interrupted sessions and abnormal shutdowns.
- Non-blocking UI handling for UAC, sealing, diagnostics, and log operations.

## Requirements

- Windows 10 or later.
- JDK 17 or later for development and packaging.
- WiX Toolset 3.x for installer packaging. `build-installer.bat`
  auto-detects a repository-local copy under `tools\wix` (git-ignored) or an
  installed WiX; CI downloads WiX automatically.
- Administrator privileges for installer execution and protected session
  operations.

## Build the installer

```bat
build-installer.bat
```

Produces:

```text
dist\CheatGuardCentral-Setup.exe
dist\CheatGuardCentral-Setup.exe.sha256
```

The installer contains the application and its bundled Java runtime. WiX
binaries are build tooling and are never committed.

## Run the tests

All five headless suites run with an isolated data directory (never touch the
developer's own data):

```powershell
$sources = Get-ChildItem src -Recurse -Filter *.java | ForEach-Object FullName
New-Item -ItemType Directory -Force build-classes, test-classes | Out-Null
javac -encoding UTF-8 -d build-classes $sources
javac -encoding UTF-8 -cp build-classes -d test-classes (Get-ChildItem test -Filter *.java | ForEach-Object FullName)

$data = "$PWD\test-data"; New-Item -ItemType Directory -Force $data | Out-Null
java -Dcheatguard.data.dir="$data" -cp "build-classes;test-classes" CoreFlowTest
java -Dcheatguard.data.dir="$data" -cp "build-classes;test-classes" SecurityUpgradeTest
java -Dcheatguard.data.dir="$data" -cp "build-classes;test-classes" com.cheatguard.config.UpdateCheckerTest
java -Dcheatguard.data.dir="$data" -cp "build-classes;test-classes" CentralTlsTest
java -Dcheatguard.data.dir="$data" -cp "build-classes;test-classes" BackupRotationTest
```

- **Unit/protocol tests** (above, run in CI on every PR and push): core flow,
  credentials, vault encryption and tamper rejection, TLS transport
  (keystore generation, certificate rejection, HMAC failure, reconnect,
  plaintext rejection), backup/retention/rotation, updater verification.
- **Real-Windows integration tests** (installer install/uninstall, app
  startup, lockdown arm/restore, emergency restore) run ONLY on the
  dedicated disposable VM runner via
  [`.github/workflows/integration-vm.yml`](.github/workflows/integration-vm.yml);
  see [test/integration/README.md](test/integration/README.md). They never
  run implicitly and never fake a pass.

PowerShell syntax of every `.ps1` in the repository is validated with
`test\ps1-syntax-check.ps1` (also in CI).

## Repository layout

```text
src\com\cheatguard\       Application source
  config\                  Configuration and update handling
  core\                    Sessions, logs, and violations
  gui\                     Desktop UI and workflows
  security\                Credentials, vaults, backups, integrity controls
  watchdog\                Process, network, device enforcement, central link
resources\                 Elevated PowerShell helpers and resources
support\                   Recovery, diagnostics, TLS keystore generation
test\                      Headless verification tests (unit/protocol)
test\integration\          Real-Windows VM harness (see its README)
docs\                      TLS transport and backup/retention documentation
.github\workflows\         CI, release, and VM integration workflows
release-notes\             Notes shipped with each release
build-installer.bat        Installer build and checksum generation
```

## Operational workflow (invigilator)

1. Install `CheatGuardCentral-Setup.exe` with administrator privileges on
   the invigilator PC and every student PC.
2. Set the administrator password on first launch on each machine.
3. On the invigilator PC, open Central Monitor and press **Start monitor**.
   The app automatically detects the active LAN IP and provisions TLS on the
   first start. Copy the generated `central-monitor-truststore.p12` to every
   student PC when using the production TLS client setup.
4. Configure approved applications and exam websites (or load a saved exam
   profile).
5. Start the central monitor, share the displayed LAN IP and exam code, and
   start sessions on the students' PCs with the same code. Press **Stop**
   before using Back; Back is blocked while monitoring is active.
6. End each session ("End session and seal log"); the sealed vault is backed
   up automatically.

If a session ends unexpectedly, use the installed recovery utility or relaunch
the application as an administrator. Diagnostics are available through the
installed `diagnostics.bat` utility.

## Security boundaries

CheatGuard is designed to enforce policy against a signed-in standard student
account. It cannot protect against a person who has the local administrator
password, physical access to another device, or a communication path that
cannot be distinguished from an approved endpoint. The security model, its
guarantees, and vulnerability reporting are described in
[SECURITY.md](SECURITY.md). The development-only plaintext transport requires
an explicit opt-in and shows a visible warning; production defaults are TLS
only.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Released under the
[MIT license](LICENSE).

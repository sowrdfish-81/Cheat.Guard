# Cheat.Guard — v1.9.0 Project Report

## Scope

This report records the current implementation, security hardening,
verification status, and release process for Cheat.Guard v1.9.0. It
describes only what is in the repository now.

## Product summary

Cheat.Guard is a Windows Java desktop application for supervised
online exams. The application controls approved processes, restricts network
access to approved websites, monitors removable devices, limits access to
files outside the exam workspace, creates protected session records, and
streams audit events to the invigilator's central monitor over TLS.

## Implemented controls

### Session enforcement

- Starts with a clean process state and closes unauthorized applications.
- Monitors process identity using PID and process start time to avoid
  PID-reuse errors.
- Detects hidden or headless processes launched from student-writable
  locations.
- Enforces exam-folder boundaries for supported applications and
  interpreters.
- Records routine enforcement, blocked actions, and security alerts
  separately.

### Network enforcement

- Provides DNS-layer website allowlisting for IPv4 and IPv6 adapters.
- Disables browser DNS-over-HTTPS paths and blocks common bypass routes.
- Applies proxy/PAC restrictions during active sessions and restores the
  prior state.
- Blocks common VPN, tunnel, remote-control, RDP, VNC, QUIC, and IPsec ports.
- Uses an outbound web policy tied to addresses resolved through the
  approved filter.
- Refuses unsafe IPv6 configurations instead of silently filtering only
  IPv4.
- Falls back safely when full egress enforcement cannot be established and
  records the active mode.

### File and device controls

- Applies session-scoped NTFS restrictions outside the approved exam
  workspace.
- Restores file permissions when the session ends or is recovered.
- Monitors USB storage, portable devices, and network-adapter changes.
- Clears recent-file surfaces and clipboard history at session start.

### Security and integrity

- Stores sensitive state under `C:\ProgramData\CheatGuard` rather than the
  student profile.
- Uses PBKDF2-HMAC-SHA256 administrator credential protection with
  escalating lockout.
- Uses authenticated AES-256-GCM for new vaults; reads legacy CBC vaults and
  migrates them when they are sealed again.
- Uses ACL hardening for protected logs and control files.
- Sanitizes log input to prevent forged audit entries.
- Prevents student tampering with the elevated helper, allowlist, credential
  store, and stop marker.
- After every seal, the encrypted vault (+ signature) is backed up
  atomically to `C:\ProgramData\CheatGuard\vault-backup` with configurable
  retention (default newest 30 / 90 days). Plaintext logs are never backed
  up; the active vault is never a prune candidate; failures are logged, not
  fatal.

### Central monitor transport (new in 1.9.0)

- Student-to-monitor events travel over TLS 1.2/1.3 by default: PKCS12
  keystore on the monitor PC, PKCS12 truststore on student PCs, JSSE
  endpoint identification plus an explicit SAN check of the typed address.
- Certificate validation cannot be disabled anywhere in the codebase; a
  missing keystore/truststore fails closed with an actionable error message.
- The nonce-based HMAC challenge-response (exam-code proof) remains as a
  second layer on the encrypted channel.
- Plaintext TCP is a development-only opt-in
  (`-Dcheatguard.central.plaintext=true` or config `central.plaintext=true`)
  with a visible warning on both ends; production mode refuses it.
- Connect timeout 3 s, handshake timeout 15 s; stopping the reporter closes
  the socket cleanly after the final batch drains.
- Port (TCP 47821) and firewall rule unchanged.

### Recovery and operations

- Detects stale sessions and performs controlled recovery.
- Provides emergency network restoration and diagnostics utilities.
- Keeps UAC, sealing, log operations, and diagnostics off the UI thread.
- Clears dashboard password fields after sensitive operations.
- Diagnostic logs rotate by size (default 5 MiB per day file, 3 rolls) and
  age (14 days); audit vaults and diagnostics live in separate directories.

## Verification

### Headless suites (CI on every push/PR; Windows runner, JDK 17)

- `CoreFlowTest` — session, credential, vault, DNS, and scanner flow.
- `SecurityUpgradeTest` — AES-GCM integrity and central HMAC authentication.
- `UpdateCheckerTest` — updater URL, checksum, and release verification.
- `CentralTlsTest` (new) — real PKCS12 keystore/truststore generation,
  successful TLS + HMAC round trip, invalid-certificate rejection, HMAC
  failure rejection, reconnect, missing-keystore fail-closed, plaintext-mode
  rejection in production mode.
- `BackupRotationTest` (new) — backup creation and decryption integrity,
  plaintext refusal, duplicate-safe re-backup, retention by count and age,
  active-vault safety, interrupted-backup recovery, diagnostic log rotation.

### Build and packaging checks (CI)

- Full Java compilation (JDK 17, `--release 17`).
- PowerShell syntax validation of every tracked `.ps1`
  (`test/ps1-syntax-check.ps1`).
- `git diff --check`.
- Automatic WiX 3.14 download; `build-installer.bat` producing
  `dist\Cheat.Guard-Setup.exe` + `.sha256`; independent checksum
  verification; artifacts uploaded.

### Real-Windows integration tests

`.github/workflows/integration-vm.yml` (manual trigger) runs
`test/integration/` on a labeled disposable Windows VM runner: silent install
and uninstall, application startup, a real lockdown arm/restore cycle using
the shipped `network-lockdown.ps1`, and emergency restore. The workflow
refuses to run without the `CHEATGUARD_VM=1` marker and stays queued if no VM
runner exists — integration results can never be faked by CI alone.
**Status: implemented and documented; requires the maintainer to provision
the VM runner (see `test/integration/README.md`) before results exist.**

## Release process

- CI (`.github/workflows/ci.yml`) gates every pull request and push to
  `main`; `main` is branch-protected (PRs + 1 approval + required CI check
  + up-to-date branches; force-push and deletion denied; administrators
  included).
- Pushing a `v*` tag runs `.github/workflows/release.yml`: full test suite,
  WiX download, installer build, optional Authenticode signing (SHA-256
  digest, RFC 3161 timestamp, certificate decoded only inside the runner and
  deleted in a `finally` block; cleanly skipped and reported when the
  `WINDOWS_CERTIFICATE_BASE64` / `WINDOWS_CERTIFICATE_PASSWORD` secrets are
  absent), checksum regenerated AFTER signing and independently verified,
  and a GitHub release published with the installer, checksum, and
  `release-notes/<tag>.md`.

## Known boundaries

The client cannot reliably distinguish every HTTPS proxy or tunnel that
shares an approved CDN address. It cannot prevent screen capture,
photography, or activity performed using a separate device. A local
administrator can override client-side controls. These are deployment
limitations, not unreported test failures.

## Maintenance rules

- Keep installer filenames and checksum references synchronized across
  `README.md`, `build-installer.bat`, and release assets.
- Update the version in `UpdateChecker.java` and `build-installer.bat`
  together, and add `release-notes/<tag>.md` for every release.
- Run the isolated headless suites before every release; CI does this
  automatically and must be green.
- Publish the installer and its matching `.sha256` asset together (the
  release workflow enforces this).
- Do not commit WiX binaries, generated build directories, test data,
  release installers, certificates, or credentials.

# Contributing to Cheat.Guard

Thanks for helping improve exam integrity tooling. This repository follows a
few firm rules because the software enforces security during real exams.

## Ground rules

- **Never weaken the security model.** Certificate validation, HMAC
  authentication, sealed-vault encryption, lockdown restore paths and the
  admin password gates are not up for negotiation. If you think one is wrong,
  open an issue and explain the threat model first.
- **Never commit** build output, installers, WiX binaries, keystores,
  certificates, passwords, real exam logs or test data. All of these are
  covered by `.gitignore`.
- Keep changes focused: one bug fix or one feature per pull request.

## Getting started

Requirements: Windows 10+, JDK 17+, WiX Toolset 3.x (a copy under
`tools\wix\` works and is auto-detected by the build; do not commit it).

```bat
build-installer.bat
```

produces `dist\Cheat.Guard-Setup.exe` and its `.sha256`.

## Running the tests

Headless (no GUI, safe on any machine - always use a fresh data dir):

```bat
javac -encoding UTF-8 -d build-classes src\com\cheatguard\*.java src\com\cheatguard\**\*.java
javac -encoding UTF-8 -cp build-classes -d test-classes test\*.java
java -Dcheatguard.data.dir=%TEMP%\cg-test-1 -cp build-classes;test-classes CoreFlowTest
java -Dcheatguard.data.dir=%TEMP%\cg-test-2 -cp build-classes;test-classes SecurityUpgradeTest
java -Dcheatguard.data.dir=%TEMP%\cg-test-3 -cp build-classes;test-classes com.cheatguard.config.UpdateCheckerTest
java -Dcheatguard.data.dir=%TEMP%\cg-test-4 -cp build-classes;test-classes CentralTlsTest
java -Dcheatguard.data.dir=%TEMP%\cg-test-5 -cp build-classes;test-classes BackupRotationTest
```

Every suite must print `ALL CHECKS PASSED` / `PASS ...` and exit 0. CI
(`.github/workflows/ci.yml`) runs exactly these plus PowerShell syntax
validation, `git diff --check` and the installer build.

Real-Windows integration tests (installer, lockdown, emergency restore) run
only on the disposable VM runner - see `test/integration/README.md`. Do not
run them on your daily machine.

## Style

- Plain Java 17, no new dependencies. Match the existing file style: plain
  main-class tests with PASS/FAIL output, small focused classes, javadoc that
  explains WHY.
- GUI work must never block the Swing event-dispatch thread.
- PowerShell additions must pass `test\ps1-syntax-check.ps1`.

## Pull requests

1. Fork/branch from `main`; keep `main` protected (PRs + 1 approval + CI).
2. Fill in the PR template.
3. Make CI green before requesting review.
4. Report verification honestly: state exactly what you ran and what it
   printed. "Should work" is not verified.

## Reporting bugs

Use the bug report issue template. Include the app version (Settings →
About), Windows version, and the diagnostics file from
`support\diagnostics.bat` - but scrub anything exam-identifiable first.
Security issues go through `SECURITY.md`, never a public issue.

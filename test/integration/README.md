# Windows VM integration tests

These scripts exercise Cheat.Guard **on a real, disposable Windows
machine**: the actual installer, the actual installed application, the actual
network-lockdown helper and the actual emergency-restore tool. They are the
only place where installer-, ACL-, firewall- and DNS-level behavior is
verified end to end. The headless suites under `test/` (CI) are isolated
unit/protocol tests and are explicitly NOT a substitute for these.

## What runs where

| Suite | Where | What it proves |
|---|---|---|
| `test/CoreFlowTest.java`, `test/SecurityUpgradeTest.java`, `test/UpdateCheckerTest.java`, `test/CentralTlsTest.java`, `test/BackupRotationTest.java` | CI (`ci.yml`, windows-latest) + any dev machine | protocol, crypto, backup, rotation and TLS logic with an isolated data dir |
| `test/integration/*.ps1` | `integration-vm.yml` on the dedicated VM | silent install/uninstall, app startup, real lockdown arm/restore cycle, emergency restore on a real machine |

## Runner prerequisites

Provision ONE dedicated Windows 10/11 virtual machine (Hyper-V, VirtualBox or
a cloud VM) that can be **rolled back to a snapshot** after every run:

1. Install a GitHub Actions self-hosted runner on the VM.
2. Give it the exact labels `self-hosted`, `Windows`, `CheatGuard-VM`
   (set during `config.cmd`, or edit `.runner`).
3. Run the runner service under an account in the local **Administrators**
   group. The lockdown helper and installer require elevation; the runner
   account must be able to elevate without a click (built-in Administrator or
   UAC set to not prompt for that account).
4. Set an environment variable `CHEATGUARD_VM=1` for the runner service
   (System Properties → Environment Variables, then restart the runner). The
   workflow refuses to run lockdown tests without it, so a developer
   workstation can never be mistaken for the VM.
5. Java 17+ on the runner (or let `actions/setup-java` install it).
6. After each run, restore the VM snapshot. The tests uninstall the app and
   restore network settings, but the snapshot is the guarantee.

## Running manually on the VM

```powershell
# from a checkout of this repository on the VM
./test/integration/run-all.ps1 -RepoRoot . -InstallerPath dist/CheatGuardCentral-Setup.exe
```

`run-all.ps1` runs the phases in order and stops at the first failure:
prerequisites → silent install → app startup → network lockdown arm/restore →
emergency restore → silent uninstall. Output lands in `integration-output/`.

The GitHub workflow `.github/workflows/integration-vm.yml` runs the same
harness via *Run workflow*. If no VM runner is online the job stays queued -
it never fakes a pass.

## Safety notes

- Never point these scripts at a machine you care about: the lockdown phase
  genuinely changes DNS, firewall and proxy settings (and restores them).
- The scripts refuse to run when `CHEATGUARD_VM` is not `1`.
- No test data, installers or certificates produced by these runs are
  committed; `integration-output/` and `dist/` are git-ignored.

# Code ownership map

This file documents responsibility boundaries for review and maintenance.
Ownership comments are also placed at the top of source files and immediately
above shared implementation sections.

## Muhit — Security & Enforcement

Owns lockdown, file/folder walls, process enforcement, device restrictions,
session security, recovery, fail-safe and fail-closed behavior.

## Rohan — Detection, Policy & Network

Owns PC scanning, allowed/blocked policy decisions, DNS website filtering,
central networking, pairing, TLS transport and event processing.

## Rafa — Product/UI & Quality

Owns UI/UX, central-monitor presentation, installer/updater experience,
documentation, release presentation and regression testing.

## Shared files

For shared files, the owner comment immediately above a section is the source
of truth. Cross-owner changes require review from the other listed owners.

## File-by-file ownership

| Area | Owner | Responsibility |
|---|---|---|
| `security/` | Muhit | encryption, credentials, ACL walls, vaults, recovery |
| `watchdog/Process*` | Rohan | process discovery and policy input |
| `watchdog/Dns*`, `Site*` | Rohan | website filtering and blocked-site events |
| `StrictNetworkLockdown.java` | Muhit | firewall, DNS and file-wall enforcement |
| `watchdog/Central*` | Rohan | pairing, TLS and event transport |
| `core/` | Muhit + Rohan | session security and event data |
| `gui/` | Rafa | screens, controls and presentation |
| `config/UpdateChecker.java` | Rafa | updater and installer verification |
| `test/` | Rafa | regression coverage and reporting |
| `resources/`, `support/` | Muhit | elevated helpers and recovery |
| `README.md`, `docs/`, `.github/` | Rafa | documentation and release automation |

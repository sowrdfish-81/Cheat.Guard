# Central monitor TLS transport

Every event a student PC sends to the invigilator's central monitor now
travels over **TLS 1.2/1.3 by default**. The existing HMAC challenge-response
(`CentralAuth`, the exam-code proof) stays as a second layer on top of the
encrypted channel. Plaintext TCP is a development-only opt-in, never a
fallback.

## How the two layers work

1. **TLS** - the student PC validates the monitor's certificate against a
   truststore before ANY exam data leaves the machine; the address typed on
   the session card must appear in the certificate's SANs. No trust-all
   managers, no disabled validation anywhere in the codebase.
2. **HMAC** - after TLS, the monitor issues a random nonce and the client
   answers with an HMAC-SHA256 keyed by the exam code (`HELLO`/`AUTH`
   exchange). Wrong code or missing challenge = connection rejected.

Port and firewall stay exactly as before: **TCP 47821** in both modes, the
same `Cheat.Guard Monitor` firewall rule.

## Automatic setup (recommended)

The current installer automatically detects the invigilator PC's active LAN
IPv4 addresses and creates the TLS keystore/truststore when **Start monitor**
is pressed for the first time. No manual certificate generation or password
entry is required. If an interrupted first setup left an unmanaged keystore,
the app preserves it as an orphaned backup and provisions a fresh managed
identity.

## Network changes and certificate rotation

When the monitor starts it compares the certificate's SANs against the
machine's current student-facing LAN addresses. If the network changed
(hotspot, new room, new subnet) and any current address is no longer covered,
the certificate is regenerated automatically - the old identity is preserved
as an orphaned backup. Student PCs re-pair on their own through the beacon
(see below).

## Finding the invigilator PC (UDP beacon)

While the monitor runs it broadcasts a `CHEATGUARD-CENTRAL@@@<port>@@@<sha256>`
beacon on UDP 47822 every two seconds. A student PC that leaves the
**Invigilator PC IP** field empty auto-detects the monitor from the beacon and
connects back to the address the packet actually came from, so hotspot/DHCP
address changes no longer break the join. A manually typed IP always wins; the
beacon is still received for its fingerprint.

## Automatic pairing (trust on first use)

The beacon carries the SHA-256 fingerprint of the monitor certificate. A
student PC that has no truststore yet (or whose stored certificate was just
rejected because the monitor rotated it) captures the certificate the monitor
presents, accepts it ONLY when its SHA-256 matches the beacon fingerprint,
pins it into the local truststore and reconnects with full validation. No
file has to be copied to student PCs.

What this means for security: passive eavesdroppers on the exam LAN learn
nothing, and every connection still requires the HMAC exam-code proof. An
ACTIVE attacker inside the exam LAN could broadcast a fake beacon and present
their own certificate to a student's FIRST join - the same trust level as
walking into the exam room. Environments that need stronger guarantees can
pre-provision a custom truststore with the manual keystore helper below.

## Manual keystore generation (optional)

Run the shipped helper as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File support\generate-central-tls.ps1 -LanIp 192.168.0.10
```

It creates:

- `%ProgramData%\CheatGuard\config\central-monitor-keystore.p12` - the
  monitor's private key + certificate. **Stays on the invigilator PC.**
- `%ProgramData%\CheatGuard\config\central-monitor-truststore.p12` - contains
  only the certificate. With automatic pairing this file normally stays on the
  invigilator PC; student PCs pin the certificate themselves from the beacon.

The certificate covers the LAN IP you pass (`-LanIp`), `localhost`, and any
extra names via `-ExtraDnsNames`. If the invigilator's IP changes
(regenerated certificate needed), students see a clear
"certificate does not cover 'x.x.x.x'" error instead of a silent failure.

## Configuring passwords (never plaintext in files you share)

The keystore/truststore password is resolved in this order and never logged:

1. system property `cheatguard.central.tls.storepass`
2. environment variable `CHEATGUARD_CENTRAL_TLS_STOREPASS`
3. the app's own config value `central.tls.storepass`
   (`%ProgramData%\CheatGuard\config\whitelist.properties` - Administrators
   only)

A truststore of public certificates needs no password; empty is accepted
there but not for the keystore.

## Other config keys

| Key (in `whitelist.properties`, `cfg.` prefix internally) | Meaning |
|---|---|
| `central.tls.keystore` | absolute keystore path (default: `central-monitor-keystore.p12` in the config dir) |
| `central.tls.truststore` | absolute truststore path (default: `central-monitor-truststore.p12` in the config dir) |
| `central.tls.storepass` | store password (see order above) |
| `central.plaintext` | `true` enables development-only plaintext; see below |

## Development-only plaintext mode

For local debugging you MAY run both ends in plaintext:

```
java -Dcheatguard.central.plaintext=true -jar CheatGuardCentral.jar
```

or set the config value `central.plaintext=true`. Both sides then:

- require this explicit opt-in (production default is TLS, and TLS setup
  fails closed - no keystore means "monitor cannot start", not "fall back to
  plaintext"),
- print a visible warning (`WARNING: central monitor link is PLAINTEXT...`)
  in the monitor status line and the application log.

The workflow tests assert that production mode refuses both plaintext client
sockets and plaintext server sockets, and that an untrusted certificate and a
wrong exam code are rejected.

## What happens on failure

- Missing/unreadable keystore on the monitor: "Could not start" with the
  exact path and a pointer to this document. No fallback.
- Missing truststore on a student PC: the reporter keeps the events queued
  locally and retries - nothing is sent in the clear while retrying.
- Handshake/certificate/name failures: connection refused, queued events
  preserved, retry with backoff.
- Timeouts: 3 s connect, 15 s handshake; closing the app unblocks and closes
  the socket cleanly (SESSION_END still drains first).

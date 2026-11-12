package com.cheatguard.watchdog;

import com.cheatguard.config.AppPaths;
import com.cheatguard.core.AppLog;
import com.cheatguard.core.LogManager;
import com.cheatguard.core.Violation;
import com.cheatguard.security.LogProtection;

import java.io.*;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Starts website lockdown: the local {@link DnsAllowlistServer} plus the elevated
 * helper that points the machine's DNS at it and forces browser DNS-over-HTTPS off.
 *
 * <p>Enforcement is at name resolution. An earlier design also forced browsers
 * through a local HTTP proxy under a firewall outbound default-deny; that reliably
 * blocked unapproved sites but broke approved ones whenever a browser did not
 * honour the injected proxy setting, leaving the student with no working Internet.
 * Filtering DNS instead keeps approved sites on their normal, direct network path.
 */
public final class StrictNetworkLockdown implements Closeable {
    private final LogManager logManager;
    private final ViolationListener listener;
    private DnsAllowlistServer dnsServer;
    private final File networkDir = AppPaths.getNetworkDirectory();
    private final File helper = new File(networkDir, "network-lockdown.ps1");
    private final File config = new File(networkDir, "active-config.json");
    private final File ready = new File(networkDir, "ready.marker");
    private final File stop = new File(networkDir, "stop.marker");
    private final File restored = new File(networkDir, "restored.marker");
    private final File error = new File(networkDir, "error.txt");
    private final File state = new File(networkDir, "firewall_state.json");
    private final File allowedIps = new File(networkDir, "allowed-ips.txt");
    private final File egressStatus = new File(networkDir, "egress-status.txt");
    private final File lockPathsFile = new File(networkDir, "lock-paths.txt");
    private final File lockStatusFile = new File(networkDir, "lock-status.txt");
    /** Invigilator central monitor passthrough: IPs allowed on TCP 47821. */
    private final File centralIpFile = new File(networkDir, "central-ip.txt");
    private final int centralPort = 47821;
    /** The student's exam folder - the ONLY folder that stays readable. */
    private volatile File examFolder;
    private volatile boolean active;
    private volatile String lastError = "";

    public StrictNetworkLockdown(LogManager logManager, ViolationListener listener) {
        this.logManager = logManager;
        this.listener = listener;
    }

    /** Give the lockdown the student's exam folder - the only readable folder. */
    public void setExamFolder(File folder) {
        if (folder != null && folder.isDirectory()) this.examFolder = folder;
    }

    public boolean start() {
        lastError = "";
        if (!isWindows()) {
            lastError = "Strict network mode requires Windows.";
            return false;
        }
        try {
            copyHelper();
            cleanupMarkers();
            startDnsServer();
            String sid = currentUserSid();
            String program = currentProgramPath();
            if (sid.isEmpty()) throw new IOException("Could not identify the signed-in Windows user SID.");
            if (program.isEmpty()) throw new IOException("Could not identify the Cheat.Guard executable path.");
            seedAllowedIps();
            writeLockPaths();
            writeConfig(sid, program);
            launchElevated(false);
            // 5 minutes: the elevated helper arms DNS, firewall and file walls; a
            // bounded file-wall deny on a cloud-synced folder (OneDrive, Google
            // Drive) can legitimately take over a minute per folder while NTFS
            // propagates the ACE through thousands of placeholder children.
            long end = System.currentTimeMillis() + 300000L;
            while (System.currentTimeMillis() < end) {
                if (ready.exists()) {
                    active = true;
                    emitInfo("STRICT_NETWORK_LOCK_ENABLED", "Website allowlist active: only admin-approved domains can be reached during this exam.");
                    emitEgressStatus();
                    emitLockStatus();
                    return true;
                }
                if (error.exists()) throw new IOException(readQuietly(error));
                Thread.sleep(250L);
            }
            throw new IOException("Administrator approval timed out or the elevated network helper did not start."
                    + " Its step-by-step log is at " + new File(networkDir, "helper-log.txt").getAbsolutePath() + ".");
        } catch (Exception e) {
            lastError = friendlyError(e);
            rollbackPartialStart();
            return false;
        }
    }

    /**
     * Undo everything a helper may already have applied when the start never
     * completed: without this, a helper that armed DNS redirection (or locks)
     * but did not reach its READY marker - a slow machine, a late UAC approval,
     * a stalled verification - would leave the computer with a dead resolver
     * (127.0.0.1 with no filter behind it) and no Internet after a "failed"
     * start. Writing the stop marker makes the helper tear itself down and
     * restore every original setting; it is harmless when the helper never ran.
     */
    private void rollbackPartialStart() {
        active = false;
        try {
            Files.writeString(stop.toPath(), "STOP", StandardCharsets.US_ASCII);
            long end = System.currentTimeMillis() + 30000L;
            while (System.currentTimeMillis() < end) {
                if (restored.exists() || !state.exists()) break;
                if (error.exists()) break;
                Thread.sleep(200L);
            }
        } catch (Exception ignored) {
        } finally {
            closeServers();
        }
    }

    /**
     * Bind the local DNS filter. Failure is fatal to starting the exam: without
     * it the elevated helper would still redirect every adapter to 127.0.0.1,
     * which would break all name resolution instead of filtering it.
     *
     * <p>The machine's current resolvers are captured first so approved domains
     * keep resolving through the network the exam is actually running on (a campus
     * resolver, an ISP resolver) instead of hard-coded public addresses that a
     * restrictive network may refuse to answer.
     */
    private void startDnsServer() throws IOException {
        dnsServer = new DnsAllowlistServer(logManager, listener, detectSystemUpstreams(), allowedIps);
        try {
            dnsServer.start();
        } catch (IOException e) {
            dnsServer = null;
            throw new IOException("Could not start the local DNS filter on 127.0.0.1:"
                    + DnsAllowlistServer.DNS_PORT + " - " + e.getMessage()
                    + ". Another DNS service (Internet Connection Sharing, a local"
                    + " resolver such as Acrylic/Pi-hole, or an older Cheat.Guard"
                    + " session) is using that port. Stop it and start the exam again.", e);
        }
        // If real IPv6 resolvers are configured but ::1 could not be bound, the
        // helper must leave IPv6 DNS untouched and Windows - which prefers IPv6
        // resolvers - would route lookups around the filter silently. Starting an
        // exam in that state would be theatre, so refuse loudly instead.
        Boolean ipv6Configured = ipv6DnsServersPresent();
        if (!dnsServer.isIpv6Bound() && !Boolean.FALSE.equals(ipv6Configured)) {
            closeServers();
            throw new IOException("This computer has IPv6 DNS servers configured, but the"
                    + " local DNS filter could not bind the IPv6 loopback (::1:"
                    + DnsAllowlistServer.DNS_PORT + "). Website blocking could be bypassed"
                    + " through IPv6, so the session was not started. Restart the computer"
                    + " and try again; if it persists, disable IPv6 on the network adapter"
                    + " or close the program that is using the port.");
        }
    }

    /**
     * True when an adapter holds a routable IPv6 resolver (global, ULA or
     * link-local). The site-local fec0:0:0:ffff::x entries Windows reports when no
     * IPv6 DNS was ever configured are placeholder metadata, not real resolvers, and
     * are ignored.
     */
    private Boolean ipv6DnsServersPresent() {
        try {
            String script = "$ErrorActionPreference='SilentlyContinue';"
                    + "Get-DnsClientServerAddress -AddressFamily IPv6 | ForEach-Object { $_.ServerAddresses }";
            Process p = PowerShellUtil.start(script);
            if (!p.waitFor(8, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return null;
            }
            if (p.exitValue() != 0) return null;
            boolean present = false;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String v = line.trim().toLowerCase(java.util.Locale.ROOT);
                    if (v.isEmpty()) continue;
                    if (v.equals("::1")) continue;
                    if (v.startsWith("fec0:")) continue;
                    if (v.contains(":")) present = true;
                }
            }
            return present;
        } catch (Exception ignored) {
            // Unknown must fail closed: IPv4-only filtering is not sufficient proof.
            return null;
        }
    }

    /**
     * The IPv4 resolvers in use right now, excluding loopback addresses this
     * application binds. Best effort: on any failure an empty list is returned and
     * the DNS server falls back to public resolvers.
     */
    private List<String> detectSystemUpstreams() {
        Set<String> found = new LinkedHashSet<>();
        try {
            String script = "$ErrorActionPreference='SilentlyContinue';"
                    + "Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { $_.ServerAddresses }";
            Process p = PowerShellUtil.start(script);
            // Wait BEFORE reading: readLine blocks to EOF, so reading first would
            // make the 8-second timeout unreachable if the probe ever hangs.
            // Output is a handful of IP lines and cannot fill the pipe buffer.
            if (!p.waitFor(8, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return new ArrayList<>(found);
            }
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String v = line.trim();
                    if (v.isEmpty()) continue;
                    if (v.equals("127.0.0.1") || v.equals("::1") || v.contains(":")) continue;
                    if (!v.matches("\\d{1,3}(\\.\\d{1,3}){3}")) continue;
                    found.add(v);
                    if (found.size() >= 4) break;
                }
            }
        } catch (Exception ignored) {
            // fall back to public resolvers
        }
        return new ArrayList<>(found);
    }

    private void closeServers() {
        if (dnsServer != null) dnsServer.close();
        dnsServer = null;
    }

    public String getLastError() {
        String s = lastError == null ? "" : lastError.trim();
        if (s.length() > 1800) s = s.substring(0, 1800) + "...";
        return s;
    }

    public File getErrorFile() { return error; }

    public boolean stopAndRestore() {
        if (!isWindows()) return true;
        // Kill the helper watchdog FIRST so a normal shutdown can never be mistaken
        // for a dead helper and trigger a spurious relaunch.
        active = false;
        try {
            // A restored.marker left over from a PREVIOUS session would satisfy
            // waitForRestore immediately and report success while this machine is
            // still locked down. Clear the old confirmations before asking for a
            // fresh one.
            restored.delete();
            error.delete();
            Files.writeString(stop.toPath(), "STOP", StandardCharsets.US_ASCII);
            // A verified restore sweeps every drive root and profile folder with
            // icacls and retries DNS - it can legitimately take over a minute on a
            // slow machine, so wait long enough before considering a fallback.
            if (waitForRestore(60000L)) {
                closeServers();
                return true;
            }
            // The helper did not confirm a restore (it was killed by a power cut, a
            // crash or a task kill, or it hit an error). Do not leave the machine with
            // a dead resolver and locked drives: relaunch it in recover-only mode, which
            // restores everything the session changed and needs one UAC approval.
            try {
                copyHelper();
                restored.delete();
                error.delete();
                launchElevatedStatic(helper, config, true);
                boolean ok = waitForRestore(75000L);
                closeServers();
                return ok;
            } catch (Exception recovery) {
                closeServers();
                return restored.exists() || !state.exists();
            }
        } catch (Exception e) {
            closeServers();
            return false;
        }
    }

    /** Poll until the helper confirms restoration, the state file is gone, or it errors. */
    private boolean waitForRestore(long timeoutMs) throws InterruptedException {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            if (restored.exists() || !state.exists()) return true;
            // error.txt is terminal - the helper only writes it right before exiting.
            if (error.exists()) return false;
            Thread.sleep(200L);
        }
        return restored.exists() || !state.exists();
    }

    public static boolean recoverStaleIfPresent() {
        if (!isWindowsStatic()) return true;
        File dir = AppPaths.getNetworkDirectory();
        File state = new File(dir, "firewall_state.json");
        File cfg = new File(dir, "active-config.json");
        File helper = new File(dir, "network-lockdown.ps1");
        if (!state.exists() || !cfg.exists()) return true;
        try {
            // Always use the helper bundled with this version for stale-session recovery.
            try (InputStream in = StrictNetworkLockdown.class.getResourceAsStream("/network-lockdown.ps1")) {
                if (in == null) return false;
                Files.copy(in, helper.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            File restored = new File(dir, "restored.marker");
            File error = new File(dir, "error.txt");
            restored.delete(); error.delete();
            launchElevatedStatic(helper, cfg, true);
            long end = System.currentTimeMillis() + 60000L;
            while (System.currentTimeMillis() < end) {
                if (restored.exists() || !state.exists()) return true;
                if (error.exists()) return false;
                Thread.sleep(250L);
            }
        } catch (Exception ignored) {}
        return false;
    }

    private void emitInfo(String type, String detail) {
        Violation v = new Violation(type, detail, Violation.Severity.INFO);
        logManager.record(v);
        if (listener != null) listener.onViolation(v);
    }

    /**
     * Registers the permanent OS fail-safe (SYSTEM task, every 3 minutes + at
     * logon) while the app STARTS, so the net exists before the first session is
     * ever armed. The task idles in under a second whenever there is no lockdown
     * state to recover, and it is refreshed on every session start.
     */
    public static void ensureFailSafeRegistered() {
        Thread t = new Thread(() -> {
            // The task registration must happen even when the helper copy below
            // fails: a surviving old helper is far better than no fail-safe net.
            boolean copyOk = false;
            String copyDetail = "unchanged";
            try {
                File dir = AppPaths.getNetworkDirectory();
                File helper = new File(dir, "network-lockdown.ps1");
                byte[] bundled;
                try (InputStream in = StrictNetworkLockdown.class.getResourceAsStream("/network-lockdown.ps1")) {
                    if (in == null) { AppLog.warn("Fail-safe helper resource missing"); }
                    else {
                        bundled = in.readAllBytes();
                        boolean identical = false;
                        try {
                            identical = Files.size(helper.toPath()) == bundled.length
                                    && Arrays.equals(bundled, Files.readAllBytes(helper.toPath()));
                        } catch (Exception ignored) {
                        }
                        if (!identical) {
                            // REPLACE_EXISTING has failed with a bare-path access
                            // error on hardened/locked dirs; write a sibling temp
                            // file and move over it instead.
                            File staged = new File(dir, "network-lockdown.ps1.new");
                            try {
                                Files.write(staged.toPath(), bundled);
                                try {
                                    Files.move(staged.toPath(), helper.toPath(),
                                            java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                                } catch (Exception atomicUnsupported) {
                                    Files.move(staged.toPath(), helper.toPath(),
                                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                                }
                                copyOk = true;
                                copyDetail = "updated";
                            } catch (Exception copyEx) {
                                try { Files.deleteIfExists(staged.toPath()); } catch (Exception ignored) {}
                                copyDetail = copyEx.getClass().getSimpleName() + ": " + copyEx.getMessage();
                            }
                        } else {
                            copyOk = true;
                        }
                    }
                }
            } catch (Exception copyEx) {
                copyDetail = copyEx.getClass().getSimpleName() + ": " + copyEx.getMessage();
            }

            try {
                String script = "$d = $env:ProgramData + '/CheatGuard/network'; "
                        + "$ps = $env:SystemRoot + '/System32/WindowsPowerShell/v1.0/powershell.exe'; "
                        + "$s = $d + '/network-lockdown.ps1'; "
                        + "if (-not (Test-Path $s)) { exit 1 }; "
                        + "$action = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ''' + $s + ''' -FailSafeCheck'); "
                        + "$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) "
                        + "-RepetitionInterval (New-TimeSpan -Minutes 3) -RepetitionDuration (New-TimeSpan -Days 3650); "
                        + "$logon = New-ScheduledTaskTrigger -AtLogOn; "
                        + "$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
                        + "-StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15); "
                        + "Register-ScheduledTask -TaskName 'CheatGuard SessionFailSafe' -Action $action "
                        + "-Trigger @($trigger, $logon) -Settings $settings -User 'SYSTEM' -RunLevel Highest "
                        + "-Force -ErrorAction Stop | Out-Null; "
                        + "if ($?) { exit 0 } else { exit 2 }";
                Process p = PowerShellUtil.start(script);
                int code = p.waitFor(60, TimeUnit.SECONDS) ? p.exitValue() : -1;
                if (code == 0) {
                    AppLog.info("Fail-safe task ensured at app start (helper " + copyDetail + ")");
                } else {
                    AppLog.warn("Fail-safe task registration failed (exit " + code
                            + ", helper " + copyDetail + ")");
                }
            } catch (Exception e) {
                AppLog.warn("Fail-safe task registration failed: "
                        + e.getClass().getSimpleName() + ": " + e.getMessage()
                        + " (helper " + copyDetail + ")");
            }
        }, "CheatGuard-FailSafeReg");
        t.setDaemon(true);
        t.start();
    }

    private void copyHelper() throws IOException {
        byte[] bundled;
        try (InputStream in = StrictNetworkLockdown.class.getResourceAsStream("/network-lockdown.ps1")) {
            if (in == null) throw new FileNotFoundException("network-lockdown.ps1 resource missing");
            bundled = in.readAllBytes();
        }
        try {
            Files.write(helper.toPath(), bundled);
        } catch (Exception replaceFailed) {
            // REPLACE_EXISTING can fail on a locked/hardened file even when the
            // app is elevated. An OUTDATED helper still runs a correct session;
            // a missing one does not exist at all. Only fail when there is no
            // file to fall back to.
            if (!helper.isFile()) throw new IOException(
                    "Could not stage the network helper: " + replaceFailed, replaceFailed);
            AppLog.warn("Helper update skipped, using existing copy: "
                    + replaceFailed.getClass().getSimpleName());
        }
    }

    private void cleanupMarkers() {
        ready.delete(); stop.delete(); restored.delete(); error.delete();
        new File(networkDir, "helper-log.txt").delete(); // log reflects only the newest attempt
        LogProtection.requestFile().delete();
        LogProtection.doneFile().delete();
    }

    private void writeConfig(String sid, String program) throws IOException {
        boolean dnsIpv6 = dnsServer != null && dnsServer.isIpv6Bound();
        String verifyHost = firstAllowedSite();
        String json = "{\n" +
                "\"parentPid\":" + currentPid() + ",\n" +
                "\"parentName\":\"" + jsonEscape(parentName()) + "\",\n" +
                "\"dnsPort\":" + DnsAllowlistServer.DNS_PORT + ",\n" +
                "\"dnsIpv6\":" + dnsIpv6 + ",\n" +
                "\"userSid\":\"" + jsonEscape(sid) + "\",\n" +
                "\"programPath\":\"" + jsonEscape(program) + "\",\n" +
                "\"vaultDir\":\"" + jsonEscape(AppPaths.getVaultDirectory().getAbsolutePath()) + "\",\n" +
                "\"allowedIpFile\":\"" + jsonEscape(allowedIps.getAbsolutePath()) + "\",\n" +
                "\"egressStatusFile\":\"" + jsonEscape(egressStatus.getAbsolutePath()) + "\",\n" +
                "\"verifyHost\":\"" + jsonEscape(verifyHost) + "\",\n" +
                "\"centralIpFile\":\"" + jsonEscape(centralIpFile.getAbsolutePath()) + "\",\n" +
                "\"centralPort\":" + 47821 + ",\n" +
                "\"lockPathsFile\":\"" + jsonEscape(lockPathsFile.getAbsolutePath()) + "\",\n" +
                "\"lockStatusFile\":\"" + jsonEscape(lockStatusFile.getAbsolutePath()) + "\",\n" +
                "\"userSidForLocks\":\"" + jsonEscape(sid) + "\",\n" +
                "\"stateFile\":\"" + jsonEscape(state.getAbsolutePath()) + "\",\n" +
                "\"readyFile\":\"" + jsonEscape(ready.getAbsolutePath()) + "\",\n" +
                "\"stopFile\":\"" + jsonEscape(stop.getAbsolutePath()) + "\",\n" +
                "\"restoredFile\":\"" + jsonEscape(restored.getAbsolutePath()) + "\",\n" +
                "\"protectRequestFile\":\"" + jsonEscape(LogProtection.requestFile().getAbsolutePath()) + "\",\n" +
                "\"protectDoneFile\":\"" + jsonEscape(LogProtection.doneFile().getAbsolutePath()) + "\",\n" +
                "\"errorFile\":\"" + jsonEscape(error.getAbsolutePath()) + "\"\n}";
        Files.writeString(config.toPath(), json, StandardCharsets.UTF_8);
    }

    /** A judge domain the helper's egress lockdown verifies against before arming. */
    private String firstAllowedSite() {
        for (String s : com.cheatguard.config.AppConfig.getInstance().getAllowedSites()) return s;
        return "";
    }

    /**
     * Resolve the first allowed domains up front and write their addresses, so the
     * helper's egress allowlist is populated before it switches the firewall to
     * default-deny (an empty list would verify-fail on every network).
     */
    private void seedAllowedIps() {
        List<String> seeds = new ArrayList<>();
        int sites = 0;
        for (String site : com.cheatguard.config.AppConfig.getInstance().getAllowedSites()) {
            if (++sites > 6 || seeds.size() >= 32) break;
            try {
                for (java.net.InetAddress a : java.net.InetAddress.getAllByName(site)) {
                    if (seeds.size() < 32) seeds.add(a.getHostAddress());
                }
            } catch (Exception ignored) {
                // offline or unreachable: the DNS server records addresses as they are answered
            }
        }
        try {
            Files.writeString(allowedIps.toPath(), String.join("\n", seeds) + "\n", StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
    }

    /** Report whether the egress firewall layer armed, or fell back to DNS-only. */
    private void emitEgressStatus() {
        String status = "";
        try {
            if (egressStatus.isFile()) {
                status = Files.readString(egressStatus.toPath(), StandardCharsets.UTF_8).trim();
            }
        } catch (Exception ignored) {
        }
        if ("ACTIVE".equalsIgnoreCase(status)) {
            emitInfo("EGRESS_FIREWALL_ENABLED",
                    "Egress firewall active: web traffic is restricted to the servers of approved websites.");
        } else {
            emitInfo("EGRESS_FIREWALL_FALLBACK",
                    "Egress firewall could not be verified on this network; DNS-level website blocking is active.");
        }
    }

    /** Report whether the student's file-access locks applied. */
    private void emitLockStatus() {
        String status = "";
        try {
            if (lockStatusFile.isFile()) {
                status = Files.readString(lockStatusFile.toPath(), StandardCharsets.UTF_8).trim();
            }
        } catch (Exception ignored) {
        }
        if ("ACTIVE".equalsIgnoreCase(status)) {
            emitInfo("FILE_LOCK_ENABLED",
                    "File walls up: the student's account cannot open files outside the exam folder "
                            + "(Documents, Downloads, other drives, USB).");
        } else {
            emitInfo("FILE_LOCK_SKIPPED",
                    "Pre-exam file blocking could not be applied; process and folder alerts stay active.");
        }
    }

    /**
     * Build the list of folders the student's account is locked out of for the
     * exam: the profile's content folders, everything on the Desktop except the
     * exam folder and shortcuts, and every drive that holds neither Windows, the
     * profile, ProgramData nor an approved app.
     */
    private List<String> buildLockPaths() {
        File profile = com.cheatguard.config.AppPaths.getUserProfileDirectory();
        File desktop = com.cheatguard.config.AppPaths.getDesktopDirectory();
        Set<String> keepDrives = new java.util.HashSet<>();
        addDriveOf(keepDrives, new File(System.getenv("SystemRoot") == null ? "C:\\" : System.getenv("SystemRoot")));
        addDriveOf(keepDrives, profile);
        addDriveOf(keepDrives, examFolder);
        addDriveOf(keepDrives, com.cheatguard.config.AppPaths.getDataDirectory());
        for (String allowed : com.cheatguard.config.AppConfig.getInstance().getAllowedProcesses()) {
            addDriveOf(keepDrives, new File(com.cheatguard.config.AppConfig.getInstance()
                    .getProcessPath(allowed) == null ? "C:\\" : com.cheatguard.config.AppConfig
                    .getInstance().getProcessPath(allowed)));
        }
        List<File> extraRoots = new ArrayList<>();
        for (File root : File.listRoots()) {
            if (!keepDrives.contains(root.getAbsolutePath().toLowerCase(java.util.Locale.ROOT))) {
                extraRoots.add(root);
            }
        }
        return collectLockPaths(profile, desktop, examFolder, extraRoots);
    }

    /** Drives that must stay untouched: add the drive letter of the given path. */
    private static void addDriveOf(Set<String> keep, File f) {
        if (f == null) return;
        String p = f.getAbsolutePath().toLowerCase(java.util.Locale.ROOT);
        if (p.length() >= 3 && p.charAt(1) == ':') keep.add(p.substring(0, 3));
    }

    /**
     * Pure path collection (testable): profile content folders, desktop children
     * except the exam folder and shortcuts, plus the given extra drive roots.
     *
     * Ancestor safety: a folder that CONTAINS the exam folder (for example OneDrive
     * when the Desktop is OneDrive-redirected) is never locked wholesale - denying
     * it would inherit down onto the exam folder itself. Its OTHER children are
     * locked instead, so only the exam chain stays open.
     */
    public static List<String> collectLockPaths(File profile, File desktop, File examFolder,
                                                List<File> extraRoots) {
        List<String> out = new ArrayList<>();
        if (profile != null && profile.isDirectory()) {
            for (String name : new String[]{"Documents", "Downloads", "Music", "Pictures",
                    "Videos", "Saved Games", "Contacts", "Links", "OneDrive", "3D Objects",
                    "Searches"}) {
                File f = new File(profile, name);
                if (!f.isDirectory()) continue;
                // Avoid one recursive ACL operation on a large profile root.
                // Lock its children instead so icacls does not time out on a
                // cloud/large Documents tree while the contents remain denied.
                lockChildrenExceptExam(f, examFolder, out, 0);
            }
        }
        if (desktop != null && desktop.isDirectory()) {
            lockChildrenExceptExam(desktop, examFolder, out, 0);
        }
        if (extraRoots != null) {
            for (File root : extraRoots) {
                if (!root.exists()) continue;
                if (isAncestorOrSelf(root, examFolder)) {
                    lockChildrenExceptExam(root, examFolder, out, 0);
                } else {
                    out.add(root.getAbsolutePath());
                }
            }
        }
        // A redirected Desktop/OneDrive tree can contribute the same path through
        // multiple roots. Deduplicate before handing paths to icacls; each ACL call
        // is expensive and duplicate calls were the main source of slow startup/end.
        return new ArrayList<>(new LinkedHashSet<>(out));
    }

    /** Deny a folder's children, but leave the chain to the exam folder open. */
    private static void lockChildrenExceptExam(File folder, File examFolder,
                                               List<String> out, int depth) {
        if (folder == null || !folder.isDirectory() || depth > 4) return;
        File[] kids = folder.listFiles();
        if (kids == null) return;
        for (File kid : kids) {
            if (examFolder != null && sameTarget(kid, examFolder)) continue; // the exam folder itself
            if (examFolder != null && isAncestor(kid, examFolder)) {         // on the exam chain
                lockChildrenExceptExam(kid, examFolder, out, depth + 1);
                continue;
            }
            if (kid.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".lnk")) continue;
            out.add(kid.getAbsolutePath());
        }
    }

    private static boolean isAncestorOrSelf(File dir, File examFolder) {
        return sameTarget(dir, examFolder) || isAncestor(dir, examFolder);
    }

    /** True when the exam folder lives INSIDE the given folder (strictly below it). */
    private static boolean isAncestor(File dir, File examFolder) {
        if (dir == null || examFolder == null) return false;
        String d;
        String e;
        try {
            d = dir.getCanonicalPath();
            e = examFolder.getCanonicalPath();
        } catch (Exception ex) {
            d = dir.getAbsolutePath();
            e = examFolder.getAbsolutePath();
        }
        d = d.toLowerCase(java.util.Locale.ROOT);
        e = e.toLowerCase(java.util.Locale.ROOT);
        if (!d.endsWith("\\")) d = d + "\\";
        return e.startsWith(d);
    }

    private static boolean sameTarget(File a, File b) {
        try {
            return a.getCanonicalPath().equalsIgnoreCase(b.getCanonicalPath());
        } catch (Exception e) {
            return a.getAbsolutePath().equalsIgnoreCase(b.getAbsolutePath());
        }
    }

    /** Write the lock list so the elevated helper can apply the denies. */
    private void writeLockPaths() {
        List<String> paths = buildLockPaths();
        try {
            Files.writeString(lockPathsFile.toPath(), String.join("\n", paths) + "\n",
                    StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
    }

    private void launchElevated(boolean recoverOnly) throws IOException {
        launchElevatedStatic(helper, config, recoverOnly);
    }

    /**
     * Uses PowerShell's native RunAs verb instead of Windows Script Host/VBScript.
     * This works on machines where Windows Script Host is disabled by policy.
     */
    private static void launchElevatedStatic(File helper, File config, boolean recoverOnly) throws IOException {
        File launchLog = new File(config.getParentFile(), "helper-launch.log");
        try { Files.writeString(launchLog.toPath(), "Launching elevated helper at " + java.time.Instant.now() + System.lineSeparator(), StandardCharsets.UTF_8); }
        catch (Exception ignored) { }
        String helperPath = psSingleQuote(helper.getAbsolutePath());
        String configPath = psSingleQuote(config.getAbsolutePath());
        String workDir = psSingleQuote(helper.getParentFile().getAbsolutePath());
        String recoverArg = recoverOnly ? ", '-RecoverOnly'" : "";
        // IMPORTANT: no -Wait here. network-lockdown.ps1 writes ready.marker almost
        // immediately, then intentionally keeps running (it loops until stop.marker
        // appears) for the whole exam session. If we -Wait on it, this call would
        // block for the entire exam and the caller's ready.marker/error.txt polling
        // loop would never get a chance to run, eventually timing out even though
        // the helper actually started fine - leaving the firewall/proxy lockdown
        // active with nothing to signal success. UAC-decline is still surfaced
        // synchronously by Start-Process -Verb RunAs even without -Wait, so we don't
        // lose that error path.
        // Pass a literal argument array to Start-Process.  Passing a variable
        // containing an array through the nested PowerShell command is subtly
        // lossy on some Windows PowerShell builds: the elevated process is
        // created, but -File/-Config are collapsed and the script exits before
        // its own diagnostics can be written.
        String command = "$ErrorActionPreference='Stop'; " +
                "$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs " +
                "-WorkingDirectory '" + workDir + "' -WindowStyle Hidden " +
                "-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','" + helperPath +
                "','-Config','" + configPath + "'" + recoverArg + ") -PassThru; " +
                "if($null -eq $p){ throw 'Could not start elevated network helper.' }";

        // Hidden: this relay waits only until the UAC prompt is answered, and the
        // elevated helper runs hidden for the whole session - a visible console
        // here used to sit on screen ("instead of the app, a PowerShell opened").
        Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden", "-Command", command)
                .redirectErrorStream(true).start();
        boolean done;
        try {
            // Start-Process blocks here only until the UAC prompt is answered (the
            // elevated helper itself runs detached). A non-technical user often
            // needs well over 20 seconds to read and approve the prompt, so wait
            // as long as the helper-start window itself; a start that still times
            // out is rolled back by the caller either way.
            done = p.waitFor(90, TimeUnit.SECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for Administrator/UAC approval.", ie);
        }
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        if (!done) {
            p.destroyForcibly();
            throw new IOException("Administrator/UAC approval timed out.");
        }
        if (p.exitValue() != 0) {
            File helperError = new File(config.getParentFile(), "error.txt");
            String detail = "";
            try { if (helperError.isFile()) detail = Files.readString(helperError.toPath(), StandardCharsets.UTF_8).trim(); }
            catch (Exception ignored) {}
            if (detail.isEmpty()) detail = out;
            if (detail.isEmpty()) detail = "The elevated network helper did not launch (UAC declined or blocked). Check error.txt and Windows Event Viewer.";
            throw new IOException(detail);
        }
        try { Files.writeString(launchLog.toPath(), "Elevated helper accepted by Windows at " + java.time.Instant.now() + System.lineSeparator(), StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND); }
        catch (Exception ignored) { }
        // Launch succeeded; actual readiness/failure of network-lockdown.ps1 itself
        // is now reported via ready.marker / error.txt, which start() already polls.
    }

    private String currentUserSid() throws IOException, InterruptedException {
        Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
                .redirectErrorStream(true).start();
        // This runs on the session-starter thread: sessionBusy is only cleared
        // after it returns, so an unbounded wait would wedge every future
        // session action until the app is killed. Output is one SID line.
        if (!p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("Could not read the current user's SID in time.");
        }
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    }

    /**
     * Path granted unrestricted outbound access by the firewall helper.
     *
     * <p>Prefers the packaged launcher reported by jpackage. Falling back to
     * {@link ProcessHandle} would return the JDK's {@code java.exe} when the app
     * is started with {@code java -jar}, which would hand full Internet access to
     * every Java program on the machine for the duration of the exam.
     */
    private String currentProgramPath() {
        String packaged = System.getProperty("jpackage.app-path", "");
        if (!packaged.isBlank() && new File(packaged).isFile()) return packaged;
        try { return ProcessHandle.current().info().command().orElse(""); }
        catch (Exception e) { return ""; }
    }

    /** This process's executable name; the helper verifies it against parentPid so
     *  a reused PID can never keep a dead session's lockdown alive. PowerShell's
     *  ProcessName carries no .exe extension, so strip it before sending. */
    private String parentName() {
        try {
            String cmd = ProcessHandle.current().info().command().orElse("");
            if (!cmd.isBlank()) return new File(cmd).getName().replaceAll("(?i)\\.exe$", "");
        } catch (Exception ignored) {
        }
        return "CheatGuard";
    }

    private long currentPid() {
        try { return ProcessHandle.current().pid(); }
        catch (Exception e) {
            try { return Long.parseLong(ManagementFactory.getRuntimeMXBean().getName().split("@")[0]); }
            catch (Exception ignored) { return -1L; }
        }
    }

    private String readQuietly(File f) {
        try {
            String value = Files.readString(f.toPath(), StandardCharsets.UTF_8).trim();
            if (!value.isEmpty()) return value;
        } catch (Exception ignored) {
        }
        File stepLog = new File(networkDir, "helper-log.txt");
        try {
            String value = Files.readString(stepLog.toPath(), StandardCharsets.UTF_8).trim();
            if (!value.isEmpty()) return value.substring(Math.max(0, value.length() - 1800));
        } catch (Exception ignored) {
        }
        return "The elevated helper stopped before it reported a reason. See " + stepLog.getAbsolutePath() + ".";
    }

    private String friendlyError(Exception e) {
        String m = e.getMessage();
        if (m == null || m.trim().isEmpty()) m = e.toString();
        m = m.replace("\r", "").trim();
        return m;
    }

    private String jsonEscape(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }
    private static String psSingleQuote(String s) { return s.replace("'", "''"); }
    private boolean isWindows() { return isWindowsStatic(); }
    private static boolean isWindowsStatic() { return System.getProperty("os.name", "").toLowerCase().contains("win"); }

    public boolean isActive() { return active; }
    @Override public void close() { stopAndRestore(); }
}

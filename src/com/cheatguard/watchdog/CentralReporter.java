package com.cheatguard.watchdog;

import com.cheatguard.core.AppLog;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;
import com.cheatguard.config.AppPaths;

import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/**
 * Streams this student's audit events to the invigilator's central monitor over
 * the exam LAN.
 *
 * <p>The student types the invigilator's IP and the exam code he shared (an
 * empty IP field is filled in automatically from the monitor's UDP beacon).
 * This client keeps a TLS connection (plaintext TCP only in explicit
 * development mode) to that IP on port 47821 and forwards every violation,
 * plus the session start and end, as one text line. The invigilator's
 * certificate is validated before any byte of exam data leaves the machine -
 * the beacon's fingerprint drives automatic certificate pairing - and the
 * HMAC challenge-response then proves the exam code on the encrypted channel.
 * When the monitor is unreachable the events queue (bounded) and are flushed
 * on reconnect - nothing here can ever block or break the exam itself, and
 * each distinct failure reason is surfaced once on the live screen instead of
 * failing silently.
 *
 * <p>Mice and keyboards never appear in the feed (they are not device-monitored);
 * everything the watchdog flags locally is what the invigilator sees.
 */
public final class CentralReporter {

    public static final int CENTRAL_TCP_PORT = 47821;
    public static final int DISCOVERY_UDP_PORT = 47822;
    public static final String BEACON_PREFIX = "CHEATGUARD-CENTRAL@@@";
    private static final int MAX_QUEUED = 1000;
    /** How long to wait for a beacon before the UI hints at manual entry. */
    private static final long DISCOVERY_HINT_AFTER_MS = 15000;

    private final ExamSession session;
    private final String hostPc;
    private final ArrayDeque<String> queue = new ArrayDeque<>();
    private volatile String centralHost = "";
    /** The invigilator's IP, typed on the setup card. */
    private final String manualHost;
    /** The exam code sir shared; the monitor rejects connections with other codes. */
    private final String examCode;
    private volatile boolean running;
    private volatile boolean stopping;
    private volatile Socket activeSocket;
    private volatile java.net.DatagramSocket discoverySocket;
    /** Latest certificate fingerprint advertised by each monitor's beacon (bounded). */
    private final java.util.Map<String, String> beaconFingerprints =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** Optional live sink so the student's screen shows WHY the invigilator is blind. */
    private volatile java.util.function.Consumer<Violation> statusConsumer;
    private String lastReportedReason = "";
    private boolean waitingHintShown;
    private boolean connectedOnce;
    private Thread worker;

    public CentralReporter(ExamSession session) {
        this(session, "", "");
    }

    public CentralReporter(ExamSession session, String manualHost, String examCode) {
        this.session = session;
        this.manualHost = manualHost == null ? "" : manualHost.trim();
        this.examCode = examCode == null ? "" : examCode.trim();
        if (!this.manualHost.isEmpty()) {
            centralHost = this.manualHost;
        }
        // Always (re)write the IP file: a stale file from a PREVIOUS session would
        // make the lockdown helper's outbound rule trust the old invigilator PC.
        persistCentralIp(this.manualHost);
        String pc = "PC";
        try {
            pc = InetAddress.getLocalHost().getHostName().trim();
        } catch (Exception ignored) {
        }
        this.hostPc = pc.isEmpty() ? "PC" : pc;
    }

    /** Start the sender loop. Best effort, never throws. */
    public void start() {
        if (running) return;
        stopping = false;
        running = true;
        worker = new Thread(this::sendLoop, "CheatGuard-CentralSender");
        worker.setDaemon(true);
        worker.start();
        // The beacon carries the monitor's certificate fingerprint for automatic
        // pairing, so it is listened for even when the IP was typed manually.
        startDiscovery();
        // Some Wi-Fi APs drop all broadcast traffic even between clients on the
        // same subnet.  TCP probing is a bounded fallback for that case: it only
        // checks private /24 LAN ranges and only accepts a host with the monitor
        // listener open; TLS and exam-code authentication still happen below.
        startTcpDiscovery();
        // announce the session itself
        report(new Violation("SESSION_START",
                "Course=" + session.getCourseCode() + " | StudentID=" + session.getStudentId()
                        + " | PC=" + hostPc + " | ExamFolder=" + session.getExamFolder().getAbsolutePath(),
                Violation.Severity.INFO));
    }

    /** Optional sink for live connection diagnostics; the student UI shows these. */
    public void setStatusConsumer(java.util.function.Consumer<Violation> sink) {
        this.statusConsumer = sink;
    }

    public void stop() {
        if (!running) return;
        report(new Violation("SESSION_END",
                "Course=" + session.getCourseCode() + " | StudentID=" + session.getStudentId()
                        + " | PC=" + hostPc,
                Violation.Severity.INFO));
        stopping = true;
        running = false;
        if (worker != null) worker.interrupt();
        // A thread blocked in readLine() waiting for the challenge never notices
        // the interrupt (plain sockets have no read timeout), so close the
        // connection out from under it to unblock the loop.
        Socket live = activeSocket;
        if (live != null) {
            try {
                live.close();
            } catch (Exception ignored) {
            }
        }
        java.net.DatagramSocket ds = discoverySocket;
        if (ds != null) {
            try {
                ds.close();
            } catch (Exception ignored) {
            }
        }
    }

    /** Queue one violation for the invigilator; drops the oldest when overflowing. */
    public void report(Violation v) {
        if (!running || v == null) return;
        String line = System.currentTimeMillis()
                + "@@@" + sanitize(hostPc)
                + "@@@" + sanitize(session.getStudentId())
                + "@@@" + sanitize(session.getCourseCode())
                + "@@@" + v.getSeverity().name()
                + "@@@" + sanitize(v.getType())
                + "@@@" + sanitize(v.getDescription())
                + "@@@" + sanitize(LogDisplayHelper.display(v));
        synchronized (queue) {
            while (queue.size() >= MAX_QUEUED) queue.pollFirst();
            queue.addLast(line);
        }
    }

    /** Tell the firewall helper which IP to let through on TCP 47821. */
    private static void persistCentralIp(String addr) {
        try {
            java.nio.file.Files.write(
                    new File(AppPaths.getNetworkDirectory(), "central-ip.txt").toPath(),
                    addr.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {
        }
    }

    private static String sanitize(String s) {
        return s == null ? "" : s.replace("@@@", " @ ").replace("\n", " ").replace("\r", " ");
    }

    /**
     * Listen for the invigilator's UDP discovery beacon. A manually typed IP
     * always wins (the beacon only fills in a missing one); the fingerprint the
     * beacon advertises is remembered per monitor address either way, because
     * the automatic certificate pairing verifies against it. The first valid
     * beacon's source address is by definition an address this PC can reach -
     * exactly what a hotspot setup needs, where the invigilator's IP changes
     * with every new network.
     */
    private void startDiscovery() {
        Thread t = new Thread(() -> {
            try (java.net.DatagramSocket socket = new java.net.DatagramSocket(null)) {
                socket.setReuseAddress(true);
                socket.bind(new InetSocketAddress(DISCOVERY_UDP_PORT));
                discoverySocket = socket;
                byte[] buf = new byte[256];
                while (running) {
                    java.net.DatagramPacket packet = new java.net.DatagramPacket(buf, buf.length);
                    try {
                        socket.receive(packet);
                    } catch (Exception e) {
                        if (!running) break;
                        continue;
                    }
                    String payload = new String(packet.getData(), packet.getOffset(),
                            packet.getLength(), StandardCharsets.UTF_8).trim();
                    if (!payload.startsWith(BEACON_PREFIX)) continue;
                    String rest = payload.substring(BEACON_PREFIX.length()).trim();
                    // rest: "<port>" (older monitors) or "<port>@@@<sha256>"
                    String fingerprint = "";
                    int sep = rest.indexOf("@@@");
                    if (sep >= 0) {
                        fingerprint = rest.substring(sep + 3).trim()
                                .toLowerCase(java.util.Locale.ROOT);
                        rest = rest.substring(0, sep).trim();
                    }
                    String from = packet.getAddress().getHostAddress();
                    if (from == null || from.isEmpty()) continue;
                    if (fingerprint.matches("[0-9a-f]{64}")
                            && (beaconFingerprints.containsKey(from)
                            || beaconFingerprints.size() < 32)) {
                        beaconFingerprints.put(from, fingerprint);
                    }
                    if (centralHost.isEmpty()) {
                        centralHost = from;
                        persistCentralIp(from);
                        emitStatus("CENTRAL_MONITOR_DISCOVERED",
                                "Invigilator monitor found at " + from + " (network beacon); connecting...");
                    }
                }
            } catch (Exception ignored) {
                // discovery is optional; the manual IP field still works
            } finally {
                discoverySocket = null;
            }
        }, "CheatGuard-CentralDiscovery");
        t.setDaemon(true);
        t.start();
    }

    private void startTcpDiscovery() {
        Thread t = new Thread(() -> {
            try {
                java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors
                        .newFixedThreadPool(24);
                java.util.List<java.util.concurrent.Future<?>> jobs = new java.util.ArrayList<>();
                java.util.Enumeration<java.net.NetworkInterface> interfaces =
                        java.net.NetworkInterface.getNetworkInterfaces();
                while (interfaces.hasMoreElements()) {
                    java.net.NetworkInterface ni = interfaces.nextElement();
                    if (!ni.isUp() || ni.isLoopback()) continue;
                    java.util.Enumeration<java.net.InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        java.net.InetAddress a = addresses.nextElement();
                        if (!(a instanceof java.net.Inet4Address) || !a.isSiteLocalAddress()) continue;
                        String ip = a.getHostAddress();
                        int dot = ip.lastIndexOf('.');
                        if (dot <= 0) continue;
                        String prefix = ip.substring(0, dot) + ".";
                        for (int host = 1; host <= 254; host++) {
                            final String candidate = prefix + host;
                            if (candidate.equals(ip)) continue;
                            jobs.add(pool.submit(() -> {
                                if (!running || !centralHost.isEmpty()) return;
                                try (java.net.Socket probe = new java.net.Socket()) {
                                    probe.connect(new java.net.InetSocketAddress(candidate, CENTRAL_TCP_PORT), 180);
                                    if (centralHost.isEmpty()) {
                                        String fingerprint = com.cheatguard.watchdog.CentralTls
                                                .pairMonitorOverTcp(candidate, CENTRAL_TCP_PORT);
                                        beaconFingerprints.put(candidate, fingerprint);
                                        centralHost = candidate;
                                        persistCentralIp(candidate);
                                        emitStatus("CENTRAL_MONITOR_DISCOVERED",
                                                "Invigilator monitor found at " + candidate + " (LAN probe); connecting...");
                                    }
                                } catch (Exception ignored) {}
                            }));
                        }
                    }
                }
                for (java.util.concurrent.Future<?> job : jobs) {
                    if (!running || !centralHost.isEmpty()) break;
                    try { job.get(500, java.util.concurrent.TimeUnit.MILLISECONDS); }
                    catch (Exception ignored) {}
                }
                pool.shutdownNow();
            } catch (Exception ignored) {
                // UDP discovery and manual IP remain available if probing fails.
            }
        }, "CheatGuard-CentralTcpDiscovery");
        t.setDaemon(true);
        t.start();
    }

    /** One diagnostic row into the sealed log AND onto the live student screen. */
    private void emitStatus(String type, String message) {
        Violation v = new Violation(type, message, Violation.Severity.INFO);
        try {
            session.getLogManager().record(v);
        } catch (Exception ignored) {
        }
        java.util.function.Consumer<Violation> sink = statusConsumer;
        if (sink != null) {
            try {
                sink.accept(v);
            } catch (Exception ignored) {
            }
        }
    }

    /** A concrete, actionable one-line reason the invigilator is not receiving. */
    private static String failureReason(String host, Exception e) {
        String message = e.getMessage() == null ? "" : e.getMessage();
        if (message.contains("beacon has been heard")) {
            return "No invigilator monitor has been found on this network yet - start the "
                    + "monitor on the invigilator PC first; it announces itself for automatic "
                    + "pairing (or type its IP and the exam code on the setup card).";
        }
        if (message.contains("does not match its beacon")) {
            return "The monitor's certificate does not match what it advertised - the "
                    + "invigilator should restart the monitor, then this PC joins again.";
        }
        if (message.contains("does not cover")) {
            return "The invigilator's certificate does not cover " + host + " - the invigilator "
                    + "should restart the monitor on this network (it re-issues the "
                    + "certificate automatically).";
        }
        if (message.contains("challenge")) {
            return "Reached the invigilator's monitor but the link was rejected - check the exam code.";
        }
        return "Could not reach the invigilator's monitor at " + host + ":" + CENTRAL_TCP_PORT
                + " (" + e.getClass().getSimpleName() + ") - alerts stay on this PC until it reconnects.";
    }

    /** Connect/reconnect to the central monitor and drain the queue. */
    private void sendLoop() {
        List<String> batch = new ArrayList<>();
        long startedAt = System.currentTimeMillis();
        while (running || stopping) {
            String host = centralHost;
            if (host.isEmpty()) {
                // No manual IP and no beacon yet: wait for discovery instead of
                // exiting - a session started before the monitor must still join it.
                if (stopping) break;
                if (!waitingHintShown
                        && System.currentTimeMillis() - startedAt > DISCOVERY_HINT_AFTER_MS) {
                    waitingHintShown = true;
                    emitStatus("CENTRAL_MONITOR_UNREACHABLE",
                            "No invigilator monitor has been found on this network yet "
                                    + "(auto-detect is listening). Type the invigilator's IP and "
                                    + "exam code on the setup card if it stays silent.");
                }
                sleepQuiet(500);
                continue;
            }
            try (Socket socket = CentralTls.openClientSocket(host, CENTRAL_TCP_PORT,
                    beaconFingerprints.get(host))) {
                activeSocket = socket;
                // In TLS mode openClientSocket already connected and handshaken;
                // connecting again throws SocketException("already connected").
                if (!socket.isConnected()) {
                    socket.connect(new InetSocketAddress(host, CENTRAL_TCP_PORT), 3000);
                    if (socket instanceof javax.net.ssl.SSLSocket ssl) ssl.startHandshake();
                }
                OutputStream out = socket.getOutputStream();
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                String challenge = in.readLine();
                if (challenge == null || !challenge.startsWith("CHALLENGE@@@")) {
                    throw new java.io.IOException("Central monitor did not issue a challenge");
                }
                String nonce = challenge.substring("CHALLENGE@@@".length()).trim();
                String hello = "HELLO@@@" + sanitize(hostPc) + "@@@" + sanitize(session.getStudentId())
                        + "@@@" + sanitize(session.getCourseCode());
                String auth = "AUTH@@@" + CentralAuth.response(examCode, nonce, hostPc,
                        session.getStudentId(), session.getCourseCode());
                out.write((hello + "\n" + auth + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
                // Read the monitor's verdict. Without it a WRONG exam code looked
                // exactly like a dead monitor: the client reconnected every 2 s
                // forever while silently discarding up to 50 queued events per
                // cycle. A legacy (pre-1.9.18) monitor sends no verdict and its
                // 15 s read timeout is treated as a silent OK.
                String ack;
                try {
                    ack = in.readLine();
                } catch (java.net.SocketTimeoutException legacyMonitor) {
                    ack = "OK";
                }
                if (ack == null) {
                    throw new java.io.IOException("Central monitor rejected the connection (wrong exam code?)");
                }
                if (ack.startsWith("DENIED")) {
                    com.cheatguard.core.AppLog.warn(
                            "Central monitor rejected the exam code; central reporting is disabled for this session.");
                    return;
                }
                if (!connectedOnce) {
                    connectedOnce = true;
                    emitStatus("CENTRAL_MONITOR_CONNECTED",
                            "Connected to the invigilator's monitor at " + host
                                    + ":" + CENTRAL_TCP_PORT + ". Alerts are streaming to the invigilator.");
                }
                while (running || hasQueuedEvents()) {
                    synchronized (queue) {
                        batch.clear();
                        while (!queue.isEmpty() && batch.size() < 50) batch.addLast(queue.pollFirst());
                    }
                    for (String line : batch) {
                        out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
                    }
                    if (!batch.isEmpty()) out.flush();
                    if (batch.isEmpty()) sleepQuiet(700);
                }
                out.flush();
                stopping = false;
                lastReportedReason = ""; // a later failure should report again
            } catch (Exception e) {
                // monitor down or lockdown blocking: retry after a pause
                // Put a polled-but-unsent batch back at the HEAD of the queue, or a
                // mid-batch write failure would silently drop up to 50 events.
                if (!batch.isEmpty()) {
                    synchronized (queue) {
                        for (int i = batch.size() - 1; i >= 0; i--) queue.addFirst(batch.get(i));
                    }
                    batch.clear();
                }
                if (stopping) break;
                // A wrong IP, a stale certificate or a blocked port otherwise looks
                // like a working session: say exactly what is wrong, once per
                // distinct reason, in the sealed log and on the live screen.
                String reason = failureReason(host, e);
                if (!reason.equals(lastReportedReason)) {
                    lastReportedReason = reason;
                    emitStatus("CENTRAL_MONITOR_UNREACHABLE", reason);
                }
                sleepQuiet(2000);
            }
        }
        stopping = false;
    }

    private boolean hasQueuedEvents() {
        synchronized (queue) {
            return !queue.isEmpty();
        }
    }

    private static void sleepQuiet(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    /** Tiny formatter so the reporter does not depend on the Swing gui package. */
    private static final class LogDisplayHelper {
        static String display(Violation v) {
            return v.getType() + ": " + v.getDescription();
        }
    }
}

package com.cheatguard.watchdog;

import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.AppLog;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * TLS transport for the central monitor link (invigilator server + student
 * clients), layered UNDER the existing HMAC challenge-response: TLS encrypts
 * and authenticates the channel, CentralAuth still proves the exam code.
 *
 * <p>Production mode (the default) only ever speaks TLS 1.2/1.3 with real
 * certificate validation — no trust-all managers, no disabled checks. The
 * invigilator PC presents a certificate from a PKCS12 keystore; student PCs
 * verify it against a PKCS12 truststore that contains exactly that
 * certificate, and the name/IP they typed must appear in the certificate's
 * Subject Alternative Names. Plaintext TCP remains available ONLY as an
 * explicit development opt-in ({@code -Dcheatguard.central.plaintext=true} or
 * config {@code central.plaintext=true}) and every side then shows a warning.
 *
 * <p>Keystore password sources (first wins; never logged): the system property
 * {@code cheatguard.central.tls.storepass}, the environment variable
 * {@code CHEATGUARD_CENTRAL_TLS_STOREPASS}, or the admin-owned config value
 * {@code central.tls.storepass}. See docs/CENTRAL_TLS.md for generation.
 */
public final class CentralTls {

    public static final String KEYSTORE_CONFIG = "central.tls.keystore";
    public static final String TRUSTSTORE_CONFIG = "central.tls.truststore";
    public static final String STOREPASS_CONFIG = "central.tls.storepass";
    public static final String PLAINTEXT_CONFIG = "central.plaintext";
    public static final String STOREPASS_SYSTEM_PROPERTY = "cheatguard.central.tls.storepass";
    public static final String STOREPASS_ENVIRONMENT = "CHEATGUARD_CENTRAL_TLS_STOREPASS";
    public static final String PLAINTEXT_SYSTEM_PROPERTY = "cheatguard.central.plaintext";
    private static final String DEFAULT_TRUSTSTORE_PASSWORD = "changeit";

    static final int CONNECT_TIMEOUT_MS = 3000;
    static final int HANDSHAKE_TIMEOUT_MS = 15000;

    private static final String[] TLS_PROTOCOLS = {"TLSv1.2", "TLSv1.3"};

    private CentralTls() {
    }

    // ------------------------------------------------------------- mode ----

    /**
     * True only when plaintext TCP was explicitly opted in for development.
     * Production default is false: TLS is mandatory on both ends.
     */
    public static boolean plaintextDevModeEnabled() {
        String flag = System.getProperty(PLAINTEXT_SYSTEM_PROPERTY, "");
        if (flag.isBlank()) flag = AppConfig.getInstance().getConfigValue(PLAINTEXT_CONFIG) == null
                ? "" : AppConfig.getInstance().getConfigValue(PLAINTEXT_CONFIG);
        return "true".equalsIgnoreCase(flag.trim());
    }

    public static String plaintextWarning() {
        return "WARNING: central monitor link is PLAINTEXT (development mode). "
                + "Enable TLS for real exams - see docs/CENTRAL_TLS.md.";
    }

    // --------------------------------------------------------- locations ----

    public static File defaultKeystoreFile() {
        return new File(AppPaths.getConfigDirectory(), "central-monitor-keystore.p12");
    }

    public static File defaultTruststoreFile() {
        return new File(AppPaths.getConfigDirectory(), "central-monitor-truststore.p12");
    }

    /** Keystore path from config, or the default location. */
    public static File configuredKeystoreFile() {
        String path = AppConfig.getInstance().getConfigValue(KEYSTORE_CONFIG);
        if (path != null && !path.isBlank()) return new File(path.trim());
        return defaultKeystoreFile();
    }

    /** Truststore path from config, or the default location. */
    public static File configuredTruststoreFile() {
        String path = AppConfig.getInstance().getConfigValue(TRUSTSTORE_CONFIG);
        if (path != null && !path.isBlank()) return new File(path.trim());
        return defaultTruststoreFile();
    }

    /** Create the invigilator TLS material on first monitor start. */
    public static synchronized void ensureServerSetup() throws IOException {
        File existingKey = configuredKeystoreFile();
        if (existingKey.isFile()) {
            if (hasConfiguredStorePassword()) return;
            // A previous auto-provision attempt may have created the keystore
            // before persisting its password. Preserve it for recovery, then
            // create a fresh managed identity instead of blocking monitor start.
            if (!existingKey.equals(defaultKeystoreFile())) return;
            String suffix = ".orphaned-" + System.currentTimeMillis();
            Files.move(existingKey.toPath(), new File(existingKey + suffix).toPath());
            File oldTrust = configuredTruststoreFile();
            if (oldTrust.isFile() && oldTrust.equals(defaultTruststoreFile())) {
                Files.move(oldTrust.toPath(), new File(oldTrust + suffix).toPath());
            }
        }
        File dir = configuredKeystoreFile().getParentFile();
        if (dir == null) throw new IOException("Central TLS config directory is unavailable");
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("Could not create " + dir);
        String password = randomPassword();
        String san = "SAN=dns:localhost,ip:127.0.0.1";
        try {
            java.util.Enumeration<java.net.NetworkInterface> interfaces =
                    java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                java.net.NetworkInterface ni = interfaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                java.util.Enumeration<java.net.InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    java.net.InetAddress address = addresses.nextElement();
                    if (address instanceof java.net.Inet4Address) san += ",ip:" + address.getHostAddress();
                }
            }
            File key = configuredKeystoreFile();
            File trust = configuredTruststoreFile();
            String keytool = new File(System.getProperty("java.home"), "bin/keytool.exe").getAbsolutePath();
            if (!new File(keytool).isFile()) keytool = new File(System.getProperty("java.home"), "bin/keytool").getAbsolutePath();
            // jpackage's trimmed runtime normally omits keytool; use the system
            // JDK tool when the installed runtime does not contain it.
            if (!new File(keytool).isFile()) keytool = "keytool";
            runKeytool(keytool, "-genkeypair", "-alias", "central", "-keyalg", "RSA", "-keysize", "2048",
                    "-validity", "3650", "-dname", "CN=CheatGuard Central Monitor", "-ext", san,
                    "-keystore", key.getAbsolutePath(), "-storetype", "PKCS12", "-storepass", password, "-keypass", password);
            File cert = File.createTempFile("cheatguard-central-", ".cer", dir);
            try {
                runKeytool(keytool, "-exportcert", "-alias", "central", "-rfc", "-keystore", key.getAbsolutePath(), "-storepass", password, "-file", cert.getAbsolutePath());
                // The truststore holds only a PUBLIC certificate, so its password
                // adds no security: create it with the hard-coded default that
                // every client can fall back to. Student PCs receive just the
                // truststore (no config password), so a managed password here
                // would make the truststore unreadable everywhere but this PC.
                runKeytool(keytool, "-importcert", "-alias", "central", "-file", cert.getAbsolutePath(), "-keystore", trust.getAbsolutePath(), "-storetype", "PKCS12", "-storepass", DEFAULT_TRUSTSTORE_PASSWORD, "-noprompt");
            } finally { Files.deleteIfExists(cert.toPath()); }
            AppConfig.getInstance().setConfigValue(STOREPASS_CONFIG, password);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("TLS setup was interrupted", e);
        }
    }

    private static String randomPassword() {
        byte[] bytes = new byte[18]; new SecureRandom().nextBytes(bytes);
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) out.append(String.format("%02x", b));
        return out.toString();
    }

    private static boolean hasConfiguredStorePassword() {
        String value = System.getProperty(STOREPASS_SYSTEM_PROPERTY, "");
        if (value.isBlank()) value = System.getenv(STOREPASS_ENVIRONMENT);
        if (value == null || value.isBlank()) {
            value = AppConfig.getInstance().getConfigValue(STOREPASS_CONFIG);
        }
        return value != null && !value.isBlank();
    }

    private static void runKeytool(String keytool, String... args) throws IOException, InterruptedException {
        java.util.ArrayList<String> command = new java.util.ArrayList<>(); command.add(keytool);
        java.util.Collections.addAll(command, args);
        Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        if (p.waitFor() != 0) throw new IOException("TLS certificate setup failed: " + output.trim());
    }

    // ----------------------------------------------------------- server ----

    /**
     * A bound TLS server socket on {@code port} (port 0 = ephemeral, used by
     * tests). Throws with an actionable message when the keystore is missing
     * or unreadable — the monitor must not fall back to plaintext.
     */
    public static SSLServerSocket newServerSocket(int port) throws IOException {
        if (plaintextDevModeEnabled()) {
            throw new IllegalStateException(
                    "TLS was requested but plaintext development mode is enabled");
        }
        ensureServerSetup();
        File keystoreFile = configuredKeystoreFile();
        if (!keystoreFile.isFile()) {
            throw new IOException("Central monitor keystore not found: " + keystoreFile
                    + ". Generate one with support/generate-central-tls.ps1"
                    + " (see docs/CENTRAL_TLS.md).");
        }
        char[] password = storePassword(true);
        try {
            KeyStore keyStore = loadKeyStore(keystoreFile, password);
            if (keyStore.size() == 0) {
                throw new IOException("Central monitor keystore is empty: " + keystoreFile);
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, password);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(kmf.getKeyManagers(), null, null);
            SSLServerSocket socket = (SSLServerSocket)
                    ((SSLServerSocketFactory) context.getServerSocketFactory())
                            .createServerSocket();
            socket.setReuseAddress(true);
            socket.setEnabledProtocols(enabledProtocols(socket.getSupportedProtocols()));
            socket.setNeedClientAuth(false); // students authenticate via the HMAC layer
            socket.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), port), 50);
            return socket;
        } catch (IOException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Central monitor TLS setup failed: " + e.getMessage(), e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** Opens the configured monitor listener, or the explicit development transport. */
    public static ServerSocket openServerSocket(int port) throws IOException {
        if (plaintextDevModeEnabled()) {
            ServerSocket socket = new ServerSocket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(InetAddress.getByName("0.0.0.0"), port), 50);
            return socket;
        }
        return newServerSocket(port);
    }

    // ----------------------------------------------------------- client ----

    /**
     * A connected, handshaken TLS client socket to the monitor at
     * {@code host}:{@code port}, validated against the configured truststore.
     */
    public static SSLSocket newClientSocket(String host, int port) throws IOException {
        return newClientSocket(host, port, "");
    }

    /**
     * A connected, handshaken TLS client socket to the monitor at
     * {@code host}:{@code port}. The certificate must chain to the configured
     * truststore and contain {@code host} (name or IP) in its SANs.
     *
     * <p>Automatic pairing: when no truststore exists yet (or a rotated monitor
     * certificate was just rejected) and the monitor's own beacon advertised a
     * certificate fingerprint, the presented certificate is pinned after
     * matching that fingerprint and the connection is re-established with full
     * validation. Without a beacon fingerprint the failure stays a failure -
     * never a silent downgrade.
     */
    public static SSLSocket newClientSocket(String host, int port,
                                            String expectedFingerprint) throws IOException {
        if (plaintextDevModeEnabled()) {
            throw new IllegalStateException(
                    "TLS was requested but plaintext development mode is enabled");
        }
        String wanted = expectedFingerprint == null
                ? "" : expectedFingerprint.trim().toLowerCase(java.util.Locale.ROOT);
        File truststoreFile = configuredTruststoreFile();
        if (truststoreFile.isFile()) {
            try {
                return tlsConnect(host, port, loadTruststoreLeniently(truststoreFile));
            } catch (IOException trustedFailure) {
                // A rotated monitor certificate is rejected here; when the beacon
                // advertises the new fingerprint the student re-pairs below. Any
                // non-certificate failure (unreachable, timeout) surfaces as-is.
                String message = trustedFailure.getMessage() == null ? "" : trustedFailure.getMessage();
                boolean certificateProblem = message.contains("PKIX")
                        || message.contains("certification path")
                        || message.contains("certificate");
                if (wanted.isEmpty() || !certificateProblem) throw trustedFailure;
            }
        } else if (wanted.isEmpty()) {
            throw new IOException("No invigilator monitor beacon has been heard on this network "
                    + "yet and no truststore is installed - start the monitor first; it "
                    + "announces its certificate every two seconds for automatic pairing.");
        }
        // First contact (or a rotated certificate): pin the presented certificate
        // ONLY when it matches the fingerprint the monitor itself broadcast.
        X509Certificate presented = captureCertificate(host, port);
        String actual = sha256Hex(presented);
        if (actual.isEmpty() || !actual.equals(wanted)) {
            throw new IOException("The monitor's certificate does not match its beacon ("
                    + (actual.isEmpty() ? "unreadable" : actual.substring(0, Math.min(16, actual.length()))
                    + "...") + ") - restart the monitor on this network and join again.");
        }
        upsertPinnedCertificate(truststoreFile, presented);
        return tlsConnect(host, port, loadTruststoreLeniently(truststoreFile));
    }

    /** Full TLS connect with endpoint + SAN validation against a truststore. */
    private static SSLSocket tlsConnect(String host, int port, KeyStore trustStore) throws IOException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
            socket.setEnabledProtocols(enabledProtocols(socket.getSupportedProtocols()));
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            socket.startHandshake();
            verifyPeerName(socket, host);
            return socket;
        } catch (IOException | RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Central monitor TLS setup failed: " + e.getMessage(), e);
        }
    }

    /** Opens the configured monitor client transport, or explicit development TCP. */
    public static Socket openClientSocket(String host, int port) throws IOException {
        return openClientSocket(host, port, "");
    }

    /** Opens the monitor client transport with an optional beacon fingerprint. */
    public static Socket openClientSocket(String host, int port,
                                          String expectedFingerprint) throws IOException {
        if (plaintextDevModeEnabled()) return new Socket();
        return newClientSocket(host, port, expectedFingerprint);
    }

    /**
     * A plain client socket for development mode only; production callers must
     * use {@link #newClientSocket(String, int)}.
     */
    public static Socket newDevelopmentClientSocket() {
        if (!plaintextDevModeEnabled()) {
            throw new IllegalStateException(
                    "Plaintext central transport is not allowed outside development mode");
        }
        return new Socket();
    }

    /**
     * Explicit SAN check of the handshake peer against the host the student
     * typed. Complements JSSE's endpoint identification; both must pass.
     */
    private static void verifyPeerName(SSLSocket socket, String host) throws IOException {
        String wanted = host == null ? "" : host.trim();
        if (wanted.isEmpty()) throw new IOException("Central host is empty");
        Certificate[] chain;
        try {
            chain = socket.getSession().getPeerCertificates();
        } catch (Exception e) {
            throw new IOException("Central monitor certificate could not be read", e);
        }
        if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate cert)) {
            throw new IOException("Central monitor did not present a certificate");
        }
        List<String> names = new ArrayList<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    // type 2 = dNSName, 7 = iPAddress (RFC 5280)
                    if (san.size() >= 2 && (san.get(0).equals(2) || san.get(0).equals(7))
                            && san.get(1) instanceof String value) {
                        names.add(value.toLowerCase(java.util.Locale.ROOT));
                    }
                }
            }
        } catch (Exception e) {
            throw new IOException("Central monitor certificate has no readable SANs", e);
        }
        String expected = wanted.toLowerCase(java.util.Locale.ROOT);
        boolean ip = expected.matches("\\d{1,3}(\\.\\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:]+");
        for (String name : names) {
            if (name.equals(expected)) return;
            if (!ip && (name.startsWith("*.") && expected.endsWith(name.substring(1)))) return;
        }
        throw new IOException("Central monitor certificate does not cover '" + wanted
                + "'; its SAN entries are " + names
                + ". Regenerate the certificate with this address (docs/CENTRAL_TLS.md).");
    }

    // ------------------------------------------------ certificate rotation ----

    /**
     * Every IPv4 address on an up, non-loopback interface. The certificate is
     * issued with all of them in its SANs so a student may type any address the
     * invigilator PC answers on - including a hotspot adapter that has no
     * default gateway of its own.
     */
    public static java.util.LinkedHashSet<String> allLanIpv4s() {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        try {
            java.util.Enumeration<java.net.NetworkInterface> interfaces =
                    java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                java.net.NetworkInterface ni = interfaces.nextElement();
                if (!ni.isUp() || ni.isLoopback()) continue;
                java.util.Enumeration<java.net.InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    java.net.InetAddress address = addresses.nextElement();
                    if (address instanceof java.net.Inet4Address) out.add(address.getHostAddress());
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    /**
     * The LAN addresses a student could realistically be told to type:
     * site-local IPv4s minus adapters whose churn must never rotate the
     * certificate (WSL, Hyper-V, tunnels, TAP). A Windows Mobile Hotspot
     * adapter counts - its name says "Virtual" but it is exactly the address
     * students sit behind.
     */
    private static java.util.LinkedHashSet<String> studentFacingLanIps() {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        for (String ip : allLanIpv4s()) {
            if (!ip.matches("\\d{1,3}(\\.\\d{1,3}){3}")) continue;
            java.net.InetAddress a;
            try {
                a = java.net.InetAddress.getByName(ip); // literal IP: never a DNS lookup
            } catch (Exception e) {
                continue;
            }
            if (!a.isSiteLocalAddress()) continue;
            out.add(ip);
        }
        out.removeAll(churningVirtualIps());
        return out;
    }

    /** Site-local IPv4s on adapters whose addresses come and go with tooling. */
    private static java.util.Set<String> churningVirtualIps() {
        java.util.Set<String> out = new java.util.HashSet<>();
        try {
            java.util.Enumeration<java.net.NetworkInterface> interfaces =
                    java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                java.net.NetworkInterface ni = interfaces.nextElement();
                String name = (ni.getName() + " " + ni.getDisplayName()).toLowerCase(java.util.Locale.ROOT);
                if (name.contains("wsl") || name.contains("hyper-v") || name.contains("vethernet")
                        || name.contains("virtualbox") || name.contains("tunnel")
                        || name.contains("tailscale") || name.contains("tap-")) {
                    java.util.Enumeration<java.net.InetAddress> addresses = ni.getInetAddresses();
                    while (addresses.hasMoreElements()) {
                        java.net.InetAddress a = addresses.nextElement();
                        if (a instanceof java.net.Inet4Address) out.add(a.getHostAddress());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    /**
     * The ip SAN entries of the monitor certificate currently on disk; empty
     * when the keystore is missing, unreadable or passwordless - each of those
     * states needs a fresh identity anyway.
     */
    private static java.util.Set<String> certificateIpSans() {
        File key = configuredKeystoreFile();
        if (!key.isFile()) return new java.util.HashSet<>();
        char[] password;
        try {
            password = storePassword(true);
        } catch (Exception e) {
            return new java.util.HashSet<>();
        }
        try {
            KeyStore store = loadKeyStore(key, password);
            Certificate[] chain = store.getCertificateChain("central");
            if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate cert)) {
                return new java.util.HashSet<>();
            }
            java.util.Set<String> ips = new java.util.HashSet<>();
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (san.size() >= 2 && san.get(0).equals(7) && san.get(1) instanceof String value) {
                        ips.add(value.toLowerCase(java.util.Locale.ROOT));
                    }
                }
            }
            return ips;
        } catch (Exception e) {
            return new java.util.HashSet<>();
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Rotate the monitor certificate when the machine's current student-facing
     * LAN addresses are not all covered by its SANs - the network changed
     * (hotspot, new subnet) and every student connection would otherwise fail
     * certificate validation with no fix short of manual regeneration. The
     * stale identity is preserved as an orphaned backup, then a fresh
     * certificate is provisioned with today's addresses.
     *
     * @return true when an existing certificate was replaced, so the invigilator
     *         knows student PCs will re-pair via the beacon (offline-imported
     *         truststore copies need a re-export). A first provision returns false.
     */
    public static synchronized boolean ensureCurrentIpsCovered() throws IOException {
        File key = configuredKeystoreFile();
        if (!key.isFile()) {
            ensureServerSetup(); // first provision already covers today's addresses
            return false;
        }
        java.util.Set<String> wanted = studentFacingLanIps();
        if (certificateIpSans().containsAll(wanted)) return false;
        String suffix = ".orphaned-" + System.currentTimeMillis();
        Files.move(key.toPath(), new File(key + suffix).toPath());
        File trust = configuredTruststoreFile();
        if (trust.isFile() && trust.equals(defaultTruststoreFile())) {
            Files.move(trust.toPath(), new File(trust + suffix).toPath());
        }
        ensureServerSetup();
        return true;
    }

    // ------------------------------------------------------ auto-pairing ----

    /**
     * TLS handshake that records the presented certificate instead of trusting
     * it. The result is only ever used after an explicit fingerprint match.
     */
    private static X509Certificate captureCertificate(String host, int port) throws IOException {
        final X509Certificate[] captured = new X509Certificate[1];
        try {
            javax.net.ssl.TrustManager capture = new javax.net.ssl.X509TrustManager() {
                @Override public void checkClientTrusted(
                        java.security.cert.X509Certificate[] chain, String authType)
                        throws java.security.cert.CertificateException {
                    throw new java.security.cert.CertificateException("no client certificates expected");
                }

                @Override public void checkServerTrusted(
                        java.security.cert.X509Certificate[] chain, String authType) {
                    if (chain != null && chain.length > 0
                            && chain[0] instanceof X509Certificate cert) {
                        captured[0] = cert;
                    }
                }

                @Override public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[0];
                }
            };
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new javax.net.ssl.TrustManager[]{capture}, null);
            SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket();
            socket.setEnabledProtocols(enabledProtocols(socket.getSupportedProtocols()));
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            socket.startHandshake();
            Certificate[] peers = socket.getSession().getPeerCertificates();
            socket.close();
            if (peers != null && peers.length > 0 && peers[0] instanceof X509Certificate cert) {
                return cert;
            }
            throw new IOException("The monitor did not present a certificate");
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Could not read the monitor's certificate: " + e.getMessage(), e);
        }
    }

    /** Pin a beacon-verified monitor certificate into the local truststore. */
    private static void upsertPinnedCertificate(File trust, X509Certificate certificate)
            throws IOException {
        KeyStore store;
        try {
            store = KeyStore.getInstance("PKCS12");
            if (trust.isFile()) {
                try (InputStream in = Files.newInputStream(trust.toPath())) {
                    store.load(in, DEFAULT_TRUSTSTORE_PASSWORD.toCharArray());
                }
            } else {
                store.load(null, null);
                File dir = trust.getParentFile();
                if (dir != null && !dir.isDirectory() && !dir.mkdirs()) {
                    throw new IOException("Could not create " + dir);
                }
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            // An unreadable existing store is replaced rather than failing the join.
            try {
                store = KeyStore.getInstance("PKCS12");
                store.load(null, null);
            } catch (Exception ignored) {
                throw new IOException("Could not open the local truststore for pairing", e);
            }
        }
        try {
            String alias = "central-" + sha256Hex(certificate).substring(0, 8);
            store.setCertificateEntry(alias, certificate);
            try (OutputStream out = Files.newOutputStream(trust.toPath())) {
                store.store(out, DEFAULT_TRUSTSTORE_PASSWORD.toCharArray());
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Could not save the paired monitor certificate: "
                    + e.getMessage(), e);
        }
    }

    /** Pair a monitor discovered by the authenticated LAN TCP fallback. */
    public static String pairMonitorOverTcp(String host, int port) throws IOException {
        X509Certificate certificate = captureCertificate(host, port);
        String fingerprint = sha256Hex(certificate);
        if (fingerprint.isEmpty()) throw new IOException("The monitor certificate fingerprint is empty");
        upsertPinnedCertificate(configuredTruststoreFile(), certificate);
        return fingerprint;
    }

    /** Lowercase SHA-256 hex of a certificate's DER encoding; "" when unavailable. */
    public static String sha256Hex(X509Certificate certificate) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(certificate.getEncoded());
            StringBuilder out = new StringBuilder(digest.length * 2);
            for (byte b : digest) out.append(String.format("%02x", b));
            return out.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** The fingerprint of this PC's monitor certificate; "" when none exists yet. */
    public static String monitorCertificateFingerprint() {
        File key = configuredKeystoreFile();
        if (!key.isFile()) return "";
        char[] password;
        try {
            password = storePassword(true);
        } catch (Exception e) {
            return "";
        }
        try {
            KeyStore store = loadKeyStore(key, password);
            Certificate[] chain = store.getCertificateChain("central");
            if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate cert)) {
                return "";
            }
            return sha256Hex(cert);
        } catch (Exception e) {
            return "";
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    // ----------------------------------------------------------- helpers ----

    /**
     * Open the truststore with whichever password was actually used to create it.
     * A truststore holds only a public certificate, so its password is an
     * integrity nicety, not a secret: it may carry the configured store password
     * (this PC, where the config value exists) or the hard-coded default (a
     * student PC that received only the truststore file, or the auto-provisioned
     * truststore). Try the configured source first, then the default.
     */
    private static KeyStore loadTruststoreLeniently(File truststoreFile) throws IOException {
        try {
            return loadKeyStore(truststoreFile, storePassword(false));
        } catch (Exception configuredFailed) {
            return loadKeyStore(truststoreFile, DEFAULT_TRUSTSTORE_PASSWORD.toCharArray());
        }
    }

    private static KeyStore loadKeyStore(File file, char[] password) throws IOException {
        try (InputStream in = Files.newInputStream(file.toPath())) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(in, password.length == 0 ? null : password);
            return store;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Could not read PKCS12 store " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * Store password without ever logging it: system property, then environment
     * variable, then the admin-owned config file. A truststore of certificates
     * needs no password, so empty is allowed there but not for the keystore.
     */
    private static char[] storePassword(boolean required) {
        String value = System.getProperty(STOREPASS_SYSTEM_PROPERTY, "");
        if (value.isBlank()) {
            value = System.getenv(STOREPASS_ENVIRONMENT);
        }
        if (value == null || value.isBlank()) {
            value = AppConfig.getInstance().getConfigValue(STOREPASS_CONFIG) == null
                    ? "" : AppConfig.getInstance().getConfigValue(STOREPASS_CONFIG);
        }
        if ((value == null || value.isBlank()) && !required) {
            return DEFAULT_TRUSTSTORE_PASSWORD.toCharArray();
        }
        if ((value == null || value.isBlank()) && required) {
            throw new IllegalStateException("Central TLS store password is not set. Provide "
                    + STOREPASS_SYSTEM_PROPERTY + ", the " + STOREPASS_ENVIRONMENT
                    + " environment variable, or the " + STOREPASS_CONFIG
                    + " config value (see docs/CENTRAL_TLS.md).");
        }
        return value == null ? new char[0] : value.toCharArray();
    }

    /** The store password for tests; production code uses storePassword(). */
    static char[] storePasswordForTest() {
        return storePassword(false);
    }

    private static String[] enabledProtocols(String[] supported) {
        List<String> enabled = new ArrayList<>();
        for (String protocol : TLS_PROTOCOLS) {
            for (String candidate : supported) {
                if (candidate.equalsIgnoreCase(protocol)) enabled.add(candidate);
            }
        }
        if (enabled.isEmpty()) {
            throw new IllegalStateException("No TLS 1.2/1.3 support in this runtime");
        }
        return enabled.toArray(new String[0]);
    }

    /** Best-effort one-time warning for development plaintext, client side. */
    public static void warnPlaintextOnce() {
        AppLog.warn(plaintextWarning());
    }
}

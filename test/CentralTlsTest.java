import com.cheatguard.watchdog.CentralAuth;
import com.cheatguard.watchdog.CentralTls;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Headless TLS tests for the central monitor transport, in the same plain-main
 * style as CoreFlowTest. Real PKCS12 keystore/truststore pairs are generated
 * with the JDK's keytool and the challenge-response protocol runs over real
 * TLS sockets on loopback.
 *
 * Run with an isolated {@code -Dcheatguard.data.dir=<fresh temp dir>} so the
 * developer's own central TLS stores are never touched.
 */
public class CentralTlsTest {

    private static final String STORE_PASS = "tls-test-pass-2026";
    private static final String EXAM_CODE = "951753";
    private static final String WRONG_CODE = "000000";

    private static int failures = 0;

    /** Shared state of the in-test monitor. */
    private static volatile SSLServerSocket serverSocket;
    private static volatile String serverError = "";
    private static final CountDownLatch serverReady = new CountDownLatch(1);
    /** Counts completed (authenticated) handshakes server-side. */
    private static volatile int authenticatedSessions = 0;
    private static volatile int rejectedSessions = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("== CentralTlsTest ==");
        System.out.println("Isolated data dir: "
                + com.cheatguard.config.AppPaths.getDataDirectory());

        Path certs = Files.createTempDirectory("cheatguard-tls-certs");
        checkPlaintextDefaults();
        buildStores(certs);
        startMonitor();
        checkSuccessfulTlsConnection();
        checkHmacFailureRejected();
        checkReconnect();
        checkInvalidCertificateRejected(certs);
        checkMissingKeystoreFailsClosed();
        checkPlaintextRejectedInProduction();
        stopMonitor();

        System.out.println();
        if (failures == 0) {
            System.out.println("ALL CHECKS PASSED");
        } else {
            System.out.println(failures + " CHECK(S) FAILED");
            System.exit(1);
        }
    }

    // ------------------------------------------------------------- mode ----

    private static void checkPlaintextDefaults() {
        section("Plaintext is never the default");
        expect("production mode rejects plaintext development sockets",
                !CentralTls.plaintextDevModeEnabled());
        boolean refused = false;
        try {
            CentralTls.newDevelopmentClientSocket();
        } catch (IllegalStateException expected) {
            refused = true;
        }
        expect("plaintext client socket refused outside development mode", refused);
    }

    // ------------------------------------------------------------ stores ----

    /** Generate keystore + truststore (and a rogue pair) with the JDK keytool. */
    private static void buildStores(Path certs) throws Exception {
        section("PKCS12 store generation (keytool)");
        File configDir = com.cheatguard.config.AppPaths.getConfigDirectory();
        keytool(certs, "genpair", "central-monitor-keystore.p12",
                "SAN=dns:localhost,ip:127.0.0.1");
        keytool(certs, "export", "central-monitor-keystore.p12", null);
        File exported = certs.resolve("central.cer").toFile();
        File truststore = certs.resolve("central-monitor-truststore.p12").toFile();
        keytoolDirect(new String[]{
                "-importcert", "-alias", "central", "-file", exported.getAbsolutePath(),
                "-keystore", truststore.getAbsolutePath(), "-storetype", "PKCS12",
                "-storepass", STORE_PASS, "-noprompt"});
        // A self-signed certificate that trusts nothing we serve.
        keytool(certs, "genpair-rogue", "rogue-keystore.p12", "SAN=dns:rogue.invalid");
        keytoolDirect(new String[]{
                "-exportcert", "-alias", "rogue", "-rfc",
                "-keystore", certs.resolve("rogue-keystore.p12").toFile().getAbsolutePath(),
                "-storepass", STORE_PASS, "-file", certs.resolve("rogue.cer").toFile().getAbsolutePath()});
        File rogueTrust = certs.resolve("rogue-truststore.p12").toFile();
        keytoolDirect(new String[]{
                "-importcert", "-alias", "rogue", "-file", certs.resolve("rogue.cer").toFile().getAbsolutePath(),
                "-keystore", rogueTrust.getAbsolutePath(), "-storetype", "PKCS12",
                "-storepass", STORE_PASS, "-noprompt"});

        Files.copy(certs.resolve("central-monitor-keystore.p12"),
                new File(configDir, "central-monitor-keystore.p12").toPath());
        Files.copy(certs.resolve("central-monitor-truststore.p12"),
                new File(configDir, "central-monitor-truststore.p12").toPath());
        System.setProperty(CentralTls.STOREPASS_SYSTEM_PROPERTY, STORE_PASS);
        expect("keystore present in the app config directory",
                CentralTls.configuredKeystoreFile().isFile());
        expect("truststore present in the app config directory",
                CentralTls.configuredTruststoreFile().isFile());
    }

    private static void keytool(Path certs, String dnameKind, String keystoreName,
            String ext) throws Exception {
        String dname;
        String alias;
        switch (dnameKind) {
            case "genpair-rogue" -> {
                dname = "CN=CheatGuard Rogue Monitor";
                alias = "rogue";
            }
            case "export" -> {
                keytoolDirect(new String[]{
                        "-exportcert", "-alias", "central", "-rfc",
                        "-keystore", certs.resolve(keystoreName).toFile().getAbsolutePath(),
                        "-storepass", STORE_PASS,
                        "-file", certs.resolve("central.cer").toFile().getAbsolutePath()});
                return;
            }
            default -> {
                dname = "CN=Cheat.Guard Monitor";
                alias = "central";
            }
        }
        var cmd = new java.util.ArrayList<>(java.util.List.of(
                "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "30", "-dname", dname, "-keystore",
                certs.resolve(keystoreName).toFile().getAbsolutePath(),
                "-storetype", "PKCS12", "-storepass", STORE_PASS, "-keypass", STORE_PASS));
        if (ext != null) {
            cmd.add("-ext");
            cmd.add(ext);
        }
        keytoolDirect(cmd.toArray(new String[0]));
    }

    private static void keytoolDirect(String[] keytoolArgs) throws Exception {
        String exe = System.getProperty("java.home") + File.separator + "bin"
                + File.separator + "keytool"
                + (System.getProperty("os.name", "").toLowerCase().contains("win") ? ".exe" : "");
        Process p = new ProcessBuilder(
                java.util.stream.Stream.concat(java.util.stream.Stream.of(exe),
                        Arrays.stream(keytoolArgs)).toArray(String[]::new))
                .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor(60, TimeUnit.SECONDS) ? p.exitValue() : -1;
        if (code != 0) {
            throw new IllegalStateException("keytool failed (" + code + "): " + out);
        }
    }

    // ----------------------------------------------------------- monitor ----

    /**
     * Minimal in-test monitor: accepts several connections, issues a
     * challenge, checks the HMAC response against EXAM_CODE, echoes the
     * HELLO line back when authenticated, and just closes on a bad response.
     */
    private static void startMonitor() throws Exception {
        section("Monitor start (TLS server socket)");
        Thread server = new Thread(() -> {
            try (SSLServerSocket ss = CentralTls.newServerSocket(0)) {
                serverSocket = ss;
                serverReady.countDown();
                while (true) {
                    SSLSocket client = (SSLSocket) ss.accept();
                    client.setSoTimeout(10_000);
                    handleClient(client);
                }
            } catch (java.net.SocketException stopped) {
                // monitor socket closed by stopMonitor()
            } catch (Exception e) {
                serverError = String.valueOf(e);
            }
        }, "tls-test-monitor");
        server.setDaemon(true);
        server.start();
        expect("TLS server socket bound", serverReady.await(15, TimeUnit.SECONDS)
                && serverSocket != null && serverSocket.getLocalPort() > 0);
    }

    private static void handleClient(SSLSocket client) {
        try (client) {
            OutputStream out = client.getOutputStream();
            String nonce = CentralAuth.newNonce();
            out.write(("CHALLENGE@@@" + nonce + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
            String hello = in.readLine();
            String auth = in.readLine();
            if (hello == null || auth == null || !hello.startsWith("HELLO@@@")
                    || !auth.startsWith("AUTH@@@")) {
                rejectedSessions++;
                return;
            }
            String[] hp = hello.split("@@@", 4);
            String expected = CentralAuth.response(EXAM_CODE, nonce,
                    hp.length > 1 ? hp[1] : "", hp.length > 2 ? hp[2] : "",
                    hp.length > 3 ? hp[3] : "");
            if (!CentralAuth.constantTimeEquals(expected, auth.substring("AUTH@@@".length()))) {
                rejectedSessions++;
                return; // close without any confirmation
            }
            authenticatedSessions++;
            out.write(("OK@@@" + hello + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            // hold the connection open briefly like the real monitor would
            client.setSoTimeout(400);
            try {
                while (in.readLine() != null) {
                    // drain until the client goes away
                }
            } catch (java.net.SocketTimeoutException ignored) {
            }
        } catch (Exception e) {
            rejectedSessions++;
        }
    }

    // ------------------------------------------------------------- tests ----

    /** Full happy path: TLS + challenge-response + authenticated reply. */
    private static void checkSuccessfulTlsConnection() throws Exception {
        section("Successful TLS connection with HMAC authentication");
        String reply = connectAndAuthenticate(EXAM_CODE, serverSocket.getLocalPort());
        expect("monitor echoed the authenticated HELLO line",
                reply != null && reply.startsWith("OK@@@HELLO@@@")
                        && reply.contains("test-pc") && reply.contains("S-100"));
        expect("server recorded an authenticated session", authenticatedSessions >= 1);
    }

    private static void checkHmacFailureRejected() throws Exception {
        section("HMAC authentication failure");
        int rejectedBefore = rejectedSessions;
        String reply = connectAndAuthenticate(WRONG_CODE, serverSocket.getLocalPort());
        expect("wrong exam code gets no confirmation", reply == null);
        expect("server counted the rejection", rejectedSessions == rejectedBefore + 1);
    }

    private static void checkReconnect() throws Exception {
        section("Reconnect behavior");
        int before = authenticatedSessions;
        String first = connectAndAuthenticate(EXAM_CODE, serverSocket.getLocalPort());
        String second = connectAndAuthenticate(EXAM_CODE, serverSocket.getLocalPort());
        expect("two consecutive sessions both authenticated",
                first != null && second != null && authenticatedSessions >= before + 2);
    }

    private static void checkInvalidCertificateRejected(Path certs) throws Exception {
        section("Invalid certificate rejection");
        com.cheatguard.config.AppConfig.getInstance().setConfigValue(
                CentralTls.TRUSTSTORE_CONFIG,
                certs.resolve("rogue-truststore.p12").toFile().getAbsolutePath());
        boolean refused = false;
        String message = "";
        try {
            CentralTls.newClientSocket("127.0.0.1", serverSocket.getLocalPort());
        } catch (Exception e) {
            refused = true;
            message = String.valueOf(e);
        }
        expect("client refuses a certificate outside its truststore", refused);
        expect("rejection is a TLS/validation failure, not a silent pass",
                message.contains("certificate") || message.contains("handshake")
                        || message.contains("trust"));
        com.cheatguard.config.AppConfig.getInstance().setConfigValue(
                CentralTls.TRUSTSTORE_CONFIG, "");
        expect("truststore config restored", CentralTls.configuredTruststoreFile()
                .getName().equals("central-monitor-truststore.p12"));
    }

    private static void checkMissingKeystoreFailsClosed() throws Exception {
        section("Missing keystore fails closed (no plaintext fallback)");
        com.cheatguard.config.AppConfig.getInstance().setConfigValue(
                CentralTls.KEYSTORE_CONFIG,
                new File(com.cheatguard.config.AppPaths.getConfigDirectory(),
                        "does-not-exist.p12").getAbsolutePath());
        boolean refused = false;
        String message = "";
        try {
            CentralTls.newServerSocket(0);
        } catch (Exception e) {
            refused = true;
            message = String.valueOf(e);
        }
        expect("server refuses to start without its keystore", refused);
        expect("error points at the keystore, not a plaintext fallback",
                message.contains("keystore"));
        com.cheatguard.config.AppConfig.getInstance().setConfigValue(
                CentralTls.KEYSTORE_CONFIG, "");
    }

    private static void checkPlaintextRejectedInProduction() throws Exception {
        section("Plaintext mode rejected in production mode");
        System.setProperty(CentralTls.PLAINTEXT_SYSTEM_PROPERTY, "true");
        try {
            expect("flag enables development mode",
                    CentralTls.plaintextDevModeEnabled());
            boolean tlsServerRefused = false;
            try {
                CentralTls.newServerSocket(0);
            } catch (IllegalStateException expected) {
                tlsServerRefused = true;
            }
            expect("TLS server socket refuses to bind in plaintext dev mode", tlsServerRefused);
            boolean tlsClientRefused = false;
            try {
                CentralTls.newClientSocket("127.0.0.1", serverSocket.getLocalPort());
            } catch (IllegalStateException expected) {
                tlsClientRefused = true;
            }
            expect("TLS client socket refuses to connect in plaintext dev mode", tlsClientRefused);
            boolean plainAllowed = false;
            try (java.net.Socket ignored = CentralTls.newDevelopmentClientSocket()) {
                plainAllowed = true;
            } catch (Exception e) {
                // not expected
            }
            expect("explicit development opt-in allows the plain socket", plainAllowed);
            expect("a visible warning is produced",
                    CentralTls.plaintextWarning().contains("PLAINTEXT"));
        } finally {
            System.setProperty(CentralTls.PLAINTEXT_SYSTEM_PROPERTY, "");
            expect("flag cleared restores production mode",
                    !CentralTls.plaintextDevModeEnabled());
        }
    }

    // ----------------------------------------------------------- helpers ----

    /** One client session: TLS connect, challenge-response, read the reply. */
    private static String connectAndAuthenticate(String examCode, int port) throws Exception {
        try (SSLSocket socket = CentralTls.newClientSocket("127.0.0.1", port)) {
            OutputStream out = socket.getOutputStream();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            String challenge = in.readLine();
            if (challenge == null || !challenge.startsWith("CHALLENGE@@@")) {
                throw new java.io.IOException("no challenge from test monitor");
            }
            String nonce = challenge.substring("CHALLENGE@@@".length()).trim();
            String hello = "HELLO@@@test-pc@@@S-100@@@CSE101";
            String auth = "AUTH@@@" + CentralAuth.response(examCode, nonce, "test-pc",
                    "S-100", "CSE101");
            out.write((hello + "\n" + auth + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            socket.setSoTimeout(8000);
            return in.readLine();
        } catch (Exception e) {
            if (examCode.equals(EXAM_CODE)) throw e;
            return null; // the rejected path ends without a readable reply
        }
    }

    private static void stopMonitor() {
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (Exception ignored) {
        }
        expect("monitor stopped without server errors", serverError.isEmpty());
    }

    private static void expect(String label, boolean condition) {
        System.out.println((condition ? "  PASS  " : "  FAIL  ") + label);
        if (!condition) failures++;
    }

    private static void section(String name) {
        System.out.println();
        System.out.println("-- " + name + " --");
    }
}
// QA flow: TLS/pairing input -> transport validation -> accepted/rejected result.

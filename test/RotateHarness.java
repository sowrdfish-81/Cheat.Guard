import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.watchdog.CentralAuth;
import com.cheatguard.watchdog.CentralTls;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Cert-rotation E2E: a stale certificate (other-network SANs) must rotate and serve. */
public class RotateHarness {
    public static void main(String[] args) throws Exception {
        String dataDir = System.getProperty("cheatguard.data.dir");
        new File(dataDir, "Desktop").mkdirs(); // keep the real Desktop clean
        AppPaths.setInteractiveProfile(dataDir);
        AppPaths.setInteractiveDesktop(new File(dataDir, "Desktop").getAbsolutePath());
        // 1. A certificate created on ANOTHER network: SANs = localhost/127.0.0.1 only.
        File key = CentralTls.configuredKeystoreFile();
        File dir = key.getParentFile();
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IllegalStateException("no config dir");
        String keytool = new File(System.getProperty("java.home"), "bin/keytool.exe").getAbsolutePath();
        if (!new File(keytool).isFile()) keytool = "keytool";
        run(keytool, "-genkeypair", "-alias", "central", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "30", "-dname", "CN=Stale Network", "-ext",
                "SAN=dns:localhost,ip:127.0.0.1", "-keystore", key.getAbsolutePath(),
                "-storetype", "PKCS12", "-storepass", "stalepass", "-keypass", "stalepass");
        AppConfig.getInstance().setConfigValue(CentralTls.STOREPASS_CONFIG, "stalepass");
        System.out.println("ROTATE: stale certificate installed with SAN=127.0.0.1 only");

        // 2. Rotation must detect the missing LAN IPs and re-issue the identity.
        boolean rotated = CentralTls.ensureCurrentIpsCovered();
        System.out.println("ROTATE: ensureCurrentIpsCovered -> " + rotated
                + " (student-facing IPs: " + new ArrayList<>(CentralTls.allLanIpv4s()) + ")");
        if (!rotated) throw new AssertionError("FAIL: expected certificate rotation");

        // 3. The new identity must serve TLS and validate for 127.0.0.1 (SAN check).
        try (javax.net.ssl.SSLServerSocket server = CentralTls.newServerSocket(0)) {
            int port = server.getLocalPort();
            Thread serverThread = new Thread(() -> {
                try {
                    java.net.Socket s = server.accept();
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                    OutputStream out = s.getOutputStream();
                    String nonce = CentralAuth.newNonce();
                    out.write(("CHALLENGE@@@" + nonce + "\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    String hello = in.readLine();
                    String[] hp = hello.split("@@@", 4);
                    String expect = CentralAuth.response("123456", nonce, hp[1], hp[2], hp[3]);
                    String auth = in.readLine();
                    System.out.println("ROTATE: server side auth "
                            + (CentralAuth.constantTimeEquals(expect,
                                    auth.substring("AUTH@@@".length()).trim()) ? "OK" : "MISMATCH"));
                    s.close();
                } catch (Exception e) {
                    System.out.println("ROTATE: server side error: " + e);
                }
            });
            serverThread.setDaemon(true);
            serverThread.start();
            javax.net.ssl.SSLSocket client = CentralTls.newClientSocket("127.0.0.1", port);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
            OutputStream out = client.getOutputStream();
            String challenge = in.readLine();
            String nonce = challenge.substring("CHALLENGE@@@".length()).trim();
            out.write(("HELLO@@@ROTPC@@@T0002@@@CSE-TEST\n"
                    + "AUTH@@@" + CentralAuth.response("123456", nonce, "ROTPC", "T0002", "CSE-TEST")
                    + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            Thread.sleep(800);
            client.close();
            System.out.println("ROTATE: PASS - rotated identity serves TLS and validates SANs");
        }
    }

    private static void run(String... command) throws Exception {
        List<String> cmd = new ArrayList<>(Arrays.asList(command));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) throw new IllegalStateException("keytool failed: " + output);
    }
}

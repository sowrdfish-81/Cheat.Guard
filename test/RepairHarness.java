import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.watchdog.CentralTls;

import java.io.File;

/**
 * Re-pair E2E: a student pinned certificate v1; the monitor rotates to v2 and
 * advertises the new fingerprint; the student must re-pin automatically.
 */
public class RepairHarness {
    public static void main(String[] args) throws Exception {
        String dataDir = System.getProperty("cheatguard.data.dir");
        new File(dataDir, "Desktop").mkdirs();
        AppPaths.setInteractiveProfile(dataDir);
        AppPaths.setInteractiveDesktop(new File(dataDir, "Desktop").getAbsolutePath());

        // 1. Monitor identity v1, served by a live server socket.
        javax.net.ssl.SSLServerSocket serverV1 = CentralTls.newServerSocket(0);
        String fpV1 = CentralTls.monitorCertificateFingerprint();
        System.out.println("REPAIR: v1 fingerprint " + fpV1.substring(0, 16) + "...");

        // 2. The monitor rotates on disk: a brand-new key pair, same SAN coverage.
        File key = CentralTls.configuredKeystoreFile();
        java.nio.file.Files.deleteIfExists(key.toPath());
        String keytool = new File(System.getProperty("java.home"), "bin/keytool.exe").getAbsolutePath();
        if (!new File(keytool).isFile()) keytool = "keytool";
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "central",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
                "-dname", "CN=CheatGuard Central Monitor", "-ext",
                "SAN=dns:localhost,ip:127.0.0.1", "-keystore", key.getAbsolutePath(),
                "-storetype", "PKCS12", "-storepass", "v2pass", "-keypass", "v2pass")
                .redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes());
        if (p.waitFor() != 0) throw new IllegalStateException("keytool failed: " + output);
        AppConfig.getInstance().setConfigValue(CentralTls.STOREPASS_CONFIG, "v2pass");
        String fpV2 = CentralTls.monitorCertificateFingerprint();
        System.out.println("REPAIR: v2 fingerprint " + fpV2.substring(0, 16) + "...");
        if (fpV1.equals(fpV2)) throw new AssertionError("FAIL: certificate did not rotate");

        // 3. A server socket on the rotated identity (the monitor restarting).
        javax.net.ssl.SSLServerSocket serverV2 = CentralTls.newServerSocket(0);
        Thread acceptor = new Thread(() -> {
            while (true) {
                try {
                    java.net.Socket s = serverV2.accept();
                    s.setSoTimeout(5000);
                    // the read drives the server-side handshake; EOF when the client closes
                    s.getInputStream().read(new byte[64]);
                    s.close();
                } catch (Exception e) {
                    // a rejected first attempt (stale truststore) must not kill the loop
                }
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();

        // 4. The student (truststore still holds v1) joins with the beacon's v2
        //    fingerprint: the v1 truststore rejects v2, TOFU must re-pin and connect.
        javax.net.ssl.SSLSocket client = CentralTls.newClientSocket("127.0.0.1",
                serverV2.getLocalPort(), fpV2);
        System.out.println("REPAIR: PASS - student re-paired automatically after rotation");
        client.close();
        serverV1.close();
        serverV2.close();
    }
}

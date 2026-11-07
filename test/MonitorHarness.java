import com.cheatguard.watchdog.CentralAuth;
import com.cheatguard.watchdog.CentralReporter;
import com.cheatguard.watchdog.CentralTls;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;

/** Monitor-side E2E: TLS server + beacon broadcaster, like CentralMonitorPanel. */
public class MonitorHarness {
    public static void main(String[] args) throws Exception {
        String code = "123456";
        try (javax.net.ssl.SSLServerSocket server = CentralTls.newServerSocket(47821)) {
            System.out.println("MONITOR: listening on 47821 (TLS), lan-ips=" + CentralTls.allLanIpv4s());
            Thread beacon = new Thread(() -> {
                try (DatagramSocket s = new DatagramSocket()) {
                    s.setBroadcast(true);
                    // args[1] = "badfp" advertises a wrong fingerprint (mismatch test)
                    String fp = "badfp".equals(args.length > 1 ? args[1] : "")
                            ? "0000000000000000000000000000000000000000000000000000000000000000"
                            : CentralTls.monitorCertificateFingerprint();
                    byte[] payload = (CentralReporter.BEACON_PREFIX + 47821
                            + (fp.isEmpty() ? "" : "@@@" + fp)).getBytes(StandardCharsets.UTF_8);
                    LinkedHashSet<String> targets = new LinkedHashSet<>();
                    targets.add("255.255.255.255");
                    targets.add("127.0.0.1"); // lab-only: a loopback-source beacon for the sandboxed reporter
                    if (args.length > 0 && "loopback".equals(args[0])) {
                        targets.clear();
                        targets.add("127.0.0.1");
                    }
                    while (true) {
                        for (String t : targets) {
                            try {
                                s.send(new DatagramPacket(payload, payload.length,
                                        InetAddress.getByName(t), CentralReporter.DISCOVERY_UDP_PORT));
                            } catch (Exception ignored) {
                            }
                        }
                        Thread.sleep(1500);
                    }
                } catch (Exception ignored) {
                }
            });
            beacon.setDaemon(true);
            beacon.start();

            server.setSoTimeout(5000);
            long deadline = System.currentTimeMillis() + 300000;
            while (true) {
                if (System.currentTimeMillis() > deadline) {
                    throw new IllegalStateException("FAIL: no authenticated student within 300s");
                }
                java.net.Socket socket;
                try {
                    socket = server.accept();
                } catch (SocketTimeoutException e) {
                    continue;
                }
                System.out.println("MONITOR: connection from "
                        + socket.getInetAddress().getHostAddress());
                try {
                    socket.setSoTimeout(15000); // a stuck handshake must not block the loop
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                    OutputStream out = socket.getOutputStream();
                    String nonce = CentralAuth.newNonce();
                    out.write(("CHALLENGE@@@" + nonce + "\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    String hello = in.readLine();
                    String auth = in.readLine();
                    System.out.println("MONITOR: " + hello);
                    if (hello == null || !hello.startsWith("HELLO@@@") || auth == null) {
                        socket.close();
                        continue;
                    }
                    String[] hp = hello.split("@@@", 4);
                    String expect = CentralAuth.response(code, nonce, hp[1], hp[2], hp[3]);
                    if (!CentralAuth.constantTimeEquals(expect,
                            auth.substring("AUTH@@@".length()).trim())) {
                        System.out.println("MONITOR: auth mismatch - dropping");
                        socket.close();
                        continue;
                    }
                    System.out.println("MONITOR: AUTH OK");
                    // v1.9.18+ protocol: send the verdict so the student does not
                    // wait out its 15 s legacy timeout before streaming events.
                    out.write(("OK\n").getBytes(StandardCharsets.UTF_8));
                    out.flush();
                    socket.setSoTimeout(8000);
                    for (int i = 0; i < 3; i++) {
                        String line = in.readLine();
                        System.out.println("MONITOR: EVENT[" + i + "] " + line);
                        if (line == null) {
                            System.out.println("MONITOR: FAIL - stream ended early");
                            return;
                        }
                    }
                    System.out.println("MONITOR: PASS - 3 events received over TLS");
                    return;
                } catch (Exception e) {
                    System.out.println("MONITOR: dropping connection: " + e);
                    try {
                        socket.close();
                    } catch (Exception ignored) {
                    }
                }
            }
        }
    }
}

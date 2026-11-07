import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.ExamSession;
import com.cheatguard.core.Violation;
import com.cheatguard.watchdog.CentralReporter;

/** Student-side E2E: discovery (empty manual IP) + TLS streaming. */
public class StudentHarness {
    public static void main(String[] args) throws Exception {
        String dataDir = System.getProperty("cheatguard.data.dir");
        new java.io.File(dataDir, "Desktop").mkdirs(); // keep the real Desktop clean
        AppPaths.setInteractiveProfile(dataDir);
        AppPaths.setInteractiveDesktop(new java.io.File(dataDir, "Desktop").getAbsolutePath());
        // debug probe: what exactly fails when reaching the monitor?
        String probeHost = args.length > 0 ? args[0] : "127.0.0.1";
        try {
            java.net.Socket probe = new java.net.Socket();
            probe.connect(new java.net.InetSocketAddress(probeHost, 47821), 3000);
            System.out.println("PROBE: TCP connect to " + probeHost + ":47821 OK");
            probe.close(); // release the server's accept() before the real TLS attempt
            try {
                com.cheatguard.watchdog.CentralTls.newClientSocket(probeHost, 47821).close();
                System.out.println("PROBE: TLS handshake OK");
            } catch (Exception tls) {
                System.out.println("PROBE: TLS failed - " + tls);
            }
        } catch (Exception tcp) {
            System.out.println("PROBE: TCP connect failed - " + tcp);
        }
        AppConfig config = AppConfig.getInstance();
        config.setExamCode("123456");
        // args[0] = manual invigilator IP; empty -> discovery must find the monitor
        String manual = args.length > 0 ? args[0] : "";
        config.setCentralHost(manual);
        ExamSession session = new ExamSession("CSE-TEST", "T0001");
        CentralReporter reporter = new CentralReporter(session, manual, config.getExamCode());
        reporter.setStatusConsumer(v ->
                System.out.println("STUDENT-STATUS: " + v.getType() + " - " + v.getDescription()));
        reporter.start();
        Thread.sleep(2000);
        reporter.report(new Violation("USB_DEVICE", "Unknown USB mass storage plugged in",
                Violation.Severity.CRITICAL));
        reporter.report(new Violation("PROCESS_BLOCKED", "chrome.exe closed",
                Violation.Severity.NOTICE));
        Thread.sleep(25000); // let the monitor drain the stream
        reporter.stop();
        Thread.sleep(1500);
        System.out.println("STUDENT: DONE");
        System.exit(0);
    }
}

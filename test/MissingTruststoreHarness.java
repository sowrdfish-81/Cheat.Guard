import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.ExamSession;
import com.cheatguard.watchdog.CentralReporter;

/** Diagnostic E2E: an unpaired student PC (no truststore) must SAY so on the live feed. */
public class MissingTruststoreHarness {
    public static void main(String[] args) throws Exception {
        String dataDir = System.getProperty("cheatguard.data.dir");
        new java.io.File(dataDir, "Desktop").mkdirs(); // keep the real Desktop clean
        AppPaths.setInteractiveProfile(dataDir);
        AppPaths.setInteractiveDesktop(new java.io.File(dataDir, "Desktop").getAbsolutePath());
        AppConfig config = AppConfig.getInstance();
        config.setExamCode("123456");
        config.setCentralHost("127.0.0.1"); // nothing is listening; the reason must surface fast
        ExamSession session = new ExamSession("CSE-TEST", "T0003");
        CentralReporter reporter = new CentralReporter(session, config.getCentralHost(),
                config.getExamCode());
        final String[] reported = {""};
        reporter.setStatusConsumer(v -> {
            reported[0] = v.getType() + " - " + v.getDescription();
            System.out.println("STUDENT-STATUS: " + reported[0]);
        });
        reporter.start();
        long deadline = System.currentTimeMillis() + 30000;
        while (System.currentTimeMillis() < deadline
                && !reported[0].contains("truststore")) {
            Thread.sleep(500);
        }
        reporter.stop();
        Thread.sleep(500);
        if (!reported[0].contains("truststore")) {
            throw new AssertionError("FAIL: missing-truststore reason never surfaced: " + reported[0]);
        }
        System.out.println("MISSING-TRUSTSTORE: PASS");
        System.exit(0);
    }
}

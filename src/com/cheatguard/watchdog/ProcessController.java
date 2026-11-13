package com.cheatguard.watchdog;

// OWNER: Muhit — unauthorized-process enforcement and close/deny behavior.

import com.cheatguard.core.AppLog;

/** Windows process enforcement helper. */
public class ProcessController {
    public boolean terminate(long pid) {
        if (pid <= 0) return false;
        try {
            ProcessBuilder pb = new ProcessBuilder("taskkill", "/PID", Long.toString(pid), "/T", "/F");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            // terminate() runs on the watchdog scan thread: an unbounded wait on a
            // hung taskkill would stall every later scan cycle, and unread output
            // could fill the pipe and deadlock waitFor().
            if (!p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
            int code = p.exitValue();
            p.getInputStream().readAllBytes();
            return code == 0;
        } catch (Exception e) {
            AppLog.warn("Could not terminate PID " + pid + ": " + e.getMessage());
            return false;
        }
    }
}

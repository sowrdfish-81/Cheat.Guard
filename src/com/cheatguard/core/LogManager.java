package com.cheatguard.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/** Thread-safe append-only session logger with short retry for transient Windows file contention. */
public class LogManager {
    private final File logFile;
    private final List<Violation> violations = new ArrayList<>();

    public LogManager(File logFile) {
        this.logFile = logFile;
        try {
            File parent = logFile.getParentFile();
            if (parent != null) parent.mkdirs();
            if (!logFile.exists()) logFile.createNewFile();
        } catch (IOException e) {
            AppLog.warn("Could not create log file: " + e.getMessage());
        }
    }

    public synchronized void record(Violation v) {
        violations.add(v);
        String line = v.toString() + System.lineSeparator();
        IOException last = null;

        // Synchronized prevents competing watchdog/UI threads in this process.
        // A few short retries also tolerate brief Windows AV/indexer contention.
        for (int attempt = 0; attempt < 4; attempt++) {
            try {
                Files.write(logFile.toPath(), line.getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                return;
            } catch (IOException e) {
                last = e;
                try { Thread.sleep(25L * (attempt + 1)); }
                catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        AppLog.warn("Could not write log: " + (last == null ? "unknown error" : last.getMessage()));
    }

    public synchronized List<Violation> getAllViolations() { return new ArrayList<>(violations); }

    /**
     * Recreate the plaintext log from the in-memory audit list when a cleanup
     * tool, antivirus, or an interrupted recovery removed the path during the
     * session.  Sealing must never fail merely because the append file vanished;
     * the authoritative rows are already retained in this process.
     */
    public synchronized boolean ensureFilePresent() {
        if (logFile.isFile()) return true;
        try {
            File parent = logFile.getParentFile();
            if (parent != null) parent.mkdirs();
            StringBuilder content = new StringBuilder();
            for (Violation v : violations) content.append(v).append(System.lineSeparator());
            Files.write(logFile.toPath(), content.toString().getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                    StandardOpenOption.WRITE);
            return logFile.isFile();
        } catch (IOException e) {
            AppLog.warn("Could not rebuild missing log file: " + e.getMessage());
            return false;
        }
    }
    public File getLogFile() { return logFile; }
    public synchronized long getRedFlagCount() {
        long count = 0;
        for (Violation v : violations) if (v.isRedFlag()) count++;
        return count;
    }
}

package com.cheatguard.core;

// OWNER: Rohan — structured event/log records consumed by monitoring and diagnostics.

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Application diagnostics log, used by support tooling and the development team to
 * understand what happened on a machine after the fact.
 *
 * <p>Lines land in {@code <data>\logs\cheatguard-YYYY-MM-DD.log} and the console.
 * The packaged build has no console, so the file is the record. Diagnostics are
 * kept strictly separate from audit material (sealed vaults) and rotate two ways:
 * a day file that grows past the size limit rolls into
 * {@code cheatguard-YYYY-MM-DD.1.log, .2.log, ...} (newest roll has the lowest
 * number, only a few rolls are kept per day), and files older than the age limit
 * are pruned automatically. Every writer failure is swallowed — diagnostics must
 * never break the application that is being diagnosed.
 */
public final class AppLog {

    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final int KEEP_DAYS = 14;
    /** Default rotation size of one day file (system property overrides, see below). */
    private static final String MAX_BYTES_PROPERTY = "cheatguard.logs.max.bytes";
    private static final String ROLL_COUNT_PROPERTY = "cheatguard.logs.roll.count";
    private static final long DEFAULT_MAX_BYTES = 5L * 1024L * 1024L;
    private static final int DEFAULT_ROLLS_PER_DAY = 3;

    private AppLog() {
    }

    /** Route uncaught exceptions (worker threads and the Swing event thread) into the log. */
    public static void installCrashHandlers() {
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) ->
                write("ERROR", "Uncaught exception on thread '" + thread.getName() + "'", throwable));
        // Swing swallows EDT exceptions unless this legacy hook class is present.
        try {
            System.setProperty("sun.awt.exception.handler", EdtHandler.class.getName());
        } catch (Exception ignored) {
        }
    }

    /** Swing event-thread hook; instantiated reflectively by AWT. */
    public static final class EdtHandler {
        public EdtHandler() {
        }

        public void handle(Throwable throwable) {
            write("ERROR", "Exception on the Swing event thread", throwable);
        }
    }

    public static void info(String message) {
        write("INFO", message, null);
    }

    public static void warn(String message) {
        write("WARN", message, null);
    }

    public static void error(String message, Throwable throwable) {
        write("ERROR", message, throwable);
    }

    private static void write(String level, String message, Throwable throwable) {
        String line = LocalDateTime.now().format(STAMP) + " " + level + " " + message;
        if (throwable != null) {
            line += " :: " + throwable.getClass().getName() + ": " + throwable.getMessage();
            StackTraceElement[] stack = throwable.getStackTrace();
            if (stack.length > 0) line += " @ " + stack[0];
        }
        System.err.println(line); // visible in development; the file covers packaged builds
        try {
            File dir = new File(AppPaths.getDataDirectory(), "logs");
            if (!dir.exists()) dir.mkdirs();
            File file = new File(dir, "cheatguard-" + LocalDate.now() + ".log");
            boolean fresh = !file.isFile();
            if (!fresh && file.length() >= maxBytes()) rotate(dir, file);
            Files.writeString(file.toPath(), line + System.lineSeparator(),
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            if (fresh) prune(dir);
        } catch (Exception ignored) {
            // never let diagnostics break the app
        }
    }

    /**
     * Roll the current day file to {@code .1.log} when it reaches the size
     * limit, shifting older rolls down and dropping the ones beyond the
     * per-day roll count. Failures are swallowed like every write failure.
     */
    private static void rotate(File dir, File current) {
        try {
            int rolls = rollCount();
            File lastRoll = new File(dir, current.getName() + "." + rolls + ".log");
            Files.deleteIfExists(lastRoll.toPath());
            for (int i = rolls - 1; i >= 1; i--) {
                File from = new File(dir, current.getName() + "." + i + ".log");
                File to = new File(dir, current.getName() + "." + (i + 1) + ".log");
                if (from.isFile()) {
                    Files.move(from.toPath(), to.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
            }
            Files.move(current.toPath(), new File(dir, current.getName() + ".1.log").toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception ignored) {
            // rotation must never stop the log line from being written
        }
    }

    private static long maxBytes() {
        try {
            return Math.max(1024L, Long.parseLong(System.getProperty(MAX_BYTES_PROPERTY,
                    String.valueOf(DEFAULT_MAX_BYTES))));
        } catch (NumberFormatException e) {
            return DEFAULT_MAX_BYTES;
        }
    }

    private static int rollCount() {
        try {
            return Math.max(1, Integer.parseInt(System.getProperty(ROLL_COUNT_PROPERTY,
                    String.valueOf(DEFAULT_ROLLS_PER_DAY))));
        } catch (NumberFormatException e) {
            return DEFAULT_ROLLS_PER_DAY;
        }
    }

    private static void prune(File dir) {
        File[] files = dir.listFiles((d, name) -> name.startsWith("cheatguard-") && name.endsWith(".log"));
        if (files == null) return;
        long cutoff = System.currentTimeMillis() - KEEP_DAYS * 24L * 3_600_000L;
        for (File f : files) {
            if (f.lastModified() < cutoff) {
                try {
                    Files.deleteIfExists(f.toPath());
                } catch (Exception ignored) {
                }
            }
        }
    }
}

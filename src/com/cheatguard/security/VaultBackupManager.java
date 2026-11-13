package com.cheatguard.security;

// OWNER: Muhit — encrypted vault backup rotation and retention.

import com.cheatguard.config.AppConfig;
import com.cheatguard.config.AppPaths;
import com.cheatguard.core.AppLog;

import java.io.File;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Automatic backups of SEALED vault files (".vault" plus its ".vault.sig"
 * signature) into a dedicated protected backup directory.
 *
 * <p>Only ever encrypted material is copied - a plaintext ".dat" session log
 * is rejected, so no unsealed exam data can reach the backup folder. Each
 * copy is written to a temporary file first and moved into place atomically,
 * so an interrupted run (power cut, disk full) can never leave a half-written
 * backup that looks complete. Interrupted leftovers (".part-" files) are
 * cleaned up on the next run. Retention keeps the newest N backups and those
 * newer than the age limit, and deletes ONLY expired backup files inside the
 * backup directory - never the active vault in the vault directory and never
 * anything else on the machine. Every failure (disk full, permission denied,
 * file locked by a scanner) is logged and swallowed: backups must never crash
 * an exam application.
 */
public final class VaultBackupManager {

    /** Config key: how many newest backups to keep (default 30, 0 = unlimited). */
    public static final String RETENTION_COUNT_CONFIG = "backup.retention.count";
    /** Config key: backup age limit in days (default 90, 0 = no age pruning). */
    public static final String RETENTION_DAYS_CONFIG = "backup.retention.days";

    /** Prefix of the temporary files a copy-in-progress uses (also in tests). */
    public static final String PART_PREFIX = ".part-";
    private static final int DEFAULT_KEEP_COUNT = 30;
    private static final int DEFAULT_KEEP_DAYS = 90;
    /** Partial files younger than this may belong to a backup in progress. */
    private static final long PART_GRACE_MS = 60_000L;

    private final File backupDir;
    private final int keepCount;
    private final long maxAgeMs;

    public VaultBackupManager(File backupDir, int keepCount, int keepDays) {
        this.backupDir = backupDir;
        this.keepCount = Math.max(0, keepCount);
        this.maxAgeMs = keepDays > 0 ? keepDays * 24L * 3_600_000L : 0L;
    }

    /** Manager wired to the app's real backup directory and config values. */
    public static VaultBackupManager createDefault() {
        AppConfig config = AppConfig.getInstance();
        int count = parseInt(config.getConfigValue(RETENTION_COUNT_CONFIG), DEFAULT_KEEP_COUNT);
        int days = parseInt(config.getConfigValue(RETENTION_DAYS_CONFIG), DEFAULT_KEEP_DAYS);
        return new VaultBackupManager(AppPaths.getBackupDirectory(), count, days);
    }

    /**
     * Copy a sealed vault and its signature into the backup directory and
     * prune expired backups. Returns false (and logs) on any failure; never
     * throws, never touches the source files.
     */
    public boolean backupVault(File vaultFile) {
        if (vaultFile == null || !vaultFile.getName().toLowerCase().endsWith(".vault")) {
            AppLog.warn("Backup refused: only sealed .vault files are backed up, not "
                    + (vaultFile == null ? "nothing" : vaultFile.getName()));
            return false;
        }
        if (!vaultFile.isFile()) {
            AppLog.warn("Backup skipped: vault file is missing (" + vaultFile.getName() + ")");
            return false;
        }
        try {
            ensureBackupDir();
        } catch (IOException e) {
            AppLog.warn("Backup failed: could not create backup directory "
                    + backupDir + " - " + e.getMessage());
            return false;
        }
        cleanupInterrupted();
        boolean vaultOk = copyAtomically(vaultFile, new File(backupDir, vaultFile.getName()));
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        boolean sigOk = sigFile.isFile()
                ? copyAtomically(sigFile, new File(backupDir, sigFile.getName()))
                : true; // a legacy vault without a signature still backs up the vault
        if (vaultOk && sigOk) {
            prune();
            return true;
        }
        return false;
    }

    /** Delete ".part-" leftovers from interrupted runs, older than the grace window. */
    void cleanupInterrupted() {
        File[] parts = backupDir.listFiles((d, name) -> name.startsWith(PART_PREFIX));
        if (parts == null) return;
        long cutoff = System.currentTimeMillis() - PART_GRACE_MS;
        for (File part : parts) {
            if (part.lastModified() < cutoff) {
                try {
                    Files.deleteIfExists(part.toPath());
                } catch (IOException e) {
                    AppLog.warn("Could not remove interrupted backup part " + part.getName());
                }
            }
        }
    }

    /**
     * Remove expired backups: beyond the newest {@code keepCount} vault
     * backups, and older than the age limit. Only ".vault" files inside the
     * backup directory are ever considered, and their ".sig" companions go
     * with them. The active vault directory is never touched.
     */
    void prune() {
        File[] vaults = backupDir.listFiles((d, name) -> name.toLowerCase().endsWith(".vault"));
        if (vaults == null || vaults.length == 0) return;
        List<File> byNewest = new ArrayList<>(List.of(vaults));
        byNewest.sort(Comparator.comparingLong(File::lastModified).reversed());
        long ageCutoff = maxAgeMs > 0 ? System.currentTimeMillis() - maxAgeMs : 0L;
        List<File> expired = new ArrayList<>();
        for (int i = 0; i < byNewest.size(); i++) {
            File candidate = byNewest.get(i);
            boolean overCount = keepCount > 0 && i >= keepCount;
            boolean tooOld = ageCutoff > 0 && candidate.lastModified() < ageCutoff;
            if (overCount || tooOld) expired.add(candidate);
        }
        for (File expiredVault : expired) {
            File expiredSig = new File(expiredVault.getAbsolutePath() + ".sig");
            deleteQuietly(expiredVault);
            deleteQuietly(expiredSig);
        }
    }

    private void deleteQuietly(File file) {
        try {
            Files.deleteIfExists(file.toPath());
        } catch (IOException e) {
            AppLog.warn("Could not prune expired backup " + file.getName() + " - "
                    + e.getMessage());
        }
    }

    private void ensureBackupDir() throws IOException {
        if (!backupDir.isDirectory() && !backupDir.mkdirs() && !backupDir.isDirectory()) {
            throw new IOException("directory could not be created");
        }
    }

    /**
     * Copy into a uniquely named temporary file in the backup directory, then
     * atomically move it over the destination. A crash mid-copy leaves only a
     * ".part-" file behind, never a truncated "real" backup.
     */
    private boolean copyAtomically(File source, File destination) {
        Path temp = null;
        try {
            temp = Files.createTempFile(backupDir.toPath(), PART_PREFIX, ".tmp");
            Files.copy(source.toPath(), temp, StandardCopyOption.REPLACE_EXISTING);
            moveAtomically(temp, destination.toPath());
            return true;
        } catch (IOException e) {
            AppLog.warn("Backup of " + source.getName() + " failed - " + e.getMessage());
            return false;
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                }
            }
        }
    }

    private static void moveAtomically(Path temp, Path destination) throws IOException {
        try {
            Files.move(temp, destination, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temp, destination, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) return fallback;
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}

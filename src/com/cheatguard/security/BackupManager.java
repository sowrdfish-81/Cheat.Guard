package com.cheatguard.security;

// Muhit: sealed logs -> protected rotating backups -> recovery workflow.

// OWNER: Muhit — secure backup and recovery lifecycle.

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;

/** Creates recoverable copies of sealed logs without ever copying plaintext logs. */
public final class BackupManager {
    private static final int MAX_BACKUPS = 30;

    private BackupManager() {
    }

    public static void backupSealedPair(File vaultFile, File signatureFile) {
        if (vaultFile == null || !vaultFile.isFile()) return;
        try {
            File dir = new File(AppPaths.getDataDirectory(), "backups");
            if (!dir.exists() && !dir.mkdirs()) return;
            String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss-SSS").format(new Date());
            File backupVault = new File(dir, vaultFile.getName() + "." + stamp + ".bak");
            Files.copy(vaultFile.toPath(), backupVault.toPath(), StandardCopyOption.COPY_ATTRIBUTES);
            if (signatureFile != null && signatureFile.isFile()) {
                File backupSig = new File(dir, signatureFile.getName() + "." + stamp + ".bak");
                Files.copy(signatureFile.toPath(), backupSig.toPath(), StandardCopyOption.COPY_ATTRIBUTES);
            }
            prune(dir);
        } catch (Exception e) {
            // A backup failure must never prevent a session from being sealed.
            com.cheatguard.core.AppLog.warn("Sealed-log backup failed: " + e.getMessage());
        }
    }

    private static void prune(File dir) {
        File[] files = dir.listFiles((d, name) -> name.endsWith(".bak"));
        if (files == null || files.length <= MAX_BACKUPS * 2) return;
        Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
        for (int i = MAX_BACKUPS * 2; i < files.length; i++) {
            try { Files.deleteIfExists(files[i].toPath()); }
            catch (Exception ignored) { }
        }
    }
}

package com.cheatguard.security;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;

/**
 * Encryption/tamper facade for sealed logs plus admin-gated access/deletion.
 *
 * <p>Every method takes the administrator password as a {@code char[]} and wipes
 * its working copy before returning, so the plaintext password does not outlive
 * the call in a String or a leaked buffer.
 */
public class SecurityVault {
    private final FileLockManager lockManager = new FileLockManager();
    private final AesEncryptor encryptor = new AesEncryptor();
    private final Sha256Signer signer = new Sha256Signer();
    private final AdminAuth adminAuth;

    public SecurityVault(AdminAuth adminAuth) { this.adminAuth = adminAuth; }

    public boolean beginProtection(File plaintextLogFile) { return lockManager.lockFile(plaintextLogFile); }

    /** Release an in-progress log lock when session startup is rolled back. */
    public void abortProtection() { lockManager.releaseLock(); }

    public void sealVault(File plaintextLogFile, char[] adminPassword) throws Exception {
        lockManager.releaseLock();
        seal(plaintextLogFile, adminPassword);
    }

    /**
     * Seals an unsealed .dat left behind by a force-stopped session (power cut,
     * crash, task kill). Same protection as a normal seal; the dashboard offers
     * this so interrupted sessions still end up as tamper-evident vaults.
     */
    public void sealExisting(File plaintextLogFile, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (plaintextLogFile == null || !plaintextLogFile.getName().toLowerCase().endsWith(".dat")) {
            throw new IllegalArgumentException("Select an unsealed session log (.dat).");
        }
        seal(plaintextLogFile, adminPassword);
    }

    private void seal(File plaintextLogFile, char[] adminPassword) throws Exception {
        if (!plaintextLogFile.exists()) throw new IllegalStateException("Session log file is missing.");

        String name = plaintextLogFile.getName();
        String lower = name.toLowerCase();
        // .dat is accepted case-insensitively above, so derive the vault name the
        // same way; a case-sensitive replace on SESSION.DAT would make vaultFile
        // the plaintext file itself and the delete below would destroy the log.
        File vaultFile = lower.endsWith(".dat")
                ? new File(plaintextLogFile.getParent(), name.substring(0, name.length() - 4) + ".vault")
                : new File(plaintextLogFile.getParent(), name + ".vault");
        if (vaultFile.getCanonicalFile().equals(plaintextLogFile.getCanonicalFile())) {
            throw new IllegalStateException("Refusing to seal: vault path equals the plaintext log path.");
        }
        // Windows Defender/indexing can briefly hold either file immediately
        // after the final audit row is written.  A single failed encryption
        // used to make every normal End Session look like a permanent seal
        // failure.  Retry only this filesystem stage; password/authentication
        // errors still propagate normally.
        Exception last = null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                // A previous interrupted seal may have left a protected partial
                // vault/signature behind. Ordinary delete then reports
                // ERROR_ACCESS_DENIED and every retry fails forever; remove only
                // this session's incomplete pair through the same elevated path
                // used by the dashboard.
                if (vaultFile.exists() || new File(vaultFile.getAbsolutePath() + ".sig").exists()) {
                    File partialSig = new File(vaultFile.getAbsolutePath() + ".sig");
                    if (!vaultFile.delete() && vaultFile.exists()
                            || !partialSig.delete() && partialSig.exists()) {
                        if (!LogProtection.deleteElevated(java.util.List.of(vaultFile, partialSig))) {
                            throw new java.io.IOException("Windows denied cleanup of a previous partial seal.");
                        }
                    }
                }
                encryptor.encryptFile(plaintextLogFile, vaultFile, adminPassword);
                last = null;
                break;
            } catch (java.io.IOException e) {
                last = e;
                try { Files.deleteIfExists(vaultFile.toPath()); } catch (Exception ignored) {}
                if (attempt < 2) {
                    try { Thread.sleep(120L * (attempt + 1)); }
                    catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        throw interrupted;
                    }
                }
            }
        }
        if (last != null) throw last;
        String signature = AesEncryptor.isAuthenticatedFormat(vaultFile)
                ? "gcm-v2"
                : signer.generateSignature(vaultFile);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        try (FileWriter fw = new FileWriter(sigFile)) { fw.write(signature); }

        if (!plaintextLogFile.delete() && plaintextLogFile.exists()) {
            if (!LogProtection.deleteElevated(java.util.List.of(plaintextLogFile))
                    && plaintextLogFile.exists()) {
                plaintextLogFile.deleteOnExit();
            }
        }
        hideFile(vaultFile);
        hideFile(sigFile);
        BackupManager.backupSealedPair(vaultFile, sigFile);
    }

    /** Opens a sealed .vault or an unsealed .dat left by a forced termination. */
    public String openLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null || !file.exists()) throw new IllegalArgumentException("Log file does not exist.");
        if (file.getName().toLowerCase().endsWith(".dat")) {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        }
        return openVault(file, adminPassword);
    }

    public String openVault(File vaultFile, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        File sigFile = new File(vaultFile.getAbsolutePath() + ".sig");
        if (!sigFile.exists()) throw new SecurityException("Signature file is missing.");
        String expectedSig = new String(Files.readAllBytes(sigFile.toPath()), StandardCharsets.UTF_8).trim();
        boolean authenticated = "gcm-v2".equals(expectedSig)
                && AesEncryptor.isAuthenticatedFormat(vaultFile);
        if (!authenticated && !signer.verify(vaultFile, expectedSig)) {
            throw new SecurityException("WARNING: log signature mismatch; file may have been tampered with.");
        }
        byte[] plain = encryptor.decryptFile(vaultFile, adminPassword);
        String content = new String(plain, StandardCharsets.UTF_8);
        Arrays.fill(plain, (byte) 0);
        return content;
    }

    /** Re-seal every vault readable with the old password using the new password. */
    public int reencryptVaults(char[] oldPassword, char[] newPassword) throws Exception {
        File dir = com.cheatguard.config.AppPaths.getVaultDirectory();
        File[] vaults = dir.listFiles((d, name) -> name.toLowerCase().endsWith(".vault"));
        if (vaults == null) return 0;
        int converted = 0;
        for (File vault : vaults) {
            byte[] plain;
            try { plain = encryptor.decryptFile(vault, oldPassword); }
            catch (Exception ignored) { continue; }
            File staged = new File(vault.getAbsolutePath() + ".new");
            File plainStaged = File.createTempFile("cg-reseal", ".dat", dir);
            try {
                Files.write(plainStaged.toPath(), plain);
                encryptor.encryptFile(plainStaged, staged, newPassword);
                File sig = new File(vault.getAbsolutePath() + ".sig");
                // Sealed pairs are intentionally not deletable by the desktop
                // account. Re-keying is an administrator operation, so use the
                // same single elevated delete path as the dashboard instead of
                // failing with Windows "Access is denied".
                if (vault.exists() || sig.exists()) {
                    if (!LogProtection.deleteElevated(java.util.List.of(vault, sig))) {
                        throw new IllegalStateException("Windows did not grant permission to replace " + vault.getName());
                    }
                }
                if (!staged.renameTo(vault))
                    throw new IllegalStateException("Could not replace vault " + vault.getName());
                try (FileWriter fw = new FileWriter(sig)) { fw.write("gcm-v2"); }
                hideFile(vault); hideFile(sig); converted++;
            } finally {
                Arrays.fill(plain, (byte) 0);
                plainStaged.delete(); staged.delete();
            }
        }
        return converted;
    }

    /**
     * Delete a session log after checking the administrator password.
     *
     * <p>Sealed logs are owned by the Administrators group and are read-only for the
     * desktop account, so an ordinary delete is refused by Windows — that is exactly
     * what stops them being removed from Explorer. When the plain delete fails, the
     * request is repeated through an elevated helper, so deleting a log needs both the
     * administrator password here and a Windows permission prompt.
     */
    public void deleteLog(File file, char[] adminPassword) throws Exception {
        requireAdmin(adminPassword);
        if (file == null) return;

        java.util.List<File> targets = new java.util.ArrayList<>();
        targets.add(file);
        if (file.getName().toLowerCase().endsWith(".vault")) {
            File sig = new File(file.getAbsolutePath() + ".sig");
            if (sig.exists()) targets.add(sig);
        }

        boolean allGone = true;
        for (File target : targets) {
            if (target.exists() && !target.delete()) allGone = false;
        }
        if (allGone) return;

        if (!LogProtection.deleteElevated(targets)) {
            throw new IllegalStateException(
                    "Windows did not grant permission to delete this protected log.");
        }
        for (File target : targets) {
            if (target.exists()) {
                throw new IllegalStateException("The protected log could not be deleted.");
            }
        }
    }

    private void requireAdmin(char[] password) {
        // check() wipes the array it is given, so it must receive a copy - the
        // caller's array is still needed unchanged for the actual encryption.
        char[] probe = password == null ? new char[0] : password.clone();
        if (!adminAuth.check(probe).success()) {
            throw new SecurityException("Incorrect admin password.");
        }
    }

    private void hideFile(File file) {
        try {
            new ProcessBuilder("attrib", "+h", file.getAbsolutePath()).start().waitFor();
        } catch (Exception ignored) {
        }
    }
}

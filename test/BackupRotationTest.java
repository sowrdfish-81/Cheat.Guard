import com.cheatguard.core.AppLog;
import com.cheatguard.security.AesEncryptor;
import com.cheatguard.security.VaultBackupManager;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Headless tests for sealed-vault backup, retention pruning, interrupted-backup
 * recovery and diagnostic log rotation, in the same plain-main style as
 * CoreFlowTest.
 *
 * Run with an isolated {@code -Dcheatguard.data.dir=<fresh temp dir>} so the
 * developer's own vaults and logs are never touched.
 */
public class BackupRotationTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("== BackupRotationTest ==");
        System.out.println("Isolated data dir: "
                + com.cheatguard.config.AppPaths.getDataDirectory());

        checkBackupCreationAndIntegrity();
        checkPlaintextRefused();
        checkDuplicateSafe();
        checkRetentionByCount();
        checkRetentionByAge();
        checkActiveVaultNeverDeleted();
        checkInterruptedBackupRecovery();
        checkMissingSourceFailsSoftly();
        checkDiagnosticLogRotation();

        System.out.println();
        if (failures == 0) {
            System.out.println("ALL CHECKS PASSED");
        } else {
            System.out.println(failures + " CHECK(S) FAILED");
            System.exit(1);
        }
    }

    // ------------------------------------------------------------- backup ----

    private static void checkBackupCreationAndIntegrity() throws Exception {
        section("Backup creation and integrity (decrypt from the backup copy)");
        File work = tempDir("cgbt-work");
        File backups = tempDir("cgbt-backups");
        VaultBackupManager manager = new VaultBackupManager(backups, 10, 0);

        File plain = new File(work, "CSE101_Student42_20261019_090000.dat");
        Files.writeString(plain.toPath(), "audit line 1\naudit line 2\n", StandardCharsets.UTF_8);
        char[] password = "BackupTest#2026".toCharArray();
        AesEncryptor crypto = new AesEncryptor();
        File vault = new File(work, "CSE101_Student42_20261019_090000.vault");
        crypto.encryptFile(plain, vault, password.clone());
        File sig = new File(vault.getAbsolutePath() + ".sig");
        Files.writeString(sig.toPath(), "gcm-v2", StandardCharsets.UTF_8);

        expect("backup reported success", manager.backupVault(vault));
        File backedVault = new File(backups, vault.getName());
        File backedSig = new File(backups, sig.getName());
        expect("vault copy exists in the backup directory", backedVault.isFile());
        expect("signature copy exists in the backup directory", backedSig.isFile());
        expect("backup bytes are identical to the sealed vault",
                Arrays.equals(Files.readAllBytes(vault.toPath()),
                        Files.readAllBytes(backedVault.toPath())));
        String restored = new String(
                crypto.decryptFile(backedVault, password.clone()), StandardCharsets.UTF_8);
        expect("backup copy decrypts to the original audit content",
                restored.contains("audit line 1") && restored.contains("audit line 2"));
    }

    private static void checkPlaintextRefused() throws Exception {
        section("Plaintext session logs are never backed up");
        File work = tempDir("cgbt-plain");
        File backups = tempDir("cgbt-plain-backups");
        VaultBackupManager manager = new VaultBackupManager(backups, 10, 0);
        File plaintext = new File(work, "session.dat");
        Files.writeString(plaintext.toPath(), "UNSEALED AUDIT DATA", StandardCharsets.UTF_8);
        expect("a .dat plaintext file is refused", !manager.backupVault(plaintext));
        expect("backup directory stays empty", backups.listFiles().length == 0);
        expect("null input is refused without crashing", !manager.backupVault(null));
    }

    private static void checkDuplicateSafe() throws Exception {
        section("Duplicate-safe behavior (idempotent re-backup)");
        File work = tempDir("cgbt-dup");
        File backups = tempDir("cgbt-dup-backups");
        VaultBackupManager manager = new VaultBackupManager(backups, 10, 0);
        File vault = sealedVault(work, "dup.vault", "same content");
        expect("first backup succeeds", manager.backupVault(vault));
        byte[] first = Files.readAllBytes(new File(backups, "dup.vault").toPath());
        expect("second backup succeeds", manager.backupVault(vault));
        expect("no duplicate copies accumulated", backups.listFiles().length == 2);
        expect("second backup replaced the first byte-identically",
                Arrays.equals(first, Files.readAllBytes(new File(backups, "dup.vault").toPath())));
        expect("no interrupted-copy leftovers remain", noPartFiles(backups));
    }

    private static void checkRetentionByCount() throws Exception {
        section("Retention pruning by count");
        File work = tempDir("cgbt-count");
        File backups = tempDir("cgbt-count-backups");
        VaultBackupManager manager = new VaultBackupManager(backups, 3, 0);
        List<File> vaults = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            File v = sealedVault(work, "v" + i + ".vault", "vault " + i);
            // ensure distinct, increasing modification times
            v.setLastModified(System.currentTimeMillis() - (6 - i) * 10_000L);
            vaults.add(v);
            manager.backupVault(v);
        }
        List<File> remaining = vaultFiles(backups);
        expect("only the newest 3 vault backups remain", remaining.size() == 3);
        expect("v5.vault (newest) survived", hasFile(backups, "v5.vault"));
        expect("v4.vault survived", hasFile(backups, "v4.vault"));
        expect("v3.vault survived", hasFile(backups, "v3.vault"));
        expect("oldest copies pruned", !hasFile(backups, "v1.vault") && !hasFile(backups, "v2.vault"));
        expect("signatures pruned with their vaults",
                !hasFile(backups, "v1.vault.sig") && !hasFile(backups, "v2.vault.sig")
                        && hasFile(backups, "v3.vault.sig") && hasFile(backups, "v5.vault.sig"));
    }

    private static void checkRetentionByAge() throws Exception {
        section("Retention pruning by age");
        File work = tempDir("cgbt-age");
        File backups = tempDir("cgbt-age-backups");
        VaultBackupManager manager = new VaultBackupManager(backups, 0, 1);
        File old = sealedVault(work, "old.vault", "old");
        File recent = sealedVault(work, "recent.vault", "recent");
        expect("old backup succeeds", manager.backupVault(old));
        expect("recent backup succeeds", manager.backupVault(recent));
        File oldBackup = new File(backups, "old.vault");
        if (!oldBackup.setLastModified(System.currentTimeMillis() - 3L * 24 * 3_600_000L)) {
            expect("could not backdate the old copy for the age test", false);
        }
        manager.backupVault(recent); // any run prunes expired copies
        expect("expired copy removed", !hasFile(backups, "old.vault"));
        expect("fresh copy kept", hasFile(backups, "recent.vault"));
    }

    private static void checkActiveVaultNeverDeleted() throws Exception {
        section("Retention never deletes the active vault");
        File work = tempDir("cgbt-active");
        File backups = tempDir("cgbt-active-backups");
        VaultBackupManager manager = new VaultBackupManager(backups, 1, 0);
        File first = sealedVault(work, "first.vault", "first");
        File second = sealedVault(work, "second.vault", "second");
        manager.backupVault(first);
        manager.backupVault(second); // pushes the first backup out of retention
        expect("pruned backup copy is gone", !hasFile(backups, "first.vault"));
        expect("the ACTIVE vault file still exists", first.isFile());
        expect("the ACTIVE vault signature still exists",
                new File(first.getAbsolutePath() + ".sig").isFile());
        expect("the second active vault still exists", second.isFile());
    }

    private static void checkInterruptedBackupRecovery() throws Exception {
        section("Recovery after an interrupted backup");
        File work = tempDir("cgbt-int");
        File backups = tempDir("cgbt-int-backups");
        VaultBackupManager manager = new VaultBackupManager(backups, 10, 0);
        File stale = new File(backups, VaultBackupManager.PART_PREFIX + "stale.tmp");
        Files.writeString(stale.toPath(), "half-written garbage", StandardCharsets.UTF_8);
        if (!stale.setLastModified(System.currentTimeMillis() - 10 * 60_000L)) {
            expect("could not backdate the stale part file", false);
        }
        File fresh = new File(backups, VaultBackupManager.PART_PREFIX + "fresh.tmp");
        Files.writeString(fresh.toPath(), "copy that may be in flight", StandardCharsets.UTF_8);

        File vault = sealedVault(work, "recover.vault", "recover");
        expect("backup after an interrupted run succeeds", manager.backupVault(vault));
        expect("stale interrupted copy cleaned up", !stale.exists());
        expect("recent in-flight copy is not touched", fresh.exists());
        expect("real backup present alongside the fresh part file",
                hasFile(backups, "recover.vault"));
    }

    private static void checkMissingSourceFailsSoftly() throws Exception {
        section("Backup failures are reported, never thrown");
        File backups = tempDir("cgbt-missing");
        VaultBackupManager manager = new VaultBackupManager(backups, 10, 0);
        expect("missing vault file -> false, no crash",
                !manager.backupVault(new File(backups, "ghost.vault")));
        expect("backup dir without a vault directory -> false, no crash",
                !manager.backupVault(new File(tempDir("cgbt-missing-vaults"), "x.vault")));
    }

    // ----------------------------------------------------------- rotation ----

    private static void checkDiagnosticLogRotation() throws Exception {
        section("Diagnostic log rotation by size (audit logs stay separate)");
        File logsDir = new File(com.cheatguard.config.AppPaths.getDataDirectory(), "logs");
        // Small limit so a handful of writes rolls the file.
        System.setProperty("cheatguard.logs.max.bytes", "2048");
        System.setProperty("cheatguard.logs.roll.count", "2");
        for (int i = 0; i < 120; i++) {
            AppLog.info("rotation-probe line " + i
                    + " with enough padding text to exceed the limit quickly");
        }
        File current = new File(logsDir, "cheatguard-" + java.time.LocalDate.now() + ".log");
        File roll1 = new File(logsDir, current.getName() + ".1.log");
        File roll2 = new File(logsDir, current.getName() + ".2.log");
        File roll3 = new File(logsDir, current.getName() + ".3.log");
        expect("current day file exists and keeps receiving lines", current.isFile());
        expect("first roll created when the size limit was hit", roll1.isFile());
        expect("second roll created after continued writing", roll2.isFile());
        expect("rolls beyond the configured count are dropped", !roll3.isFile());
        expect("rolled file respects the size limit",
                !current.isFile() || current.length() < 8192);
        File vaultDir = com.cheatguard.config.AppPaths.getVaultDirectory();
        expect("audit vaults and diagnostics live in separate directories",
                !vaultDir.getAbsolutePath().equals(logsDir.getAbsolutePath()));
        System.setProperty("cheatguard.logs.max.bytes", "");
        System.setProperty("cheatguard.logs.roll.count", "");
    }

    // ----------------------------------------------------------- helpers ----

    private static File sealedVault(File dir, String name, String content) throws Exception {
        File plain = new File(dir, name.replace(".vault", ".dat"));
        File vault = new File(dir, name);
        Files.writeString(plain.toPath(), content, StandardCharsets.UTF_8);
        new AesEncryptor().encryptFile(plain, vault, "Probe#2026".toCharArray());
        Files.writeString(new File(vault.getAbsolutePath() + ".sig").toPath(), "gcm-v2",
                StandardCharsets.UTF_8);
        plain.delete();
        return vault;
    }

    private static List<File> vaultFiles(File dir) {
        File[] files = dir.listFiles((d, n) -> n.toLowerCase().endsWith(".vault"));
        return files == null ? new ArrayList<>() : new ArrayList<>(Arrays.asList(files));
    }

    private static boolean hasFile(File dir, String name) {
        return new File(dir, name).isFile();
    }

    private static boolean noPartFiles(File dir) {
        File[] parts = dir.listFiles((d, n) -> n.startsWith(VaultBackupManager.PART_PREFIX));
        return parts == null || parts.length == 0;
    }

    private static File tempDir(String prefix) throws Exception {
        File dir = Files.createTempDirectory(prefix).toFile();
        dir.deleteOnExit();
        return dir;
    }

    private static void expect(String label, boolean condition) {
        System.out.println((condition ? "  PASS  " : "  FAIL  ") + label);
        if (!condition) failures++;
    }

    private static void section(String name) {
        System.out.println();
        System.out.println("-- " + name + " --");
    }
}
// QA flow: vault backups + retention policy -> rotation -> recovery-safe result.

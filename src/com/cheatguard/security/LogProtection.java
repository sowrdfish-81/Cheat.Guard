package com.cheatguard.security;

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Keeps sealed session logs out of reach of Windows Explorer.
 *
 * <p>A sealed log is only evidence if it survives. Once a session ends, the
 * elevated helper that is already running for the network lockdown re-owns the
 * {@code .vault} and {@code .vault.sig} files to the Administrators group, drops
 * inherited permissions and leaves the signed-in account with <em>read</em> access
 * only. A student — or anyone using the desktop normally — then cannot delete,
 * rename or edit them: Explorer refuses, and because the account no longer owns the
 * files it cannot grant itself permission back either.
 *
 * <p>Deleting a log stays possible, but only the intended way: through the admin
 * dashboard, after the administrator password, which then asks Windows for elevation.
 *
 * <p>Boundary worth stating: a machine administrator who deliberately elevates can
 * always override file permissions. What this removes is deletion by a standard
 * user, by accident, or by anyone poking around in the folder.
 */
public final class LogProtection {

    private static final String REQUEST = "protect.request";
    private static final String DONE = "protect.done";

    private LogProtection() {
    }

    public static File requestFile() {
        return new File(AppPaths.getNetworkDirectory(), REQUEST);
    }

    public static File doneFile() {
        return new File(AppPaths.getNetworkDirectory(), DONE);
    }

    /**
     * Ask the running elevated helper to protect the given files.
     *
     * <p>Must be called while the session's lockdown helper is still alive, which is
     * why sealing happens before the network state is restored.
     *
     * @return true when the helper confirmed, false if it did not answer in time
     */
    public static boolean protectViaHelper(List<File> files) {
        List<File> existing = new ArrayList<>();
        for (File f : files) {
            if (f != null && f.isFile()) existing.add(f);
        }
        if (existing.isEmpty()) return true;

        try {
            File done = doneFile();
            // A stale done file from an earlier request would make this call
            // return true before the helper has done anything.
            if (done.exists() && !done.delete()) return false;
            StringBuilder sb = new StringBuilder();
            for (File f : existing) sb.append(f.getAbsolutePath()).append(System.lineSeparator());
            // Write to a temp file and move atomically: the helper polls for the
            // request every 500 ms and must never read a half-written file.
            File request = requestFile();
            File staged = new File(request.getParentFile(), REQUEST + ".tmp");
            Files.writeString(staged.toPath(), sb.toString(), StandardCharsets.UTF_8);
            try {
                Files.move(staged.toPath(), request.toPath(),
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception moveFailure) {
                Files.move(staged.toPath(), request.toPath(),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }

            long deadline = System.currentTimeMillis() + 20_000L;
            while (System.currentTimeMillis() < deadline) {
                if (done.exists()) {
                    if (!done.delete()) break; // cannot confirm cleanly
                    return true;
                }
                Thread.sleep(200L);
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
            // fall through: the log is still written, just not permission-hardened
        }
        return false;
    }

    /**
     * Delete protected log files with a single elevation prompt.
     *
     * @return true if Windows accepted the elevated delete request
     */
    public static boolean deleteElevated(List<File> files) {
        List<File> targets = new ArrayList<>();
        for (File f : files) {
            if (f != null && f.exists()) targets.add(f);
        }
        if (targets.isEmpty()) return true;

        Path list = null;
        try {
            StringBuilder sb = new StringBuilder();
            for (File f : targets) sb.append(f.getAbsolutePath()).append(System.lineSeparator());
            list = Files.createTempFile("cheatguard-delete-", ".txt");
            Files.writeString(list, sb.toString(), StandardCharsets.UTF_8);

            // The path list travels in a file so no quoting survives into PowerShell.
            String inner = "$l='" + list.toAbsolutePath().toString().replace("'", "''") + "';"
                    + "foreach($p in Get-Content -LiteralPath $l){"
                    + "if($p.Trim()){"
                    + "takeown /F \"$p\" /A | Out-Null;"
                    + "icacls \"$p\" /grant *S-1-5-32-544:(F) | Out-Null;"
                    + "Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue}};"
                    + "Remove-Item -LiteralPath $l -Force -ErrorAction SilentlyContinue";

            // The inner script travels base64-encoded (-EncodedCommand, UTF-16LE).
            // Nesting it inside a double-quoted outer string cannot work: in
            // PowerShell, backslash escapes nothing, so every \" in the inner
            // script would terminate the outer string and the elevated child
            // would receive a broken script.
            String encoded = Base64.getEncoder().encodeToString(
                    inner.getBytes(StandardCharsets.UTF_16LE));

            String outer = "$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs "
                    + "-WindowStyle Hidden -PassThru -Wait "
                    + "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-EncodedCommand','" + encoded + "';"
                    + "if($null -eq $p){ throw 'not started' }"
                    + "exit $p.ExitCode;";

            // Hidden on both hops: the relay waits for the whole elevated run, and
            // an elevated console popping up over the dashboard looked broken.
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile",
                    "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", outer)
                    .redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            return false;
        } finally {
            if (list != null) {
                try {
                    Files.deleteIfExists(list);
                } catch (Exception ignored) {
                    // the elevated step removes it as well
                }
            }
        }
    }

    /** Protect an already-sealed log when no live exam helper remains. */
    public static boolean protectElevated(List<File> files) {
        List<File> targets = new ArrayList<>();
        for (File f : files) if (f != null && f.isFile()) targets.add(f);
        if (targets.isEmpty()) return true;
        Path list = null;
        try {
            StringBuilder sb = new StringBuilder();
            for (File f : targets) sb.append(f.getAbsolutePath()).append(System.lineSeparator());
            list = Files.createTempFile("cheatguard-protect-", ".txt");
            Files.writeString(list, sb.toString(), StandardCharsets.UTF_8);
            String inner = "$ok=$true; foreach($p in Get-Content -LiteralPath '"
                    + list.toAbsolutePath().toString().replace("'", "''") + "'){"
                    + "if($p.Trim()){ takeown /F \"$p\" /A | Out-Null; if($LASTEXITCODE -ne 0){$ok=$false};"
                    + "icacls \"$p\" /inheritance:r | Out-Null; if($LASTEXITCODE -ne 0){$ok=$false};"
                    + "icacls \"$p\" /grant '*S-1-5-32-544:(F)' | Out-Null; if($LASTEXITCODE -ne 0){$ok=$false};"
                    + "icacls \"$p\" /grant '*S-1-5-18:(F)' | Out-Null; if($LASTEXITCODE -ne 0){$ok=$false};"
                    + "icacls \"$p\" /grant '*S-1-5-32-545:(R)' | Out-Null; if($LASTEXITCODE -ne 0){$ok=$false}}};"
                    + "Remove-Item -LiteralPath '" + list.toAbsolutePath().toString().replace("'", "''")
                    + "' -Force -ErrorAction SilentlyContinue; if(-not $ok){exit 1}";
            String encoded = Base64.getEncoder().encodeToString(inner.getBytes(StandardCharsets.UTF_16LE));
            String outer = "$p=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Hidden -PassThru -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-EncodedCommand','"
                    + encoded + "'; if($null -eq $p){exit 1}; exit $p.ExitCode";
            Process p = new ProcessBuilder("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                    "-WindowStyle", "Hidden", "-Command", outer).redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(120, java.util.concurrent.TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        } finally {
            if (list != null) try { Files.deleteIfExists(list); } catch (Exception ignored) {}
        }
    }
}

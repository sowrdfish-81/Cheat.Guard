package com.cheatguard.security;

// OWNER: Muhit — single-instance and duplicate-process protection.

import com.cheatguard.config.AppPaths;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.List;

/** Prevents two Cheat.Guard processes from running at the same time. */
public final class InstanceGuard {
    private final List<RandomAccessFile> rafs = new ArrayList<>();
    private final List<FileChannel> channels = new ArrayList<>();
    private final List<FileLock> locks = new ArrayList<>();

    public boolean acquire() {
        try {
            List<File> lockFiles = new ArrayList<>();
            lockFiles.add(new File(AppPaths.getDataDirectory(), "instance.lock"));
            // Older installed builds used the per-user location. Lock it too so
            // an old and a new executable cannot run side by side during upgrade.
            String localAppData = System.getenv("LOCALAPPDATA");
            if (localAppData != null && !localAppData.isBlank()) {
                File legacy = new File(new File(localAppData, "CheatGuard"), "instance.lock");
                if (!lockFiles.get(0).getAbsoluteFile().equals(legacy.getAbsoluteFile())) {
                    lockFiles.add(legacy);
                }
            }
            for (File f : lockFiles) {
                File parent = f.getParentFile();
                if (parent != null && !parent.exists()) parent.mkdirs();
                RandomAccessFile file = new RandomAccessFile(f, "rw");
                FileChannel ch = file.getChannel();
                FileLock acquired = ch.tryLock();
                if (acquired == null) {
                    close();
                    return false;
                }
                rafs.add(file);
                channels.add(ch);
                locks.add(acquired);
            }
            return true;
        } catch (Exception e) {
            close();
            return false;
        }
    }

    public void close() {
        for (FileLock lock : locks) {
            try { if (lock != null && lock.isValid()) lock.release(); } catch (Exception ignored) {}
        }
        for (FileChannel channel : channels) {
            try { if (channel != null && channel.isOpen()) channel.close(); } catch (Exception ignored) {}
        }
        for (RandomAccessFile raf : rafs) {
            try { if (raf != null) raf.close(); } catch (Exception ignored) {}
        }
        locks.clear();
        channels.clear();
        rafs.clear();
    }
}

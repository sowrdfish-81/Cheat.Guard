package com.cheatguard.security;

// OWNER: Muhit — checksum/signature verification for protected artifacts.

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Sha256Signer: computes a SHA-256 "fingerprint" (hash) from a file's content.
 * The hash is saved in a separate .sig file (Layer 3 of the vault).
 *
 * Why it matters: if anyone tries to edit the encrypted log file directly
 * (tamper), the hash will not match -> the instructor dashboard will know
 * the log was tampered with.
 */
public class Sha256Signer {

    public String generateSignature(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * @return true if the file's current hash matches the saved signature
     *         (i.e. the file was not tampered with)
     */
    public boolean verify(File file, String expectedSignature) throws IOException, NoSuchAlgorithmException {
        String actual = generateSignature(file);
        return actual.equalsIgnoreCase(expectedSignature);
    }
}

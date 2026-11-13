package com.cheatguard.security;

// Muhit: vault bytes/key material -> authenticated encrypted data.

// OWNER: Muhit — authenticated encryption primitives for protected records.

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * AES-256 encryption for sealed session logs (vault layer 2).
 *
 * <p>The administrator password is never used as a key directly. A 256-bit key is
 * derived with PBKDF2-HMAC-SHA256 using a random per-file salt and a high
 * iteration count, so two vaults sealed with the same password produce unrelated
 * keys and no precomputed table can be reused across files or installations.
 *
 * <p>The password travels as a {@code char[]} and is wiped from the key-spec as
 * soon as the key is derived; it is never held in a String, whose contents would
 * live in memory for an uncontrolled time.
 *
 * <p>New files use authenticated AES-GCM: {@code [CGV2][16-byte salt][12-byte nonce][ciphertext+tag]}.
 * Legacy CBC files remain readable for migration.
 */
public class AesEncryptor {

    private static final String LEGACY_ALGO = "AES/CBC/PKCS5Padding";
    private static final String GCM_ALGO = "AES/GCM/NoPadding";
    private static final byte[] GCM_MAGIC = new byte[] {'C', 'G', 'V', '2'};
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int ITERATIONS = 210_000;

    private SecretKeySpec deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    /** Read the plaintext log and write the encrypted vault file. */
    public void encryptFile(File plainFile, File encryptedOutFile, char[] password) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(salt);
        random.nextBytes(nonce);

        SecretKeySpec key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance(GCM_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] encrypted = cipher.doFinal(readAllBytes(plainFile));

        try (FileOutputStream fos = new FileOutputStream(encryptedOutFile)) {
            fos.write(GCM_MAGIC);
            fos.write(salt);
            fos.write(nonce);
            fos.write(encrypted);
        }
    }

    public static boolean isAuthenticatedFormat(File encryptedFile) throws IOException {
        try (InputStream in = new FileInputStream(encryptedFile)) {
            byte[] magic = in.readNBytes(GCM_MAGIC.length);
            return Arrays.equals(magic, GCM_MAGIC);
        }
    }

    public byte[] decryptFile(File encryptedFile, char[] password) throws Exception {
        byte[] fileBytes = readAllBytes(encryptedFile);
        if (hasMagic(fileBytes)) {
            return decryptGcm(fileBytes, password);
        }
        return decryptLegacyCbc(fileBytes, password);
    }

    private byte[] decryptGcm(byte[] fileBytes, char[] password) throws Exception {
        int header = GCM_MAGIC.length + SALT_BYTES + NONCE_BYTES;
        // A legitimately empty plaintext is exactly header + 16 (nonce + tag);
        // "<=" would make such a vault impossible to ever open again.
        if (fileBytes.length < header + 16) {
            throw new IllegalStateException("Vault file is truncated or not a Cheat.Guard vault.");
        }
        byte[] salt = Arrays.copyOfRange(fileBytes, GCM_MAGIC.length, GCM_MAGIC.length + SALT_BYTES);
        byte[] nonce = Arrays.copyOfRange(fileBytes, GCM_MAGIC.length + SALT_BYTES, header);
        byte[] cipherText = Arrays.copyOfRange(fileBytes, header, fileBytes.length);
        Cipher cipher = Cipher.getInstance(GCM_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(cipherText);
    }

    private byte[] decryptLegacyCbc(byte[] fileBytes, char[] password) throws Exception {
        int header = SALT_BYTES + IV_BYTES;
        if (fileBytes.length <= header) {
            throw new IllegalStateException("Vault file is truncated or not a Cheat.Guard vault.");
        }
        byte[] salt = new byte[SALT_BYTES];
        byte[] iv = new byte[IV_BYTES];
        System.arraycopy(fileBytes, 0, salt, 0, SALT_BYTES);
        System.arraycopy(fileBytes, SALT_BYTES, iv, 0, IV_BYTES);

        byte[] cipherText = new byte[fileBytes.length - header];
        System.arraycopy(fileBytes, header, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance(LEGACY_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    private static boolean hasMagic(byte[] data) {
        return data.length >= GCM_MAGIC.length
                && Arrays.equals(Arrays.copyOf(data, GCM_MAGIC.length), GCM_MAGIC);
    }

    private byte[] readAllBytes(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                bos.write(buffer, 0, read);
            }
            return bos.toByteArray();
        }
    }
}

import com.cheatguard.security.AesEncryptor;
import com.cheatguard.watchdog.CentralAuth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class SecurityUpgradeTest {
    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("cheatguard-security-test");
        Path plain = dir.resolve("session.dat");
        Path vault = dir.resolve("session.vault");
        Files.writeString(plain, "tamper-evident session", StandardCharsets.UTF_8);
        char[] password = "correct horse battery staple".toCharArray();
        AesEncryptor crypto = new AesEncryptor();
        crypto.encryptFile(plain.toFile(), vault.toFile(), password);
        if (!AesEncryptor.isAuthenticatedFormat(vault.toFile())) throw new AssertionError("GCM header missing");
        if (!"tamper-evident session".equals(new String(crypto.decryptFile(vault.toFile(), password), StandardCharsets.UTF_8))) {
            throw new AssertionError("GCM round trip failed");
        }
        byte[] bytes = Files.readAllBytes(vault);
        bytes[bytes.length - 1] ^= 1;
        Files.write(vault, bytes);
        boolean rejected = false;
        try { crypto.decryptFile(vault.toFile(), password); } catch (Exception expected) { rejected = true; }
        if (!rejected) throw new AssertionError("GCM tamper was accepted");

        String nonce = CentralAuth.newNonce();
        String response = CentralAuth.response("1234567890", nonce, "PC", "S1", "CS");
        if (!CentralAuth.constantTimeEquals(response, CentralAuth.response("1234567890", nonce, "PC", "S1", "CS"))) {
            throw new AssertionError("HMAC response did not reproduce");
        }
        if (CentralAuth.constantTimeEquals(response, CentralAuth.response("0000000000", nonce, "PC", "S1", "CS"))) {
            throw new AssertionError("HMAC accepted the wrong exam code");
        }
        System.out.println("PASS security upgrade tests");
    }
}
// QA flow: legacy security data -> migration/validation -> compatible result.

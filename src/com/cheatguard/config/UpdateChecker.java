package com.cheatguard.config;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.IntConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Checks GitHub for, and securely downloads, the official Cheat.Guard installer. */
public final class UpdateChecker {

    public static final String CURRENT_VERSION = "1.9.23";
    private static final String OWNER = "sowrdfish-81";
    private static final String REPOSITORY = "CheatGuard-Central";
    private static final String RELEASES_API =
            "https://api.github.com/repos/" + OWNER + "/" + REPOSITORY + "/releases/latest";
    private static final String INSTALLER_NAME = "CheatGuardCentral-Setup.exe";
    private static final String CHECKSUM_NAME = INSTALLER_NAME + ".sha256";
    private static final long MAX_INSTALLER_BYTES = 512L * 1024L * 1024L;
    private static final int MAX_API_BYTES = 2 * 1024 * 1024;
    private static final int MAX_CHECKSUM_BYTES = 16 * 1024;
    private static final int MAX_REDIRECTS = 5;
    private static final Pattern SHA256_LINE = Pattern.compile(
            "(?is)^\\s*([0-9a-f]{64})(?:\\s+.*)?\\s*$");

    /** A newer release. The two-argument constructor preserves the old API. */
    public record UpdateInfo(String version, String downloadUrl, String checksumUrl, long size) {
        public UpdateInfo(String version, String downloadUrl) {
            this(version, downloadUrl, null, -1L);
        }
    }

    /** Ask GitHub which release is latest. Network and malformed responses are treated as no update. */
    public static Optional<UpdateInfo> checkLatest() {
        return checkLatestAgainst(CURRENT_VERSION);
    }

    /** Same check against an arbitrary version; package-visible for focused tests. */
    static Optional<UpdateInfo> checkLatestAgainst(String currentVersion) {
        HttpURLConnection connection = null;
        try {
            connection = openConnection(URI.create(RELEASES_API).toURL(), null);
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) return Optional.empty();
            String body = readText(connection, MAX_API_BYTES);
            return parseReleaseJson(body, currentVersion);
        } catch (Exception ignored) {
            return Optional.empty();
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /**
     * Parses the GitHub release response, selecting only the exact installer and
     * companion checksum asset names. Package-visible for deterministic tests.
     */
    static Optional<UpdateInfo> parseReleaseJson(String json, String currentVersion) {
        try {
            Object parsed = new JsonParser(json).parse();
            if (!(parsed instanceof Map<?, ?> root)) return Optional.empty();
            String tag = stringValue(root.get("tag_name"));
            if (tag == null) return Optional.empty();
            String version = normalizeVersion(tag);
            if (version == null || compareVersions(version, currentVersion) <= 0) return Optional.empty();

            Object assetsValue = root.get("assets");
            if (!(assetsValue instanceof List<?> assets)) return Optional.empty();
            Map<?, ?> installer = null;
            Map<?, ?> checksum = null;
            for (Object value : assets) {
                if (!(value instanceof Map<?, ?> asset)) return Optional.empty();
                String name = stringValue(asset.get("name"));
                if (INSTALLER_NAME.equals(name)) {
                    if (installer != null) return Optional.empty();
                    installer = asset;
                } else if (CHECKSUM_NAME.equals(name)) {
                    if (checksum != null) return Optional.empty();
                    checksum = asset;
                }
            }
            if (installer == null || checksum == null) return Optional.empty();

            String installerUrl = stringValue(installer.get("browser_download_url"));
            String checksumUrl = stringValue(checksum.get("browser_download_url"));
            Long size = longValue(installer.get("size"));
            if (installerUrl == null || checksumUrl == null || size == null
                    || size <= 0 || size > MAX_INSTALLER_BYTES) return Optional.empty();
            validateAssetUrl(installerUrl, INSTALLER_NAME);
            validateAssetUrl(checksumUrl, CHECKSUM_NAME);
            return Optional.of(new UpdateInfo(version, installerUrl, checksumUrl, size));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    /**
     * Backward-compatible entry point. It now verifies the companion checksum and
     * atomically replaces {@code dest}; an existing destination is never truncated
     * before all checks pass.
     */
    public static void download(String url, File dest, IntConsumer progress) throws Exception {
        downloadVerified(new UpdateInfo("unknown", url), dest, progress);
    }

    /** Download, verify, and atomically replace the destination with a release asset. */
    public static void downloadVerified(UpdateInfo update, File dest, IntConsumer progress)
            throws Exception {
        Objects.requireNonNull(update, "update");
        Objects.requireNonNull(dest, "dest");
        URL installerUrl = validateAssetUrl(update.downloadUrl(), INSTALLER_NAME);
        String checksumUrlText = update.checksumUrl();
        if (checksumUrlText == null || checksumUrlText.isBlank()) {
            checksumUrlText = companionUrl(installerUrl);
        }
        URL checksumUrl = validateAssetUrl(checksumUrlText, CHECKSUM_NAME);
        long expectedSize = update.size() > 0 ? update.size() : -1L;
        if (expectedSize > MAX_INSTALLER_BYTES) {
            throw new IOException("Installer is larger than the allowed maximum");
        }

        Path destination = dest.toPath().toAbsolutePath().normalize();
        Path parent = destination.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IOException("Update destination directory does not exist");
        }
        String expectedHash = fetchChecksum(checksumUrl);
        Path temporary = Files.createTempFile(parent,
                destination.getFileName().toString() + ".", ".download");
        boolean replaced = false;
        try {
            DownloadResult result = downloadToTemp(installerUrl, temporary, expectedSize, progress);
            if (!MessageDigest.isEqual(result.digest(), hexBytes(expectedHash))) {
                throw new IOException("Installer SHA-256 checksum does not match the release asset");
            }
            atomicReplace(temporary, destination);
            replaced = true;
        } finally {
            if (!replaced) Files.deleteIfExists(temporary);
        }
    }

    /** Background update watcher retained for existing callers. */
    public static void startAutoChecking(Consumer<UpdateInfo> onNew) {
        Objects.requireNonNull(onNew, "onNew");
        ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "CheatGuard-UpdateCheck");
            t.setDaemon(true);
            return t;
        });
        ses.scheduleWithFixedDelay(() -> {
            try {
                Optional<UpdateInfo> info = checkLatest();
                if (info.isPresent()) {
                    ses.shutdown();
                    onNew.accept(info.get());
                }
            } catch (Exception ignored) {
            }
        // Check as soon as the app starts so an available release is shown during
        // the first session, while the daemon thread keeps later retries quiet.
        }, 0, 360, TimeUnit.SECONDS);
    }

    /** Numeric compare of dotted versions ("2.2" vs "3.0"). */
    static int compareVersions(String a, String b) {
        String[] pa = a.split("\\.");
        String[] pb = b.split("\\.");
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int va = part(pa, i);
            int vb = part(pb, i);
            if (va != vb) return Integer.compare(va, vb);
        }
        return 0;
    }

    private static int part(String[] parts, int i) {
        if (i >= parts.length) return 0;
        try {
            return Integer.parseInt(parts[i].trim());
        } catch (Exception e) {
            return 0;
        }
    }

    private static String normalizeVersion(String tag) {
        String version = tag.trim().replaceFirst("(?i)^v", "");
        return version.matches("\\d+(?:\\.\\d+)*") ? version : null;
    }

    private static String stringValue(Object value) {
        return value instanceof String s && !s.isBlank() ? s : null;
    }

    private static Long longValue(Object value) {
        if (!(value instanceof Number number)) return null;
        long valueAsLong = number.longValue();
        return number.doubleValue() == valueAsLong ? valueAsLong : null;
    }

    private static String companionUrl(URL installerUrl) throws IOException {
        try {
            URI uri = installerUrl.toURI();
            String path = uri.getPath();
            if (path == null || !path.endsWith("/" + INSTALLER_NAME)) {
                throw new IOException("Installer URL does not name the expected asset");
            }
            URI companion = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(),
                    path + ".sha256", uri.getQuery(), null);
            return companion.toString();
        } catch (URISyntaxException e) {
            throw new IOException("Invalid installer URL", e);
        }
    }

    private static URL validateAssetUrl(String raw, String expectedName) throws IOException {
        if (raw == null || raw.isBlank()) throw new IOException("Missing release asset URL");
        try {
            URI uri = new URI(raw);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                    || uri.getFragment() != null || (uri.getPort() != -1 && uri.getPort() != 443)) {
                throw new IOException("Release asset is not an HTTPS URL");
            }
            String host = uri.getHost();
            if ("github.com".equalsIgnoreCase(host)) {
                String prefix = "/" + OWNER + "/" + REPOSITORY + "/releases/download/";
                String path = uri.getPath();
                if (path == null || !path.startsWith(prefix) || !path.endsWith("/" + expectedName)
                        || path.substring(prefix.length(), path.length() - expectedName.length() - 1)
                                .isBlank()) {
                    throw new IOException("Release asset is outside the trusted repository");
                }
            } else if (!"release-assets.githubusercontent.com".equalsIgnoreCase(host)
                    && !"objects.githubusercontent.com".equalsIgnoreCase(host)) {
                throw new IOException("Release asset host is not trusted");
            }
            return uri.toURL();
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new IOException("Invalid release asset URL", e);
        }
    }

    private static HttpURLConnection openConnection(URL initial, String expectedName) throws IOException {
        URL current = initial;
        for (int redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
            if (expectedName == null) {
                validateApiUrl(current);
            } else if ("github.com".equalsIgnoreCase(current.getHost())) {
                validateAssetUrl(current.toString(), expectedName);
            } else {
                validateTrustedRedirect(current);
            }
            HttpURLConnection connection = (HttpURLConnection) current.openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(30000);
            connection.setRequestProperty("User-Agent", "CheatGuard-Updater");
            connection.setRequestProperty("Accept", "application/vnd.github+json");
            int status = connection.getResponseCode();
            if (status < 300 || status >= 400) return connection;
            String location = connection.getHeaderField("Location");
            connection.disconnect();
            if (location == null || location.isBlank()) throw new IOException("Redirect has no location");
            try {
                current = current.toURI().resolve(location).toURL();
            } catch (URISyntaxException | IllegalArgumentException e) {
                throw new IOException("Invalid redirect URL", e);
            }
        }
        throw new IOException("Too many redirects");
    }

    private static void validateApiUrl(URL url) throws IOException {
        try {
            URI uri = url.toURI();
            if (!"https".equalsIgnoreCase(uri.getScheme())
                    || !"api.github.com".equalsIgnoreCase(uri.getHost())
                    || uri.getUserInfo() != null || uri.getFragment() != null
                    || (uri.getPort() != -1 && uri.getPort() != 443)
                    || !("/repos/" + OWNER + "/" + REPOSITORY + "/releases/latest")
                            .equals(uri.getPath())) {
                throw new IOException("GitHub API URL is not trusted");
            }
        } catch (URISyntaxException e) {
            throw new IOException("Invalid GitHub API URL", e);
        }
    }

    private static void validateTrustedRedirect(URL url) throws IOException {
        try {
            URI uri = url.toURI();
            String host = uri.getHost();
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                    || uri.getFragment() != null || (uri.getPort() != -1 && uri.getPort() != 443)
                    || (!"github.com".equalsIgnoreCase(host)
                    && !"release-assets.githubusercontent.com".equalsIgnoreCase(host)
                    && !"objects.githubusercontent.com".equalsIgnoreCase(host))) {
                throw new IOException("Redirect target is not trusted");
            }
        } catch (URISyntaxException e) {
            throw new IOException("Invalid redirect URL", e);
        }
    }

    private static String readText(HttpURLConnection connection, int maxBytes) throws IOException {
        long advertised = connection.getContentLengthLong();
        if (advertised > maxBytes) throw new IOException("Response is too large");
        byte[] bytes;
        try (InputStream input = connection.getInputStream()) {
            bytes = readLimited(input, maxBytes);
        }
        if (advertised >= 0 && advertised != bytes.length) {
            throw new IOException("Response size changed while downloading");
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String fetchChecksum(URL url) throws IOException {
        HttpURLConnection connection = openConnection(url, CHECKSUM_NAME);
        try {
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new IOException("Checksum asset returned HTTP " + connection.getResponseCode());
            }
            String text = readText(connection, MAX_CHECKSUM_BYTES);
            Matcher matcher = SHA256_LINE.matcher(text);
            if (!matcher.matches()) throw new IOException("Checksum asset is not a SHA-256 file");
            return matcher.group(1).toLowerCase(java.util.Locale.ROOT);
        } finally {
            connection.disconnect();
        }
    }

    private static DownloadResult downloadToTemp(URL url, Path temporary, long expectedSize,
            IntConsumer progress) throws Exception {
        HttpURLConnection connection = openConnection(url, INSTALLER_NAME);
        try {
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("Installer returned HTTP " + status);
            }
            long advertised = connection.getContentLengthLong();
            if (advertised > MAX_INSTALLER_BYTES
                    || (expectedSize > 0 && advertised >= 0 && advertised != expectedSize)) {
                throw new IOException("Installer response has an unexpected size");
            }
            if (progress != null) progress.accept(0);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0;
            int lastPercent = 0;
            try (InputStream input = connection.getInputStream();
                    OutputStream output = Files.newOutputStream(temporary)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) != -1) {
                    copied += read;
                    if (copied > MAX_INSTALLER_BYTES
                            || (expectedSize > 0 && copied > expectedSize)) {
                        throw new IOException("Installer response is too large");
                    }
                    digest.update(buffer, 0, read);
                    output.write(buffer, 0, read);
                    if (progress != null && expectedSize > 0) {
                        int percent = (int) (copied * 100 / expectedSize);
                        if (percent != lastPercent) {
                            lastPercent = percent;
                            progress.accept(percent);
                        }
                    }
                }
            }
            if (copied <= 0 || (expectedSize > 0 && copied != expectedSize)
                    || (advertised >= 0 && copied != advertised)) {
                throw new IOException("Installer response was truncated or incomplete");
            }
            if (progress != null && expectedSize > 0 && lastPercent < 100) progress.accept(100);
            return new DownloadResult(digest.digest(), copied);
        } finally {
            connection.disconnect();
        }
    }

    private static void atomicReplace(Path temporary, Path destination) throws IOException {
        try {
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            throw new IOException("Atomic replacement is not supported for the update destination", e);
        }
    }

    private static byte[] readLimited(InputStream input, int maxBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            if (output.size() > maxBytes - read) throw new IOException("Response is too large");
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static byte[] hexBytes(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private record DownloadResult(byte[] digest, long size) {}

    /** Small strict JSON parser; it rejects malformed input and duplicate object keys. */
    private static final class JsonParser {
        private final String text;
        private int position;

        JsonParser(String text) { this.text = Objects.requireNonNull(text); }

        Object parse() throws IOException {
            skipSpace();
            Object value = value();
            skipSpace();
            if (position != text.length()) throw error("Trailing JSON data");
            return value;
        }

        private Object value() throws IOException {
            skipSpace();
            if (position >= text.length()) throw error("Unexpected end of JSON");
            return switch (text.charAt(position)) {
                case '{' -> object();
                case '[' -> array();
                case '"' -> string();
                case 't' -> literal("true", Boolean.TRUE);
                case 'f' -> literal("false", Boolean.FALSE);
                case 'n' -> literal("null", null);
                default -> number();
            };
        }

        private Map<String, Object> object() throws IOException {
            position++;
            Map<String, Object> result = new LinkedHashMap<>();
            skipSpace();
            if (take('}')) return result;
            while (true) {
                skipSpace();
                if (position >= text.length() || text.charAt(position) != '"') {
                    throw error("Object key is not a string");
                }
                String key = string();
                if (result.containsKey(key)) throw error("Duplicate object key");
                skipSpace();
                if (!take(':')) throw error("Missing object colon");
                result.put(key, value());
                skipSpace();
                if (take('}')) return result;
                if (!take(',')) throw error("Missing object comma");
            }
        }

        private List<Object> array() throws IOException {
            position++;
            List<Object> result = new ArrayList<>();
            skipSpace();
            if (take(']')) return result;
            while (true) {
                result.add(value());
                skipSpace();
                if (take(']')) return result;
                if (!take(',')) throw error("Missing array comma");
            }
        }

        private String string() throws IOException {
            if (!take('"')) throw error("Expected string");
            StringBuilder result = new StringBuilder();
            while (position < text.length()) {
                char c = text.charAt(position++);
                if (c == '"') return result.toString();
                if (c < 0x20) throw error("Unescaped control character");
                if (c != '\\') {
                    result.append(c);
                    continue;
                }
                if (position >= text.length()) throw error("Incomplete escape");
                switch (text.charAt(position++)) {
                    case '"' -> result.append('"');
                    case '\\' -> result.append('\\');
                    case '/' -> result.append('/');
                    case 'b' -> result.append('\b');
                    case 'f' -> result.append('\f');
                    case 'n' -> result.append('\n');
                    case 'r' -> result.append('\r');
                    case 't' -> result.append('\t');
                    case 'u' -> result.append(unicodeEscape());
                    default -> throw error("Invalid escape");
                }
            }
            throw error("Unterminated string");
        }

        private char unicodeEscape() throws IOException {
            if (position + 4 > text.length()) throw error("Incomplete unicode escape");
            String hex = text.substring(position, position + 4);
            if (!hex.matches("[0-9a-fA-F]{4}")) throw error("Invalid unicode escape");
            position += 4;
            return (char) Integer.parseInt(hex, 16);
        }

        private Object number() throws IOException {
            int start = position;
            if (text.charAt(position) == '-') position++;
            if (position >= text.length()) throw error("Invalid number");
            if (text.charAt(position) == '0') {
                position++;
            } else if (Character.isDigit(text.charAt(position)) && text.charAt(position) != '0') {
                while (position < text.length() && Character.isDigit(text.charAt(position))) position++;
            } else {
                throw error("Invalid number");
            }
            boolean decimal = false;
            if (position < text.length() && text.charAt(position) == '.') {
                decimal = true;
                position++;
                int fractionStart = position;
                while (position < text.length() && Character.isDigit(text.charAt(position))) position++;
                if (fractionStart == position) throw error("Invalid number fraction");
            }
            if (position < text.length() && (text.charAt(position) == 'e' || text.charAt(position) == 'E')) {
                decimal = true;
                position++;
                if (position < text.length() && (text.charAt(position) == '+' || text.charAt(position) == '-')) position++;
                int exponentStart = position;
                while (position < text.length() && Character.isDigit(text.charAt(position))) position++;
                if (exponentStart == position) throw error("Invalid number exponent");
            }
            String number = text.substring(start, position);
            try {
                return decimal ? Double.parseDouble(number) : Long.parseLong(number);
            } catch (NumberFormatException e) {
                throw error("Invalid number");
            }
        }

        private Object literal(String expected, Object result) throws IOException {
            if (!text.startsWith(expected, position)) throw error("Invalid literal");
            position += expected.length();
            return result;
        }

        private void skipSpace() {
            while (position < text.length() && Character.isWhitespace(text.charAt(position))) position++;
        }

        private boolean take(char expected) {
            if (position < text.length() && text.charAt(position) == expected) {
                position++;
                return true;
            }
            return false;
        }

        private IOException error(String message) {
            return new IOException(message + " at JSON offset " + position);
        }
    }

    private UpdateChecker() {}
}

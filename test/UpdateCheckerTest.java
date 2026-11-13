package com.cheatguard.config;

public final class UpdateCheckerTest {
    public static void main(String[] args) {
        String json = "{\"tag_name\":\"v1.8\",\"assets\":["
                + "{\"name\":\"CheatGuardCentral-Setup.exe\",\"browser_download_url\":"
                + "\"https://github.com/sowrdfish-81/Cheat.Guard/releases/download/v1.8/CheatGuardCentral-Setup.exe\",\"size\":123},"
                + "{\"name\":\"CheatGuardCentral-Setup.exe.sha256\",\"browser_download_url\":"
                + "\"https://github.com/sowrdfish-81/Cheat.Guard/releases/download/v1.8/CheatGuardCentral-Setup.exe.sha256\",\"size\":80}]}";
        if (UpdateChecker.parseReleaseJson(json, "1.7").isEmpty()) throw new AssertionError("valid release rejected");
        String untrusted = json.replace("https://github.com/sowrdfish-81", "https://example.com/sowrdfish-81");
        if (UpdateChecker.parseReleaseJson(untrusted, "1.7").isPresent()) throw new AssertionError("untrusted URL accepted");
        String duplicate = json.replace("]}", ",{\"name\":\"CheatGuardCentral-Setup.exe\",\"browser_download_url\":\"https://github.com/sowrdfish-81/Cheat.Guard/releases/download/v1.8/CheatGuardCentral-Setup.exe\",\"size\":123}]}" );
        if (UpdateChecker.parseReleaseJson(duplicate, "1.7").isPresent()) throw new AssertionError("duplicate asset accepted");
        System.out.println("PASS updater parser tests");
    }
}
// QA flow: release metadata/assets -> parser/checksum validation -> updater result.

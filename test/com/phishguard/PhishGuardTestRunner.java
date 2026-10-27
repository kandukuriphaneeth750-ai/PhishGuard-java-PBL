package com.phishguard;

import com.phishguard.analyzer.UrlAnalyzer;
import com.phishguard.history.ScanHistory;
import com.phishguard.model.AnalysisResult;

import java.io.File;
import java.util.List;

/**
 * Dependency-Free Automated Test Runner for PhishGuard.
 * Validates all required test suites without needing external Maven/Gradle/JUnit dependencies,
 * making it ideal and accessible for beginner college PBL evaluation.
 */
public class PhishGuardTestRunner {

    private static int totalTests = 0;
    private static int passedTests = 0;
    private static int failedTests = 0;

    public static void main(String[] args) {
        System.out.println("===================================================================");
        System.out.println("       PHISHGUARD AUTOMATED TEST SUITE & VERIFICATION RUNNER       ");
        System.out.println("===================================================================");

        UrlAnalyzer analyzer = new UrlAnalyzer();

        // 1. Empty / Blank Input Test
        runTest("Test 1: Empty and Blank Input Handling", () -> {
            AnalysisResult r1 = analyzer.analyze("");
            AnalysisResult r2 = analyzer.analyze("   ");
            AnalysisResult r3 = analyzer.analyze(null);

            assertTrue(!r1.isValid(), "Empty string should be marked invalid");
            assertTrue(!r2.isValid(), "Whitespace string should be marked invalid");
            assertTrue(!r3.isValid(), "Null input should be marked invalid");
            assertEquals("URL input cannot be blank or empty.", r1.getValidationMessage());
        });

        // 2. Valid HTTPS Clean URL Test
        runTest("Test 2: Clean Valid HTTPS URL", () -> {
            AnalysisResult res = analyzer.analyze("https://example.com/index.html");
            assertTrue(res.isValid(), "Standard HTTPS URL should be valid");
            assertEquals("https", res.getScheme());
            assertEquals("example.com", res.getHost());
            assertEquals(0, res.getScore());
            assertEquals("Low Risk Indicators", res.getRiskCategory());
            assertTrue(res.getViolations().isEmpty(), "No violations should be triggered for clean HTTPS domain");
        });

        // 3. Unencrypted HTTP URL Test (+10 pts)
        runTest("Test 3: HTTP Unencrypted Protocol Rule", () -> {
            AnalysisResult res = analyzer.analyze("http://example.com/");
            assertTrue(res.isValid(), "HTTP URL should parse correctly");
            assertEquals(10, res.getScore());
            assertTrue(res.getViolations().stream().anyMatch(v -> "RULE_HTTP".equals(v.getRuleId())),
                    "RULE_HTTP must be flagged");
        });

        // 4. Hostname containing IPv4 Address (+20 pts)
        runTest("Test 4: Raw IPv4 Hostname Rule", () -> {
            AnalysisResult res = analyzer.analyze("http://192.168.1.50/dashboard");
            assertTrue(res.isValid(), "IP URL should parse");
            // HTTP (+10) + IP (+20) = 30
            assertTrue(res.getViolations().stream().anyMatch(v -> "RULE_IP_HOST".equals(v.getRuleId())),
                    "RULE_IP_HOST must be flagged");
            assertTrue(res.getScore() >= 30, "Score must include IP + HTTP points");
        });

        // 5. Embedded '@' symbol in URL (+20 pts)
        runTest("Test 5: Embedded '@' Symbol Spoofing Rule", () -> {
            AnalysisResult res = analyzer.analyze("https://trusted-bank.com@attacker-site.org/auth");
            assertTrue(res.isValid(), "URL with userinfo @ should be handled");
            assertTrue(res.getViolations().stream().anyMatch(v -> "RULE_AT_SYMBOL".equals(v.getRuleId())),
                    "RULE_AT_SYMBOL must be flagged");
            assertTrue(res.getScore() >= 20, "Score should include @ symbol penalty");
        });

        // 6. Long and Very Long URL Tests
        runTest("Test 6: Length Heuristic Boundaries (>100 and >180 chars)", () -> {
            // Exactly 105 chars
            StringBuilder sb1 = new StringBuilder("https://example.com/search?query=");
            while (sb1.length() < 105) sb1.append("a");
            AnalysisResult res1 = analyzer.analyze(sb1.toString());
            assertTrue(res1.getViolations().stream().anyMatch(v -> "RULE_LENGTH_100".equals(v.getRuleId())),
                    "RULE_LENGTH_100 must be flagged for 105 chars");
            assertTrue(res1.getViolations().stream().noneMatch(v -> "RULE_LENGTH_180".equals(v.getRuleId())),
                    "RULE_LENGTH_180 must NOT be flagged for 105 chars");

            // > 185 chars
            StringBuilder sb2 = new StringBuilder("https://example.com/deep/path/query=");
            while (sb2.length() < 195) sb2.append("b");
            AnalysisResult res2 = analyzer.analyze(sb2.toString());
            assertTrue(res2.getViolations().stream().anyMatch(v -> "RULE_LENGTH_100".equals(v.getRuleId())),
                    "RULE_LENGTH_100 must be flagged");
            assertTrue(res2.getViolations().stream().anyMatch(v -> "RULE_LENGTH_180".equals(v.getRuleId())),
                    "RULE_LENGTH_180 must be flagged");
        });

        // 7. Suspicious Keywords Test (+10 pts)
        runTest("Test 7: Suspicious Keywords in URL Components", () -> {
            AnalysisResult res = analyzer.analyze("https://safe-domain.org/verify-account-update");
            assertTrue(res.getViolations().stream().anyMatch(v -> "RULE_SUSPICIOUS_WORD".equals(v.getRuleId())),
                    "RULE_SUSPICIOUS_WORD must be flagged for verify/account/update");
        });

        // 8. Punycode IDN hostname ('xn--') (+10 pts)
        runTest("Test 8: Punycode IDN Homograph Hostname", () -> {
            AnalysisResult res = analyzer.analyze("https://xn--pple-43d.com/login");
            assertTrue(res.getViolations().stream().anyMatch(v -> "RULE_PUNYCODE".equals(v.getRuleId())),
                    "RULE_PUNYCODE must be flagged");
        });

        // 9. Known URL Shortener Hostname (+15 pts)
        runTest("Test 9: Known URL Shorteners Identification", () -> {
            AnalysisResult res = analyzer.analyze("https://bit.ly/secure-redirect");
            assertTrue(res.getViolations().stream().anyMatch(v -> "RULE_URL_SHORTENER".equals(v.getRuleId())),
                    "RULE_URL_SHORTENER must be flagged for bit.ly");
            assertTrue(UrlAnalyzer.isKnownUrlShortener("tinyurl.com"), "tinyurl.com must be identified");
            assertTrue(UrlAnalyzer.isKnownUrlShortener("t.co"), "t.co must be identified");
        });

        // 10. Malformed URL Input Handling
        runTest("Test 10: Malformed URL Syntax (Spaces and Bad Characters)", () -> {
            AnalysisResult res = analyzer.analyze("http://not a valid url with spaces.com");
            assertTrue(!res.isValid(), "URL with spaces should be invalid format");
            assertEquals("Invalid Input", res.getRiskCategory());
        });

        // 11. Risk Score Cap and Categories
        runTest("Test 11: Risk Score Cap (Max 100) and Classification Ranges", () -> {
            // Construct a worst-case URL that triggers multiple rules exceeding 100 pts
            String heavyUrl = "http://192.168.1.1@xn--pple.com/login-verify-account-update-banking-wallet-password-secret-token"
                    + "-super-long-padding-character-sequence-to-exceed-one-hundred-and-eighty-characters-for-testing-purposes-123456789";
            AnalysisResult res = analyzer.analyze(heavyUrl);
            assertTrue(res.getScore() <= 100, "Score must never exceed 100 points");
            assertEquals(100, res.getScore(), "High penalty URL should cap out at exactly 100");
            assertEquals("High Risk Indicators", res.getRiskCategory());
        });

        // 12. Local History Save, Reload, and Formula Neutralization
        runTest("Test 12: Scan History Persistence and Reload", () -> {
            File testHistoryFile = new File("data", "test_scan_history.csv");
            if (testHistoryFile.exists()) testHistoryFile.delete();

            ScanHistory testHistory = new ScanHistory(testHistoryFile);
            AnalysisResult sample = analyzer.analyze("https://example.com/test");
            boolean saved = testHistory.recordScan(sample);
            assertTrue(saved, "History record should be saved successfully");

            List<ScanHistory.Entry> entries = testHistory.loadHistory();
            assertTrue(!entries.isEmpty(), "History should contain recorded scan");
            assertEquals("https://example.com/test", entries.get(0).getUrl());

            testHistory.clearHistory();
            List<ScanHistory.Entry> cleared = testHistory.loadHistory();
            assertEquals(0, cleared.size(), "History should be empty after clearing");

            if (testHistoryFile.exists()) testHistoryFile.delete();
        });

        // 13. CSV Escaping and Formula Injection Mitigation
        runTest("Test 13: CSV Formula Injection Prevention and Quoting", () -> {
            String formula1 = "=cmd|'/c calc'!A0";
            String formula2 = "+12345";
            String formula3 = "@SUM(1,2)";

            assertEquals("'=cmd|'/c calc'!A0", ScanHistory.sanitizeFormulaInjection(formula1));
            assertEquals("'+12345", ScanHistory.sanitizeFormulaInjection(formula2));
            assertEquals("'@SUM(1,2)", ScanHistory.sanitizeFormulaInjection(formula3));

            String withCommas = "Hello, world";
            String withQuotes = "Say \"Hi\"";
            assertEquals("\"Hello, world\"", ScanHistory.sanitizeForCsv(withCommas));
            assertEquals("\"Say \"\"Hi\"\"\"", ScanHistory.sanitizeForCsv(withQuotes));
        });

        // Summary
        System.out.println("===================================================================");
        System.out.println(String.format("TEST EXECUTION SUMMARY: %d Total | %d Passed | %d Failed",
                totalTests, passedTests, failedTests));
        System.out.println("===================================================================");

        if (failedTests > 0) {
            System.err.println("FAILED: Some tests did not pass.");
            System.exit(1);
        } else {
            System.out.println("SUCCESS: ALL 13 TEST SUITES PASSED FLAWLESSLY.");
        }
    }

    private static void runTest(String testName, Runnable testLogic) {
        totalTests++;
        try {
            testLogic.run();
            passedTests++;
            System.out.println("[PASS] " + testName);
        } catch (AssertionError | Exception e) {
            failedTests++;
            System.err.println("[FAIL] " + testName + " -> " + e.getMessage());
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("Assertion Failed: " + message);
        }
    }

    private static void assertEquals(Object expected, Object actual) {
        assertEquals(expected, actual, "");
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (expected == null && actual == null) return;
        if (expected != null && expected.equals(actual)) return;
        String prefix = (message != null && !message.isEmpty()) ? (message + " -> ") : "";
        throw new AssertionError("Assertion Failed: " + prefix + "Expected [" + expected + "] but found [" + actual + "]");
    }
}

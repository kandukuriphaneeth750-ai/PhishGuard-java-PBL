package com.phishguard.analyzer;

import com.phishguard.model.AnalysisResult;
import com.phishguard.model.RuleViolation;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Core engine of PhishGuard responsible for URL validation and rule-based
 * heuristic scoring.
 * 
 * Demonstrates:
 * - Object-Oriented Design (Separation of Concerns)
 * - Safe URI parsing with java.net.URI
 * - Regular expressions for IPv4 and pattern recognition
 * - Defensive validation and exception handling
 * - Zero network dependencies (100% offline analysis)
 */
public class UrlAnalyzer {

    // IPv4 Address Pattern (e.g. 192.168.1.1)
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    // Sequence of 4 or more consecutive digits
    private static final Pattern DIGIT_SEQUENCE_PATTERN = Pattern.compile("\\d{4,}");

    // Suspicious phishing keywords frequently used to mislead victims
    private static final Set<String> SUSPICIOUS_KEYWORDS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "login", "verify", "verification", "account", "secure", "security",
            "update", "banking", "signin", "sign-in", "password", "credential",
            "confirm", "wallet", "authenticate", "auth", "support-billing"
    )));

    // Known URL shortener services that hide the final destination
    private static final Set<String> URL_SHORTENERS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
            "rebrand.ly", "cutt.ly", "goo.gl", "bit.do", "shorte.st"
    )));

    /**
     * Analyzes an input URL string and computes risk metrics based on heuristic rules.
     *
     * @param rawInput The URL string submitted by the user.
     * @return AnalysisResult containing parsed components, scores, and violations.
     */
    public AnalysisResult analyze(String rawInput) {
        if (rawInput == null || rawInput.trim().isEmpty()) {
            return AnalysisResult.createInvalid("", "URL input cannot be blank or empty.");
        }

        String input = rawInput.trim();

        // Check for disallowed characters or whitespace within the URL
        if (input.contains(" ") || input.contains("\t") || input.contains("\n")) {
            return AnalysisResult.createInvalid(input, "URL cannot contain spaces or newline characters.");
        }

        // Determine if scheme was explicitly provided
        boolean hasExplicitScheme = input.regionMatches(true, 0, "http://", 0, 7)
                || input.regionMatches(true, 0, "https://", 0, 8)
                || input.regionMatches(true, 0, "ftp://", 0, 6);

        String parseCandidate = hasExplicitScheme ? input : "http://" + input;

        URI uri;
        try {
            uri = new URI(parseCandidate);
        } catch (URISyntaxException e) {
            return AnalysisResult.createInvalid(input, "Malformed URL format: " + e.getReason());
        }

        String scheme = uri.getScheme();
        String host = uri.getHost();
        String path = uri.getPath();
        int port = uri.getPort();

        // Fallback host extraction if URI parsing was ambiguous (e.g. userinfo presence)
        if (host == null) {
            String authority = uri.getRawAuthority();
            if (authority != null && !authority.isEmpty()) {
                if (authority.contains("@")) {
                    authority = authority.substring(authority.indexOf('@') + 1);
                }
                if (authority.contains(":")) {
                    authority = authority.substring(0, authority.indexOf(':'));
                }
                host = authority;
            }
        }

        if (host == null || host.trim().isEmpty()) {
            return AnalysisResult.createInvalid(input, "Unable to extract a valid domain or host name from the URL.");
        }

        String normalizedHost = host.toLowerCase(Locale.ENGLISH);
        String fullUrlLower = input.toLowerCase(Locale.ENGLISH);

        List<RuleViolation> violations = new ArrayList<>();
        int score = 0;

        // RULE 1: HTTP instead of HTTPS (+10 points)
        if ("http".equalsIgnoreCase(scheme) || (!hasExplicitScheme && input.startsWith("http://"))) {
            violations.add(new RuleViolation(
                    "RULE_HTTP",
                    "Unencrypted HTTP Protocol",
                    10,
                    "The URL uses unencrypted HTTP instead of HTTPS. Phishing campaigns frequently avoid SSL certificates or operate on unencrypted connections.",
                    "MODERATE"
            ));
            score += 10;
        }

        // RULE 2: URL length > 100 characters (+10 points)
        if (input.length() > 100) {
            violations.add(new RuleViolation(
                    "RULE_LENGTH_100",
                    "Long URL (> 100 chars)",
                    10,
                    "The URL length is " + input.length() + " characters. Excessively long URLs are often used to conceal target domains and evade quick inspection.",
                    "MODERATE"
            ));
            score += 10;
        }

        // RULE 3: URL length > 180 characters (+10 additional points)
        if (input.length() > 180) {
            violations.add(new RuleViolation(
                    "RULE_LENGTH_180",
                    "Very Long URL (> 180 chars)",
                    10,
                    "The URL exceeds 180 characters, strongly associated with obfuscated tokens, deep subdomains, or encoded exploit payloads.",
                    "HIGH"
            ));
            score += 10;
        }

        // RULE 4: '@' symbol in the URL (+20 points)
        if (input.contains("@")) {
            violations.add(new RuleViolation(
                    "RULE_AT_SYMBOL",
                    "Embedded '@' Symbol in URL",
                    20,
                    "The '@' character instructs browsers to treat preceding text as user credentials and navigate only to the domain following it, a classic phishing trick.",
                    "HIGH"
            ));
            score += 20;
        }

        // RULE 5: Host is an IPv4 address (+20 points)
        if (isIpv4Address(normalizedHost)) {
            violations.add(new RuleViolation(
                    "RULE_IP_HOST",
                    "IP Address Used as Hostname",
                    20,
                    "The host is an explicit IPv4 address (" + normalizedHost + "). Legitimate organizations use registered domain names; direct IP addresses often conceal rogue servers.",
                    "HIGH"
            ));
            score += 20;
        }

        // RULE 6: Suspicious terms in domain or path (+10 points per distinct keyword)
        List<String> matchedKeywords = findSuspiciousKeywords(fullUrlLower);
        for (String matchedKeyword : matchedKeywords) {
            violations.add(new RuleViolation(
                    "RULE_SUSPICIOUS_WORD",
                    "Sensitive Keyword Detected ('" + matchedKeyword + "')",
                    10,
                    "The URL contains security-sensitive or financial keywords designed to induce urgency or spoof authentication portals.",
                    "MODERATE"
            ));
            score += 10;
        }

        // RULE 7: Unusually many subdomains (+10 points)
        int subdomainCount = countSubdomains(normalizedHost);
        if (subdomainCount >= 3 && !isIpv4Address(normalizedHost)) {
            violations.add(new RuleViolation(
                    "RULE_EXCESSIVE_SUBDOMAINS",
                    "Excessive Subdomains (" + subdomainCount + " levels)",
                    10,
                    "The hostname contains " + subdomainCount + " subdomain levels. Attackers stack subdomains (e.g., paypal.com.account-update.xyz) to simulate authentic brands.",
                    "MODERATE"
            ));
            score += 10;
        }

        // RULE 8: Punycode indicator 'xn--' in hostname (+10 points)
        if (normalizedHost.contains("xn--")) {
            violations.add(new RuleViolation(
                    "RULE_PUNYCODE",
                    "Punycode / IDN Domain ('xn--')",
                    10,
                    "The host utilizes Punycode encoding, commonly used in Internationalized Domain Name (IDN) homograph attacks to mimic well-known ASCII brand names.",
                    "HIGH"
            ));
            score += 10;
        }

        // RULE 9: Known URL Shortener (+15 points)
        if (isKnownUrlShortener(normalizedHost)) {
            violations.add(new RuleViolation(
                    "RULE_URL_SHORTENER",
                    "Known URL Shortener Service",
                    15,
                    "The hostname matches a known URL shortening provider (" + normalizedHost + "). Shorteners mask the true destination domain until the link is opened.",
                    "MODERATE"
            ));
            score += 15;
        }

        // RULE 10: Long sequence of digits in hostname (+5 points)
        if (DIGIT_SEQUENCE_PATTERN.matcher(normalizedHost).find() && !isIpv4Address(normalizedHost)) {
            violations.add(new RuleViolation(
                    "RULE_DIGIT_SEQUENCE",
                    "Long Digit Sequence in Hostname",
                    5,
                    "The domain name contains 4 or more consecutive numeric digits, characteristic of dynamically generated or temporary disposable phishing domains.",
                    "INFO"
            ));
            score += 5;
        }

        // Cap score at 100
        int finalScore = Math.min(100, Math.max(0, score));

        // Determine Risk Category
        String riskCategory;
        if (finalScore <= 29) {
            riskCategory = "Low Risk Indicators";
        } else if (finalScore <= 59) {
            riskCategory = "Moderate Risk Indicators";
        } else {
            riskCategory = "High Risk Indicators";
        }

        return new AnalysisResult(
                input,
                scheme,
                host,
                path != null ? path : "/",
                port,
                true,
                "Valid",
                finalScore,
                riskCategory,
                violations
        );
    }

    /**
     * Checks if a host is an IPv4 string.
     */
    public static boolean isIpv4Address(String host) {
        if (host == null) return false;
        return IPV4_PATTERN.matcher(host.trim()).matches();
    }

    /**
     * Counts subdomain levels in a hostname (excluding standard domain + TLD).
     */
    public static int countSubdomains(String host) {
        if (host == null || host.isEmpty()) return 0;
        String[] parts = host.split("\\.");
        // A standard domain like "google.com" has 2 parts (0 subdomains)
        // "mail.google.com" has 3 parts (1 subdomain)
        // "a.b.c.google.com" has 5 parts (3 subdomains)
        return Math.max(0, parts.length - 2);
    }

    /**
     * Searches for distinct suspicious keywords in the input.
     * Prevents duplicate reporting when a shorter keyword is a sub-string of a longer keyword.
     */
    private List<String> findSuspiciousKeywords(String text) {
        List<String> matched = new ArrayList<>();
        List<String> sortedKeywords = new ArrayList<>(SUSPICIOUS_KEYWORDS);
        sortedKeywords.sort((a, b) -> Integer.compare(b.length(), a.length()));

        for (String kw : sortedKeywords) {
            if (text.contains(kw)) {
                boolean redundant = false;
                for (String existing : matched) {
                    if (existing.contains(kw)) {
                        redundant = true;
                        break;
                    }
                }
                if (!redundant) {
                    matched.add(kw);
                }
            }
        }
        return matched;
    }

    /**
     * Checks if host matches known URL shortening services.
     */
    public static boolean isKnownUrlShortener(String host) {
        if (host == null) return false;
        String cleanHost = host.toLowerCase(Locale.ENGLISH);
        if (cleanHost.startsWith("www.")) {
            cleanHost = cleanHost.substring(4);
        }
        return URL_SHORTENERS.contains(cleanHost);
    }
}

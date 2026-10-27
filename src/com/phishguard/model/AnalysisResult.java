package com.phishguard.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Encapsulates the complete findings of a PhishGuard URL analysis.
 * Stores parsed URL components, overall risk score, risk level classification,
 * validation state, and all triggered heuristic rule violations.
 */
public class AnalysisResult {

    private final String originalUrl;
    private final String scheme;
    private final String host;
    private final String path;
    private final int port;
    private final boolean valid;
    private final String validationMessage;
    private final int score;
    private final String riskCategory;
    private final List<RuleViolation> violations;
    private final LocalDateTime timestamp;

    public AnalysisResult(String originalUrl, String scheme, String host, String path, int port,
                          boolean valid, String validationMessage, int score,
                          String riskCategory, List<RuleViolation> violations) {
        this.originalUrl = originalUrl;
        this.scheme = scheme != null ? scheme : "None";
        this.host = host != null ? host : "None";
        this.path = path != null ? path : "/";
        this.port = port;
        this.valid = valid;
        this.validationMessage = validationMessage;
        this.score = Math.min(100, Math.max(0, score));
        this.riskCategory = riskCategory;
        this.violations = violations != null ? new ArrayList<>(violations) : new ArrayList<>();
        this.timestamp = LocalDateTime.now();
    }

    /**
     * Factory method for creating an invalid/malformed URL result.
     */
    public static AnalysisResult createInvalid(String inputUrl, String reason) {
        return new AnalysisResult(
                inputUrl,
                "Invalid",
                "None",
                "None",
                -1,
                false,
                reason,
                0,
                "Invalid Input",
                Collections.emptyList()
        );
    }

    public String getOriginalUrl() {
        return originalUrl;
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public String getPath() {
        return path;
    }

    public int getPort() {
        return port;
    }

    public boolean isValid() {
        return valid;
    }

    public String getValidationMessage() {
        return validationMessage;
    }

    public int getScore() {
        return score;
    }

    public String getRiskCategory() {
        return riskCategory;
    }

    public List<RuleViolation> getViolations() {
        return Collections.unmodifiableList(violations);
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getFormattedTimestamp() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        return timestamp.format(formatter);
    }

    /**
     * Formats a short summary description for history logs.
     */
    public String getSummaryDescription() {
        if (!valid) {
            return "Invalid URL: " + validationMessage;
        }
        if (violations.isEmpty()) {
            return "No obvious heuristic indicators triggered.";
        }
        return violations.size() + " indicator(s) found (" + violations.get(0).getTitle() + (violations.size() > 1 ? ", ..." : "") + ")";
    }

    /**
     * Formats a full text report suitable for clipboard copying and file export.
     */
    public String toFullReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("=================================================================\n");
        sb.append("         PHISHGUARD — SUSPICIOUS URL ANALYSIS REPORT             \n");
        sb.append("=================================================================\n");
        sb.append("Generated On     : ").append(getFormattedTimestamp()).append("\n");
        sb.append("Target URL       : ").append(originalUrl).append("\n");
        sb.append("Validity Status  : ").append(valid ? "Valid Format" : "Invalid (" + validationMessage + ")").append("\n");
        sb.append("Protocol / Scheme: ").append(scheme).append("\n");
        sb.append("Identified Host  : ").append(host).append("\n");
        sb.append("Path Component   : ").append(path).append("\n");
        if (port != -1) {
            sb.append("Custom Port      : ").append(port).append("\n");
        }
        sb.append("-----------------------------------------------------------------\n");
        sb.append("OVERALL RISK SCORE : ").append(score).append(" / 100\n");
        sb.append("RISK CLASSIFICATION: ").append(riskCategory).append("\n");
        sb.append("-----------------------------------------------------------------\n");
        sb.append("HEURISTIC FINDINGS:\n");
        if (violations.isEmpty()) {
            sb.append("  [OK] No suspicious indicators were flagged by the rule engine.\n");
        } else {
            for (int i = 0; i < violations.size(); i++) {
                RuleViolation v = violations.get(i);
                sb.append(String.format("  %d. [%s] (+%d pts) %s\n", (i + 1), v.getSeverity(), v.getPoints(), v.getTitle()));
                sb.append("     Rationale: ").append(v.getExplanation()).append("\n");
            }
        }
        sb.append("-----------------------------------------------------------------\n");
        sb.append("DISCLAIMER:\n");
        sb.append("  PhishGuard evaluates URLs using static educational heuristics.\n");
        sb.append("  - A low score DOES NOT guarantee that a URL or website is safe.\n");
        sb.append("  - A high score DOES NOT prove malicious intent.\n");
        sb.append("  - Never enter passwords or sensitive data on untrusted sites.\n");
        sb.append("=================================================================\n");
        return sb.toString();
    }
}

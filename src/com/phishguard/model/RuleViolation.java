package com.phishguard.model;

/**
 * Represents a single rule violation detected during URL heuristic analysis.
 * Encapsulates the rule identifier, human-readable title, points assigned,
 * detailed rationale explaining why the indicator is suspicious, and severity.
 */
public class RuleViolation {

    private final String ruleId;
    private final String title;
    private final int points;
    private final String explanation;
    private final String severity; // INFO, MODERATE, HIGH

    public RuleViolation(String ruleId, String title, int points, String explanation, String severity) {
        this.ruleId = ruleId;
        this.title = title;
        this.points = points;
        this.explanation = explanation;
        this.severity = severity;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getTitle() {
        return title;
    }

    public int getPoints() {
        return points;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getSeverity() {
        return severity;
    }

    @Override
    public String toString() {
        return String.format("[%s] +%d pts: %s (%s)", severity, points, title, explanation);
    }
}

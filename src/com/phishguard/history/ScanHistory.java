package com.phishguard.history;

import com.phishguard.model.AnalysisResult;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Manages persistent local history of URL scans stored as a standard CSV file.
 * 
 * Features:
 * - Automatic directory and file creation
 * - CSV escaping and RFC 4180 compliance
 * - CSV formula injection protection (neutralizing '=', '+', '-', '@', '\t', '\r')
 * - Safe concurrent access and graceful error handling
 * - Clear history capability
 */
public class ScanHistory {

    public static class Entry {
        private final String timestamp;
        private final String url;
        private final int score;
        private final String category;
        private final String explanation;

        public Entry(String timestamp, String url, int score, String category, String explanation) {
            this.timestamp = timestamp;
            this.url = url;
            this.score = score;
            this.category = category;
            this.explanation = explanation;
        }

        public String getTimestamp() {
            return timestamp;
        }

        public String getUrl() {
            return url;
        }

        public int getScore() {
            return score;
        }

        public String getCategory() {
            return category;
        }

        public String getExplanation() {
            return explanation;
        }
    }

    private static final String CSV_HEADER = "Timestamp,Submitted URL,Risk Score,Risk Category,Summary Findings";
    private final File historyFile;

    public ScanHistory() {
        this(new File("data", "scan_history.csv"));
    }

    public ScanHistory(File historyFile) {
        this.historyFile = historyFile;
        ensureFileExists();
    }

    /**
     * Ensures parent directory and CSV header exist.
     */
    private synchronized void ensureFileExists() {
        try {
            File parent = historyFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (!historyFile.exists()) {
                try (BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(new FileOutputStream(historyFile), StandardCharsets.UTF_8))) {
                    writer.write(CSV_HEADER);
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            System.err.println("[PhishGuard] Error initializing history file: " + e.getMessage());
        }
    }

    /**
     * Appends an analysis result to the local CSV log.
     */
    public synchronized boolean recordScan(AnalysisResult result) {
        if (result == null) return false;
        ensureFileExists();

        try (BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(historyFile, true), StandardCharsets.UTF_8))) {

            String timestamp = sanitizeForCsv(result.getFormattedTimestamp());
            String sanitizedUrl = sanitizeForCsv(sanitizeFormulaInjection(result.getOriginalUrl()));
            String score = String.valueOf(result.getScore());
            String category = sanitizeForCsv(result.getRiskCategory());
            String explanation = sanitizeForCsv(sanitizeFormulaInjection(result.getSummaryDescription()));

            String line = String.join(",", timestamp, sanitizedUrl, score, category, explanation);
            writer.write(line);
            writer.newLine();
            return true;
        } catch (IOException e) {
            System.err.println("[PhishGuard] Failed to write scan history: " + e.getMessage());
            return false;
        }
    }

    /**
     * Reads all recorded scan history from the CSV file.
     */
    public synchronized List<Entry> loadHistory() {
        if (!historyFile.exists()) {
            return Collections.emptyList();
        }

        List<Entry> entries = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(historyFile), StandardCharsets.UTF_8))) {

            String line = reader.readLine(); // skip header
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                List<String> tokens = parseCsvLine(line);
                if (tokens.size() >= 5) {
                    try {
                        int score = Integer.parseInt(tokens.get(2).trim());
                        entries.add(new Entry(
                                tokens.get(0),
                                tokens.get(1),
                                score,
                                tokens.get(3),
                                tokens.get(4)
                        ));
                    } catch (NumberFormatException ignored) {}
                }
            }
        } catch (IOException e) {
            System.err.println("[PhishGuard] Failed to read scan history: " + e.getMessage());
        }

        // Return most recent first
        Collections.reverse(entries);
        return entries;
    }

    /**
     * Clears all scan history and resets the CSV header.
     */
    public synchronized boolean clearHistory() {
        try {
            if (historyFile.exists()) {
                historyFile.delete();
            }
            ensureFileExists();
            return true;
        } catch (Exception e) {
            System.err.println("[PhishGuard] Failed to clear history: " + e.getMessage());
            return false;
        }
    }

    public File getHistoryFile() {
        return historyFile;
    }

    /**
     * Neutralizes Formula Injection (CSV injection attacks).
     * If text starts with =, +, -, @, tab, or carriage return, prepend a single quote (').
     */
    public static String sanitizeFormulaInjection(String input) {
        if (input == null || input.isEmpty()) return "";
        char firstChar = input.charAt(0);
        if (firstChar == '=' || firstChar == '+' || firstChar == '-' || firstChar == '@'
                || firstChar == '\t' || firstChar == '\r') {
            return "'" + input;
        }
        return input;
    }

    /**
     * Standard CSV escaping according to RFC 4180.
     * Encloses value in double quotes if it contains commas, double quotes, or newlines.
     */
    public static String sanitizeForCsv(String value) {
        if (value == null) return "\"\"";
        boolean needsQuotes = value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r");
        String escaped = value.replace("\"", "\"\"");
        if (needsQuotes) {
            return "\"" + escaped + "\"";
        }
        return escaped;
    }

    /**
     * Robust CSV line parser handling quoted fields containing commas.
     */
    public static List<String> parseCsvLine(String line) {
        List<String> result = new ArrayList<>();
        if (line == null) return result;

        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '\"') {
                    current.append('\"');
                    i++; // skip escaped quote
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                result.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        result.add(current.toString());
        return result;
    }
}

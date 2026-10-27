package com.phishguard;

import com.phishguard.ui.MainFrame;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Main application entry point for PhishGuard — Rule-Based Suspicious URL Analyzer.
 * College Java PBL Project Exhibition (12 November 2026).
 */
public class Main {

    public static void main(String[] args) {
        // Output startup telemetry to console
        System.out.println("=================================================");
        System.out.println("   PHISHGUARD — RULE-BASED SUSPICIOUS URL ANALYZER ");
        System.out.println("   Java PBL College Exhibition Project (2026)");
        System.out.println("=================================================");
        System.out.println("[PhishGuard] Initializing offline heuristic engine...");

        // Ensure modern font rendering on Windows/Linux/macOS
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");

        // Launch GUI on Event Dispatch Thread (Swing best practice)
        SwingUtilities.invokeLater(() -> {
            try {
                // Use cross-platform look and feel or system look and feel safely
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                System.out.println("[PhishGuard] Defaulting to standard Swing Look and Feel.");
            }

            MainFrame frame = new MainFrame();
            frame.setVisible(true);
            System.out.println("[PhishGuard] Dashboard interface successfully displayed.");
        });
    }
}

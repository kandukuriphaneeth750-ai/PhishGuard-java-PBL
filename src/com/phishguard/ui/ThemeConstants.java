package com.phishguard.ui;

import java.awt.Color;
import java.awt.Font;

/**
 * Modern dark navy and cyan design palette for PhishGuard.
 * Provides consistent styling tokens for colors, typography, and card accents.
 */
public final class ThemeConstants {

    private ThemeConstants() {}

    // Dark Navy Background Palette
    public static final Color BG_DARK = new Color(11, 19, 43);        // Deep navy window base
    public static final Color BG_CARD = new Color(28, 37, 65);        // Rich navy card background
    public static final Color BG_CARD_LIGHT = new Color(38, 50, 85);  // Slightly elevated card
    public static final Color BG_INPUT = new Color(17, 26, 51);       // Input field background
    public static final Color BORDER_COLOR = new Color(58, 80, 107);   // Subtle slate border

    // Cyan and Blue Accents
    public static final Color ACCENT_CYAN = new Color(0, 229, 255);    // Bright cyan highlight
    public static final Color ACCENT_BLUE = new Color(2, 132, 199);    // Primary blue action
    public static final Color ACCENT_HOVER = new Color(3, 105, 161);   // Blue hover state
    public static final Color BTN_SECONDARY = new Color(45, 60, 95);   // Secondary button background
    public static final Color BTN_SECONDARY_HOVER = new Color(60, 80, 120);

    // Exact Button Styling Palette
    public static final Color BTN_ANALYZE_BG = Color.decode("#2563EB");  // Blue
    public static final Color BTN_SAMPLE_BG = Color.decode("#0F766E");   // Teal
    public static final Color BTN_CLEAR_BG = Color.decode("#374151");    // Dark grey
    public static final Color BTN_COPY_BG = Color.decode("#7C3AED");     // Purple
    public static final Color BTN_EXPORT_BG = Color.decode("#15803D");   // Green
    public static final Color BTN_NAVY_BG = Color.decode("#1E293B");     // Dark navy
    public static final Color BTN_DEFAULT_BG = Color.decode("#2563EB");  // Blue fallback
    public static final Color TEXT_WHITE = Color.decode("#FFFFFF");      // White text
    public static final Color TEXT_LIGHT = Color.decode("#F8FAFC");      // Light text

    // Text Colors
    public static final Color TEXT_PRIMARY = new Color(248, 250, 252);  // High contrast white
    public static final Color TEXT_SECONDARY = new Color(148, 163, 184); // Soft slate gray
    public static final Color TEXT_MUTED = new Color(100, 116, 139);    // Dim subtle hint

    // Risk Level Colors
    public static final Color RISK_LOW = new Color(16, 185, 129);       // Emerald Green
    public static final Color RISK_MODERATE = new Color(245, 158, 11);  // Amber Orange
    public static final Color RISK_HIGH = new Color(239, 68, 68);       // Crimson Red

    // Typography
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font FONT_SUBTITLE = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_SECTION = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_BODY_BOLD = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_SCORE = new Font("Segoe UI", Font.BOLD, 42);
    public static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 12);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 11);
}

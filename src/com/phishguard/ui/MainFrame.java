package com.phishguard.ui;

import com.phishguard.analyzer.UrlAnalyzer;
import com.phishguard.history.ScanHistory;
import com.phishguard.model.AnalysisResult;
import com.phishguard.model.RuleViolation;
import com.phishguard.util.ReportExporter;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.plaf.basic.BasicTabbedPaneUI;

/**
 * Main application window for PhishGuard.
 * Implements a modern dark navy cybersecurity dashboard using Java Swing.
 */
public class MainFrame extends JFrame {

    private final UrlAnalyzer analyzer;
    private final ScanHistory history;

    // UI Input Controls
    private JTextField urlInputField;
    private JButton analyzeButton;
    private JButton sampleButton;
    private JButton clearButton;

    // Results Display Controls
    private JLabel scoreLabel;
    private JLabel riskBadgeLabel;
    private JLabel schemeValueLabel;
    private JLabel hostValueLabel;
    private JLabel statusValueLabel;
    private JLabel lengthValueLabel;
    private JPanel findingsListPanel;
    private JScrollPane findingsScrollPane;

    // Action Buttons
    private JButton copyButton;
    private JButton exportButton;
    private JButton clearHistoryButton;

    // History Table
    private JTable historyTable;
    private DefaultTableModel historyTableModel;

    // Currently cached analysis result
    private AnalysisResult currentResult;

    // Pre-curated educational sample URLs
    private static final String[] SAMPLE_URLS = {
            "https://www.google.com/search?q=cybersecurity",
            "http://secure-login-account-update.banking-verify.xyz/auth?user=victim",
            "http://192.168.1.105/login.html",
            "http://legit-service.com@malicious-redirect.com/update-account",
            "http://bit.ly/claim-free-gift-card-bonus-2026",
            "http://xn--pple-43d.com/verify-credentials",
            "https://sub1.sub2.sub3.suspicious-domain-name9941.com/portal"
    };
    private int sampleIndex = 0;

    public MainFrame() {
        super("PhishGuard — Rule-Based Suspicious URL Analyzer");
        this.analyzer = new UrlAnalyzer();
        this.history = new ScanHistory();

        initComponents();
        loadHistoryIntoTable();

        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1000, 720));
        setSize(1100, 780);
        setLocationRelativeTo(null);
    }

    private void initComponents() {
        JPanel rootPanel = new JPanel(new BorderLayout());
        rootPanel.setBackground(ThemeConstants.BG_DARK);

        // 1. Header Panel
        rootPanel.add(createHeaderPanel(), BorderLayout.NORTH);

        // 2. Center Content Split: Top Analysis, Bottom/Right History
        JPanel mainContentPanel = new JPanel(new BorderLayout(15, 15));
        mainContentPanel.setBackground(ThemeConstants.BG_DARK);
        mainContentPanel.setBorder(new EmptyBorder(15, 20, 15, 20));

        // URL Input Bar at top of content
        mainContentPanel.add(createInputCard(), BorderLayout.NORTH);

        // Tabbed Panel: Dashboard & Findings, History & Log, About
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(ThemeConstants.FONT_SECTION);
        tabbedPane.setOpaque(false);

        // Custom blue tab bar styling so tabs are bold, vibrant blue and 100% visible
        tabbedPane.setUI(new BasicTabbedPaneUI() {
            @Override
            protected void installDefaults() {
                super.installDefaults();
                tabInsets = new Insets(8, 20, 8, 20);
                selectedTabPadInsets = new Insets(0, 0, 0, 0);
                contentBorderInsets = new Insets(2, 0, 0, 0);
            }

            @Override
            protected void paintTabBackground(Graphics g, int tabPlacement, int tabIndex, int x, int y, int w, int h, boolean isSelected) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                if (isSelected) {
                    g2.setColor(ThemeConstants.BTN_ANALYZE_BG); // Vibrant Blue #2563EB
                } else {
                    g2.setColor(new Color(30, 58, 138)); // Slate Blue #1E3A8A
                }
                g2.fillRoundRect(x, y, w, h + 4, 8, 8);
                g2.dispose();
            }

            @Override
            protected void paintTabBorder(Graphics g, int tabPlacement, int tabIndex, int x, int y, int w, int h, boolean isSelected) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(isSelected ? new Color(96, 165, 250) : new Color(37, 99, 235));
                g2.drawRoundRect(x, y, w - 1, h + 4, 8, 8);
                g2.dispose();
            }

            @Override
            protected void paintText(Graphics g, int tabPlacement, Font font, FontMetrics metrics, int tabIndex, String title, Rectangle textRect, boolean isSelected) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                g2.setFont(font);
                g2.setColor(Color.WHITE);
                g2.drawString(title, textRect.x, textRect.y + metrics.getAscent());
                g2.dispose();
            }

            @Override
            protected void paintContentBorder(Graphics g, int tabPlacement, int selectedIndex) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setColor(ThemeConstants.BTN_ANALYZE_BG); // Crisp blue divider line #2563EB
                g2.fillRect(0, 0, tabbedPane.getWidth(), 2);
                g2.dispose();
            }

            @Override
            protected void paintFocusIndicator(Graphics g, int tabPlacement, Rectangle[] rects, int tabIndex, Rectangle iconRect, Rectangle textRect, boolean isSelected) {
                // Do not paint dotted focus indicator box
            }
        });

        tabbedPane.addTab("  Analysis Dashboard  ", createDashboardPanel());
        tabbedPane.addTab("  Scan History Log  ", createHistoryPanel());
        tabbedPane.addTab("  About & Limitations  ", createAboutPanel());

        mainContentPanel.add(tabbedPane, BorderLayout.CENTER);
        // Add the main content panel to the root layout so analysis dashboard and history appear
        rootPanel.add(mainContentPanel, BorderLayout.CENTER);

        // 3. Status Bar at bottom
        rootPanel.add(createStatusBar(), BorderLayout.SOUTH);

        setContentPane(rootPanel);
    }

    /**
     * Top Header banner with shield emblem and project title.
     */
    private JPanel createHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(ThemeConstants.BG_CARD);
        header.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, ThemeConstants.BORDER_COLOR),
                new EmptyBorder(15, 25, 15, 25)
        ));

        JPanel titleBlock = new JPanel();
        titleBlock.setLayout(new BoxLayout(titleBlock, BoxLayout.Y_AXIS));
        titleBlock.setBackground(ThemeConstants.BG_CARD);

        JLabel titleLabel = new JLabel("🛡️  PHISHGUARD");
        titleLabel.setFont(ThemeConstants.FONT_TITLE);
        titleLabel.setForeground(ThemeConstants.ACCENT_CYAN);

        JLabel subtitleLabel = new JLabel("Rule-Based Suspicious URL Analyzer  |  College Java PBL Project Exhibition");
        subtitleLabel.setFont(ThemeConstants.FONT_SUBTITLE);
        subtitleLabel.setForeground(ThemeConstants.TEXT_SECONDARY);

        titleBlock.add(titleLabel);
        titleBlock.add(Box.createVerticalStrut(3));
        titleBlock.add(subtitleLabel);

        // Right side badge
        JLabel modeBadge = new JLabel("100% Offline Static Heuristics  ");
        modeBadge.setFont(ThemeConstants.FONT_SMALL);
        modeBadge.setForeground(ThemeConstants.TEXT_MUTED);

        header.add(titleBlock, BorderLayout.WEST);
        header.add(modeBadge, BorderLayout.EAST);
        return header;
    }

    /**
     * Input panel containing the URL text box and primary action buttons.
     */
    private JPanel createInputCard() {
        JPanel card = createCardPanel();
        card.setLayout(new BorderLayout(10, 10));
        card.setBorder(new EmptyBorder(15, 15, 15, 15));

        JLabel promptLabel = new JLabel("Enter URL for Static Heuristic Inspection:");
        promptLabel.setFont(ThemeConstants.FONT_SECTION);
        promptLabel.setForeground(ThemeConstants.TEXT_PRIMARY);

        JPanel inputRow = new JPanel(new BorderLayout(10, 0));
        inputRow.setOpaque(false);

        urlInputField = new JTextField();
        urlInputField.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        urlInputField.setBackground(ThemeConstants.BG_INPUT);
        urlInputField.setForeground(ThemeConstants.TEXT_PRIMARY);
        urlInputField.setCaretColor(ThemeConstants.ACCENT_CYAN);
        urlInputField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(ThemeConstants.BORDER_COLOR, 1),
                new EmptyBorder(8, 12, 8, 12)
        ));
        urlInputField.setToolTipText("Paste or type a full web URL here (e.g. https://example.com)");
        urlInputField.addActionListener(e -> performAnalysis());

        JPanel buttonGroup = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttonGroup.setOpaque(false);

        analyzeButton = createStyledButton("⚡ Analyze URL", ThemeConstants.BTN_ANALYZE_BG, ThemeConstants.TEXT_WHITE);
        analyzeButton.setBackground(ThemeConstants.BTN_ANALYZE_BG);
        analyzeButton.setForeground(ThemeConstants.TEXT_WHITE);
        analyzeButton.setOpaque(true);
        analyzeButton.setContentAreaFilled(true);
        analyzeButton.setBorderPainted(false);
        analyzeButton.addActionListener(e -> performAnalysis());

        sampleButton = createStyledButton("🎲 Sample URL", ThemeConstants.BTN_SAMPLE_BG, ThemeConstants.TEXT_WHITE);
        sampleButton.setBackground(ThemeConstants.BTN_SAMPLE_BG);
        sampleButton.setForeground(ThemeConstants.TEXT_WHITE);
        sampleButton.setOpaque(true);
        sampleButton.setContentAreaFilled(true);
        sampleButton.setBorderPainted(false);
        sampleButton.addActionListener(e -> cycleSampleUrl());

        clearButton = createStyledButton("✖ Clear", ThemeConstants.BTN_CLEAR_BG, ThemeConstants.TEXT_WHITE);
        clearButton.setBackground(ThemeConstants.BTN_CLEAR_BG);
        clearButton.setForeground(ThemeConstants.TEXT_WHITE);
        clearButton.setOpaque(true);
        clearButton.setContentAreaFilled(true);
        clearButton.setBorderPainted(false);
        clearButton.addActionListener(e -> clearInputsAndResults());

        buttonGroup.add(analyzeButton);
        buttonGroup.add(sampleButton);
        buttonGroup.add(clearButton);

        inputRow.add(urlInputField, BorderLayout.CENTER);
        inputRow.add(buttonGroup, BorderLayout.EAST);

        card.add(promptLabel, BorderLayout.NORTH);
        card.add(inputRow, BorderLayout.CENTER);

        return card;
    }

    /**
     * Main dashboard panel containing Score Card, URL Summary, Findings, and Export Tools.
     */
    private JPanel createDashboardPanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBackground(ThemeConstants.BG_DARK);
        panel.setBorder(new EmptyBorder(15, 10, 15, 10));

        // Top Row: Score Card on Left, URL Components on Right
        JPanel topRow = new JPanel(new GridLayout(1, 2, 15, 0));
        topRow.setOpaque(false);

        topRow.add(createScoreCard());
        topRow.add(createSummaryCard());

        panel.add(topRow, BorderLayout.NORTH);

        // Center: Findings and Rule Breakdown
        panel.add(createFindingsCard(), BorderLayout.CENTER);

        // Bottom: Action Toolbar (Copy Report, Export File)
        panel.add(createActionToolbar(), BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Card displaying the overall risk score (0-100) and risk level badge.
     */
    private JPanel createScoreCard() {
        JPanel card = createCardPanel();
        card.setLayout(new GridBagLayout());
        card.setBorder(new EmptyBorder(15, 20, 15, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.CENTER;

        JLabel title = new JLabel("HEURISTIC RISK SCORE");
        title.setFont(ThemeConstants.FONT_SECTION);
        title.setForeground(new Color(0, 229, 255));
        card.add(title, gbc);

        gbc.gridy = 1;
        scoreLabel = new JLabel("-- / 100");
        scoreLabel.setFont(ThemeConstants.FONT_SCORE);
        scoreLabel.setForeground(ThemeConstants.ACCENT_CYAN);
        card.add(scoreLabel, gbc);

        gbc.gridy = 2;
        riskBadgeLabel = new JLabel(" AWAITING ANALYSIS ");
        riskBadgeLabel.setFont(ThemeConstants.FONT_BODY_BOLD);
        riskBadgeLabel.setOpaque(true);
        riskBadgeLabel.setBackground(ThemeConstants.BG_CARD_LIGHT);
        riskBadgeLabel.setForeground(ThemeConstants.TEXT_SECONDARY);
        riskBadgeLabel.setBorder(new EmptyBorder(6, 16, 6, 16));
        card.add(riskBadgeLabel, gbc);

        return card;
    }

    /**
     * Card displaying parsed URL attributes (Host, Scheme, Length, Status).
     */
    private JPanel createSummaryCard() {
        JPanel card = createCardPanel();
        card.setLayout(new GridLayout(4, 2, 8, 8));
        card.setBorder(new EmptyBorder(15, 20, 15, 20));

        JLabel l1 = new JLabel("Protocol / Scheme:");
        l1.setFont(ThemeConstants.FONT_BODY);
        l1.setForeground(ThemeConstants.TEXT_SECONDARY);
        schemeValueLabel = new JLabel("None");
        schemeValueLabel.setFont(ThemeConstants.FONT_BODY_BOLD);
        schemeValueLabel.setForeground(ThemeConstants.TEXT_PRIMARY);

        JLabel l2 = new JLabel("Detected Host:");
        l2.setFont(ThemeConstants.FONT_BODY);
        l2.setForeground(ThemeConstants.TEXT_SECONDARY);
        hostValueLabel = new JLabel("None");
        hostValueLabel.setFont(ThemeConstants.FONT_BODY_BOLD);
        hostValueLabel.setForeground(ThemeConstants.TEXT_PRIMARY);

        JLabel l3 = new JLabel("URL Character Count:");
        l3.setFont(ThemeConstants.FONT_BODY);
        l3.setForeground(ThemeConstants.TEXT_SECONDARY);
        lengthValueLabel = new JLabel("0 chars");
        lengthValueLabel.setFont(ThemeConstants.FONT_BODY_BOLD);
        lengthValueLabel.setForeground(ThemeConstants.TEXT_PRIMARY);

        JLabel l4 = new JLabel("Validation State:");
        l4.setFont(ThemeConstants.FONT_BODY);
        l4.setForeground(ThemeConstants.TEXT_SECONDARY);
        statusValueLabel = new JLabel("Ready");
        statusValueLabel.setFont(ThemeConstants.FONT_BODY_BOLD);
        statusValueLabel.setForeground(ThemeConstants.TEXT_PRIMARY);

        card.add(l1);
        card.add(schemeValueLabel);
        card.add(l2);
        card.add(hostValueLabel);
        card.add(l3);
        card.add(lengthValueLabel);
        card.add(l4);
        card.add(statusValueLabel);

        return card;
    }

    /**
     * Findings card listing each triggered heuristic indicator.
     */
    private JPanel createFindingsCard() {
        JPanel card = createCardPanel();
        card.setLayout(new BorderLayout(5, 10));
        card.setBorder(new EmptyBorder(12, 15, 12, 15));

        JLabel title = new JLabel("Triggered Heuristic Indicators & Explanations:");
        title.setFont(ThemeConstants.FONT_SECTION);
        title.setForeground(ThemeConstants.TEXT_PRIMARY);
        card.add(title, BorderLayout.NORTH);

        findingsListPanel = new JPanel();
        findingsListPanel.setLayout(new BoxLayout(findingsListPanel, BoxLayout.Y_AXIS));
        findingsListPanel.setBackground(ThemeConstants.BG_CARD);

        displayInitialFindingsPrompt();

        findingsScrollPane = new JScrollPane(findingsListPanel);
        findingsScrollPane.setBorder(BorderFactory.createLineBorder(ThemeConstants.BORDER_COLOR, 1));
        findingsScrollPane.getViewport().setBackground(ThemeConstants.BG_CARD);
        card.add(findingsScrollPane, BorderLayout.CENTER);

        return card;
    }

    private void displayInitialFindingsPrompt() {
        findingsListPanel.removeAll();
        JPanel prompt = new JPanel(new FlowLayout(FlowLayout.CENTER));
        prompt.setOpaque(false);
        JLabel label = new JLabel("Enter a URL above and click 'Analyze URL' to view triggered indicators.");
        label.setFont(ThemeConstants.FONT_BODY);
        label.setForeground(ThemeConstants.TEXT_MUTED);
        prompt.add(label);
        findingsListPanel.add(prompt);
        findingsListPanel.revalidate();
        findingsListPanel.repaint();
    }

    /**
     * Bottom action toolbar with Copy Report, Export Report, and Quick Stats.
     */
    private JPanel createActionToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        bar.setOpaque(false);

        copyButton = createStyledButton("📋 Copy Full Report", ThemeConstants.BTN_COPY_BG, ThemeConstants.TEXT_WHITE);
        copyButton.setBackground(ThemeConstants.BTN_COPY_BG);
        copyButton.setForeground(ThemeConstants.TEXT_WHITE);
        copyButton.setOpaque(true);
        copyButton.setContentAreaFilled(true);
        copyButton.setBorderPainted(false);
        copyButton.addActionListener(e -> copyCurrentReport());

        exportButton = createStyledButton("💾 Export to Text File", ThemeConstants.BTN_EXPORT_BG, ThemeConstants.TEXT_WHITE);
        exportButton.setBackground(ThemeConstants.BTN_EXPORT_BG);
        exportButton.setForeground(ThemeConstants.TEXT_WHITE);
        exportButton.setOpaque(true);
        exportButton.setContentAreaFilled(true);
        exportButton.setBorderPainted(false);
        exportButton.addActionListener(e -> exportCurrentReport());

        bar.add(copyButton);
        bar.add(exportButton);
        return bar;
    }

    /**
     * Tab 2: Scan History Log with a stylized dark table and clear history option.
     */
    private JPanel createHistoryPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBackground(ThemeConstants.BG_DARK);
        panel.setBorder(new EmptyBorder(15, 15, 15, 15));

        JPanel topBar = new JPanel(new BorderLayout());
        topBar.setOpaque(false);

        JLabel historyTitle = new JLabel("Persistent Scan History (Saved locally to data/scan_history.csv)");
        historyTitle.setFont(ThemeConstants.FONT_SECTION);
        historyTitle.setForeground(ThemeConstants.TEXT_PRIMARY);

        clearHistoryButton = createStyledButton("🗑️ Clear History", ThemeConstants.BTN_ANALYZE_BG, ThemeConstants.TEXT_WHITE);
        clearHistoryButton.setBackground(ThemeConstants.BTN_ANALYZE_BG);
        clearHistoryButton.setForeground(ThemeConstants.TEXT_WHITE);
        clearHistoryButton.setOpaque(true);
        clearHistoryButton.setContentAreaFilled(true);
        clearHistoryButton.setBorderPainted(false);
        clearHistoryButton.addActionListener(e -> promptClearHistory());

        topBar.add(historyTitle, BorderLayout.WEST);
        topBar.add(clearHistoryButton, BorderLayout.EAST);
        panel.add(topBar, BorderLayout.NORTH);

        // Setup History Table
        String[] columnNames = {"Timestamp", "Submitted URL", "Score", "Risk Category", "Findings Summary"};
        historyTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        historyTable = new JTable(historyTableModel);
        historyTable.setFont(ThemeConstants.FONT_BODY);
        historyTable.setBackground(ThemeConstants.BG_CARD);
        historyTable.setForeground(ThemeConstants.TEXT_PRIMARY);
        historyTable.setGridColor(ThemeConstants.BORDER_COLOR);
        historyTable.setRowHeight(26);
        historyTable.setSelectionBackground(ThemeConstants.ACCENT_HOVER);
        historyTable.setSelectionForeground(Color.WHITE);

        JTableHeader tableHeader = historyTable.getTableHeader();
        tableHeader.setFont(ThemeConstants.FONT_BODY_BOLD);
        tableHeader.setBackground(ThemeConstants.BG_CARD_LIGHT);
        tableHeader.setForeground(ThemeConstants.ACCENT_CYAN);
        tableHeader.setBorder(BorderFactory.createLineBorder(ThemeConstants.BORDER_COLOR));

        // Center align the score column
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        historyTable.getColumnModel().getColumn(0).setPreferredWidth(140);
        historyTable.getColumnModel().getColumn(1).setPreferredWidth(280);
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(60);
        historyTable.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        historyTable.getColumnModel().getColumn(3).setPreferredWidth(140);
        historyTable.getColumnModel().getColumn(4).setPreferredWidth(300);

        // Click row to reload URL into input
        historyTable.getSelectionModel().addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && historyTable.getSelectedRow() != -1) {
                String selectedUrl = (String) historyTableModel.getValueAt(historyTable.getSelectedRow(), 1);
                // remove leading CSV quote if present
                if (selectedUrl.startsWith("'")) {
                    selectedUrl = selectedUrl.substring(1);
                }
                urlInputField.setText(selectedUrl);
            }
        });

        JScrollPane tableScroll = new JScrollPane(historyTable);
        tableScroll.setBorder(BorderFactory.createLineBorder(ThemeConstants.BORDER_COLOR));
        tableScroll.getViewport().setBackground(ThemeConstants.BG_CARD);
        panel.add(tableScroll, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Tab 3: Educational About & Limitations panel.
     */
    private JPanel createAboutPanel() {
        JPanel panel = new JPanel(new BorderLayout(15, 15));
        panel.setBackground(ThemeConstants.BG_DARK);
        panel.setBorder(new EmptyBorder(20, 25, 20, 25));

        JPanel card = createCardPanel();
        card.setLayout(new BorderLayout(10, 10));
        card.setBorder(new EmptyBorder(20, 20, 20, 20));

        JTextArea aboutText = new JTextArea();
        aboutText.setEditable(false);
        aboutText.setFont(new Font("Segoe UI", Font.PLAIN, 13));
        aboutText.setBackground(ThemeConstants.BG_CARD);
        aboutText.setForeground(ThemeConstants.TEXT_PRIMARY);
        aboutText.setLineWrap(true);
        aboutText.setWrapStyleWord(true);

        StringBuilder sb = new StringBuilder();
        sb.append("PROJECT OVERVIEW\n");
        sb.append("PhishGuard is an educational desktop application developed for the College Java Problem-Based Learning (PBL) Exhibition.\n");
        sb.append("It demonstrates fundamental Java concepts including Object-Oriented Programming (OOP), URI parsing, regular expressions, Swing GUI event-driven design, exception handling, and persistent file I/O.\n\n");
        sb.append("HEURISTIC SCORING RULES APPLIED:\n");
        sb.append("1. Unencrypted HTTP Protocol (+10 pts) — Attackers frequently utilize plain HTTP or free unverified endpoints.\n");
        sb.append("2. Length Exceeding 100 Chars (+10 pts) — Long URLs obscure target domains and confuse victims.\n");
        sb.append("3. Length Exceeding 180 Chars (+10 additional pts) — Extreme length linked with payload injection.\n");
        sb.append("4. Embedded '@' Symbol (+20 pts) — Browser credentials spoofing trick bypassing domain inspection.\n");
        sb.append("5. Raw IPv4 Hostname (+20 pts) — Lack of registered DNS domain name indicating suspicious hosting.\n");
        sb.append("6. Sensitive Keywords (+10 pts) — Terms like 'login', 'verify', 'banking', 'account', 'wallet'.\n");
        sb.append("7. Excessive Subdomains (+10 pts) — Stacking brands before malicious domains (e.g. paypal.com.evil.xyz).\n");
        sb.append("8. Punycode IDN ('xn--') (+10 pts) — Homograph character substitution attacks.\n");
        sb.append("9. Known URL Shorteners (+15 pts) — Services hiding destination addresses (bit.ly, tinyurl.com, etc.).\n");
        sb.append("10. Long Digit Sequences (+5 pts) — Characteristic of dynamically generated burner domains.\n\n");
        sb.append("CRITICAL LIMITATIONS & DISCLAIMER:\n");
        sb.append("• Static Heuristic Only: PhishGuard inspects the structural text of the URL without querying live DNS, checking SSL certificates, or fetching website contents.\n");
        sb.append("• No Safety Guarantee: A low score (0–29) DOES NOT guarantee that a link is harmless.\n");
        sb.append("• Educational Purpose: Designed strictly for college demonstration and awareness. Never rely solely on heuristic scoring for mission-critical security decisions.\n");

        aboutText.setText(sb.toString());

        JScrollPane scroll = new JScrollPane(aboutText);
        scroll.setBorder(null);
        scroll.getViewport().setBackground(ThemeConstants.BG_CARD);

        card.add(scroll, BorderLayout.CENTER);
        panel.add(card, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Bottom status footer.
     */
    private JPanel createStatusBar() {
        JPanel status = new JPanel(new BorderLayout());
        status.setBackground(ThemeConstants.BG_CARD);
        status.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, ThemeConstants.BORDER_COLOR),
                new EmptyBorder(6, 20, 6, 20)
        ));

        JLabel statusText = new JLabel("PhishGuard v1.0.0 — Java PBL College Exhibition 2026 | Safe Offline Execution");
        statusText.setFont(ThemeConstants.FONT_SMALL);
        statusText.setForeground(ThemeConstants.TEXT_MUTED);

        JLabel tipText = new JLabel("Tip: Double check subdomains and protocol before entering credentials.");
        tipText.setFont(ThemeConstants.FONT_SMALL);
        tipText.setForeground(ThemeConstants.ACCENT_CYAN);

        status.add(statusText, BorderLayout.WEST);
        status.add(tipText, BorderLayout.EAST);
        return status;
    }

    // =========================================================================
    // ACTION HANDLERS & LOGIC
    // =========================================================================

    /**
     * Performs analysis on the user-supplied URL and refreshes the UI.
     */
    private void performAnalysis() {
        String input = urlInputField.getText();
        if (input == null || input.trim().isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter a URL to analyze.",
                    "Input Required",
                    JOptionPane.WARNING_MESSAGE
            );
            return;
        }

        AnalysisResult result = analyzer.analyze(input);
        this.currentResult = result;

        // Update Summary Cards
        schemeValueLabel.setText(result.getScheme());
        hostValueLabel.setText(result.getHost());
        lengthValueLabel.setText(input.trim().length() + " chars");
        statusValueLabel.setText(result.isValid() ? "Valid Format" : "Invalid URL");
        statusValueLabel.setForeground(result.isValid() ? ThemeConstants.RISK_LOW : ThemeConstants.RISK_HIGH);

        // Update Score & Badge
        int score = result.getScore();
        scoreLabel.setText(score + " / 100");

        if (!result.isValid()) {
            scoreLabel.setText("N/A");
            scoreLabel.setForeground(ThemeConstants.TEXT_MUTED);
            riskBadgeLabel.setText(" INVALID URL FORMAT ");
            riskBadgeLabel.setBackground(ThemeConstants.RISK_HIGH);
            riskBadgeLabel.setForeground(Color.WHITE);
        } else if (score <= 29) {
            scoreLabel.setForeground(ThemeConstants.RISK_LOW);
            riskBadgeLabel.setText(" LOW RISK INDICATORS (" + score + " pts) ");
            riskBadgeLabel.setBackground(ThemeConstants.RISK_LOW);
            riskBadgeLabel.setForeground(Color.WHITE);
        } else if (score <= 59) {
            scoreLabel.setForeground(ThemeConstants.RISK_MODERATE);
            riskBadgeLabel.setText(" MODERATE RISK INDICATORS (" + score + " pts) ");
            riskBadgeLabel.setBackground(ThemeConstants.RISK_MODERATE);
            riskBadgeLabel.setForeground(Color.WHITE);
        } else {
            scoreLabel.setForeground(ThemeConstants.RISK_HIGH);
            riskBadgeLabel.setText(" HIGH RISK INDICATORS (" + score + " pts) ");
            riskBadgeLabel.setBackground(ThemeConstants.RISK_HIGH);
            riskBadgeLabel.setForeground(Color.WHITE);
        }

        // Render Findings Breakdown
        renderFindings(result);

        // Record to History
        history.recordScan(result);
        loadHistoryIntoTable();
    }

    /**
     * Displays rule violations inside the findings panel.
     */
    private void renderFindings(AnalysisResult result) {
        findingsListPanel.removeAll();

        if (!result.isValid()) {
            JPanel item = new JPanel(new BorderLayout(5, 5));
            item.setBackground(ThemeConstants.BG_CARD_LIGHT);
            item.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 4, 0, 0, ThemeConstants.RISK_HIGH),
                    new EmptyBorder(8, 12, 8, 12)
            ));

            JLabel title = new JLabel("Parsing Error: " + result.getValidationMessage());
            title.setFont(ThemeConstants.FONT_BODY_BOLD);
            title.setForeground(ThemeConstants.RISK_HIGH);
            item.add(title, BorderLayout.NORTH);

            JLabel desc = new JLabel("The provided string cannot be parsed as a valid URI. Ensure proper formatting.");
            desc.setFont(ThemeConstants.FONT_BODY);
            desc.setForeground(ThemeConstants.TEXT_SECONDARY);
            item.add(desc, BorderLayout.CENTER);

            findingsListPanel.add(item);
        } else if (result.getViolations().isEmpty()) {
            JPanel item = new JPanel(new BorderLayout(5, 5));
            item.setBackground(ThemeConstants.BG_CARD_LIGHT);
            item.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 4, 0, 0, ThemeConstants.RISK_LOW),
                    new EmptyBorder(10, 14, 10, 14)
            ));

            JLabel title = new JLabel("✓ No Heuristic Anomalies Flagged");
            title.setFont(ThemeConstants.FONT_BODY_BOLD);
            title.setForeground(ThemeConstants.RISK_LOW);
            item.add(title, BorderLayout.NORTH);

            JLabel desc = new JLabel("This URL does not trigger any of PhishGuard's static risk indicators (Score: 0/100).");
            desc.setFont(ThemeConstants.FONT_BODY);
            desc.setForeground(ThemeConstants.TEXT_SECONDARY);
            item.add(desc, BorderLayout.CENTER);

            findingsListPanel.add(item);
        } else {
            List<RuleViolation> violations = result.getViolations();
            for (int i = 0; i < violations.size(); i++) {
                RuleViolation v = violations.get(i);
                JPanel item = new JPanel(new BorderLayout(5, 5));
                item.setBackground(ThemeConstants.BG_CARD_LIGHT);

                Color borderCol = "HIGH".equals(v.getSeverity()) ? ThemeConstants.RISK_HIGH :
                        ("MODERATE".equals(v.getSeverity()) ? ThemeConstants.RISK_MODERATE : ThemeConstants.ACCENT_CYAN);

                item.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 4, 0, 0, borderCol),
                        new EmptyBorder(8, 12, 8, 12)
                ));

                JLabel title = new JLabel(String.format("%d. [ +%d pts ]  %s", (i + 1), v.getPoints(), v.getTitle()));
                title.setFont(ThemeConstants.FONT_BODY_BOLD);
                title.setForeground(ThemeConstants.TEXT_PRIMARY);
                item.add(title, BorderLayout.NORTH);

                JLabel desc = new JLabel("<html><body style='width: 550px;'>" + v.getExplanation() + "</body></html>");
                desc.setFont(ThemeConstants.FONT_BODY);
                desc.setForeground(ThemeConstants.TEXT_SECONDARY);
                item.add(desc, BorderLayout.CENTER);

                findingsListPanel.add(item);
                findingsListPanel.add(Box.createVerticalStrut(8));
            }
        }

        findingsListPanel.revalidate();
        findingsListPanel.repaint();
    }

    /**
     * Cycles through built-in educational sample URLs.
     */
    private void cycleSampleUrl() {
        urlInputField.setText(SAMPLE_URLS[sampleIndex]);
        sampleIndex = (sampleIndex + 1) % SAMPLE_URLS.length;
        performAnalysis();
    }

    /**
     * Clears user input and resets visual indicators.
     */
    private void clearInputsAndResults() {
        urlInputField.setText("");
        currentResult = null;
        scoreLabel.setText("-- / 100");
        scoreLabel.setForeground(ThemeConstants.ACCENT_CYAN);
        riskBadgeLabel.setText(" AWAITING ANALYSIS ");
        riskBadgeLabel.setBackground(ThemeConstants.BG_CARD_LIGHT);
        riskBadgeLabel.setForeground(ThemeConstants.TEXT_SECONDARY);
        schemeValueLabel.setText("None");
        hostValueLabel.setText("None");
        lengthValueLabel.setText("0 chars");
        statusValueLabel.setText("Ready");
        statusValueLabel.setForeground(ThemeConstants.TEXT_PRIMARY);
        displayInitialFindingsPrompt();
    }

    /**
     * Copies the current analysis report to clipboard.
     */
    private void copyCurrentReport() {
        if (currentResult == null) {
            JOptionPane.showMessageDialog(this, "Please run an analysis first before copying.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        boolean success = ReportExporter.copyToClipboard(currentResult.toFullReport());
        if (success) {
            JOptionPane.showMessageDialog(this, "PhishGuard analysis report copied to clipboard!", "Report Copied", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Exports the report to a plain text file.
     */
    private void exportCurrentReport() {
        if (currentResult == null) {
            JOptionPane.showMessageDialog(this, "Please run an analysis first before exporting.", "No Data", JOptionPane.WARNING_MESSAGE);
            return;
        }
        String defaultName = "PhishGuard_Report_" + System.currentTimeMillis() + ".txt";
        ReportExporter.exportReportToFile(this, currentResult.toFullReport(), defaultName);
    }

    /**
     * Loads historical records from CSV into the JTable.
     */
    private void loadHistoryIntoTable() {
        historyTableModel.setRowCount(0);
        List<ScanHistory.Entry> entries = history.loadHistory();
        for (ScanHistory.Entry e : entries) {
            historyTableModel.addRow(new Object[]{
                    e.getTimestamp(),
                    e.getUrl(),
                    e.getScore(),
                    e.getCategory(),
                    e.getExplanation()
            });
        }
    }

    /**
     * Prompts confirmation before clearing scan history.
     */
    private void promptClearHistory() {
        int confirm = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to delete all local scan history?\nThis action cannot be undone.",
                "Confirm Clear History",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (confirm == JOptionPane.YES_OPTION) {
            boolean cleared = history.clearHistory();
            if (cleared) {
                loadHistoryIntoTable();
                JOptionPane.showMessageDialog(this, "Scan history cleared successfully.", "History Cleared", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    // =========================================================================
    // UI HELPER UTILITIES
    // =========================================================================

    private JPanel createCardPanel() {
        JPanel card = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(ThemeConstants.BG_CARD);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                g2.setColor(ThemeConstants.BORDER_COLOR);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        return card;
    }

    private JButton createStyledButton(String text, Color bg, Color fg) {
        JButton button = new JButton(text);
        button.setFont(ThemeConstants.FONT_BODY_BOLD);
        button.setBackground(bg);
        button.setForeground(fg);
        button.setOpaque(true);
        button.setContentAreaFilled(true);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(bg.darker(), 1),
                new EmptyBorder(8, 14, 8, 14)
        ));
        return button;
    }
}

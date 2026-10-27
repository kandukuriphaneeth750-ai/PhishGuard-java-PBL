package com.phishguard.util;

import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 * Utility for exporting PhishGuard reports to the system clipboard or saving
 * them as plain text files on the user's filesystem.
 */
public class ReportExporter {

    /**
     * Copies the provided report text directly to the system clipboard.
     *
     * @param text The text to copy.
     * @return true if successful, false otherwise.
     */
    public static boolean copyToClipboard(String text) {
        if (text == null) return false;
        try {
            StringSelection selection = new StringSelection(text);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(selection, selection);
            return true;
        } catch (Exception e) {
            System.err.println("[PhishGuard] Clipboard error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Displays a file save dialog and writes the report content to the chosen file.
     *
     * @param parentComponent Parent Swing component for dialog centering.
     * @param content The text report content to export.
     * @param defaultFileName The suggested file name (e.g. "PhishGuard_Report.txt").
     * @return The saved File if successful, or null if cancelled or failed.
     */
    public static File exportReportToFile(Component parentComponent, String content, String defaultFileName) {
        if (content == null || content.trim().isEmpty()) {
            JOptionPane.showMessageDialog(
                    parentComponent,
                    "No analysis report available to export.",
                    "Export Warning",
                    JOptionPane.WARNING_MESSAGE
            );
            return null;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export PhishGuard Analysis Report");
        fileChooser.setSelectedFile(new File(defaultFileName));
        fileChooser.setFileFilter(new FileNameExtensionFilter("Text Files (*.txt)", "txt"));

        int userSelection = fileChooser.showSaveDialog(parentComponent);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().toLowerCase().endsWith(".txt")) {
                fileToSave = new File(fileToSave.getParentFile(), fileToSave.getName() + ".txt");
            }

            try (BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8))) {
                writer.write(content);
                JOptionPane.showMessageDialog(
                        parentComponent,
                        "Report successfully saved to:\n" + fileToSave.getAbsolutePath(),
                        "Export Successful",
                        JOptionPane.INFORMATION_MESSAGE
                );
                return fileToSave;
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(
                        parentComponent,
                        "Failed to save file: " + ex.getMessage(),
                        "Export Error",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        }
        return null;
    }
}

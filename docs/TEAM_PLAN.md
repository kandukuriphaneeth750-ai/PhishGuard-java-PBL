# PhishGuard — Team Plan & Role Allocation (4 Members)

**Project Title:** PhishGuard — Rule-Based Suspicious URL Analyzer  
**Course:** Problem-Based Learning (PBL) in Java  
**Exhibition Date:** 12 November 2026  
**Academic Year:** 2026–2027  

---

## 1. Team Identification Details (Editable Placeholders)

| Role / Responsibility | Student Full Name | Roll / Registration Number | Branch / Division | Email / Contact |
|---|---|---|---|---|
| **Member 1 (Backend Engine)** | `[Student 1 Name]` | `[Roll Number 1]` | `[Branch / Div]` | `[email1@college.edu]` |
| **Member 2 (UI / UX Swing)** | `[Student 2 Name]` | `[Roll Number 2]` | `[Branch / Div]` | `[email2@college.edu]` |
| **Member 3 (Persistence & QA)** | `[Student 3 Name]` | `[Roll Number 3]` | `[Branch / Div]` | `[email3@college.edu]` |
| **Member 4 (Docs & Presentation)** | `[Student 4 Name]` | `[Roll Number 4]` | `[Branch / Div]` | `[email4@college.edu]` |

**Faculty Guide / Mentor:** `[Prof. / Dr. Faculty Mentor Name]`  
**Department:** `[Department of Computer Engineering / IT]`  
**College / Institute:** `[College of Engineering & Technology Name]`  

---

## 2. Work Breakdown Structure (WBS)

### Member 1: Java URL Analyzer & Heuristic Rules
* **Core Responsibilities:**
  1. Implemented `UrlAnalyzer.java` and `RuleViolation.java`.
  2. Implemented URI parsing using standard `java.net.URI` without third-party network libraries.
  3. Developed detection logic for:
     - Unencrypted HTTP protocol (+10 pts)
     - Character length thresholds (>100 and >180 chars, +10 pts each)
     - Embedded `@` symbol userinfo spoofing (+20 pts)
     - IPv4 hostname regular expression matching (+20 pts)
     - Sensitive keyword matching in domain/path (+10 pts)
     - Subdomain depth counting (+10 pts)
     - Punycode IDN homograph detection (`xn--`, +10 pts)
     - Known URL shortener matching (`bit.ly`, `tinyurl.com`, etc., +15 pts)
     - Suspicious digit sequences (+5 pts)
  4. Formulated the risk scoring formula and score capping (max 100 points).
* **Viva Focus Areas:** Object-Oriented Programming (OOP) concepts, Regular Expressions (`java.util.regex`), String manipulation, and RFC 3986 URL parsing.

---

### Member 2: Java Swing GUI & User Interaction
* **Core Responsibilities:**
  1. Designed the visual theme tokens in `ThemeConstants.java` (Dark Navy `#0B132B`, Cyan Accent `#00E5FF`, Card styling).
  2. Implemented `MainFrame.java` using Swing layout managers (`BorderLayout`, `GridBagLayout`, `GridLayout`, `FlowLayout`).
  3. Constructed the interactive controls:
     - URL text entry field with enter-key trigger
     - "⚡ Analyze URL" primary action button
     - "🎲 Sample URL" multi-case cycling button
     - "✖ Clear" input reset button
  4. Built the dynamic score card and colored risk badge (`Low`, `Moderate`, `High`).
  5. Implemented the findings card rendering individual rule cards with severity-colored borders.
  6. Managed thread-safe UI execution on the Swing Event Dispatch Thread (`SwingUtilities.invokeLater`).
* **Viva Focus Areas:** Java Swing components, Layout Managers, Event-Driven Architecture (`ActionListener`), Graphics2D custom rendering, and Event Dispatch Thread (EDT) safety.

---

### Member 3: Scan History, File I/O & Automated Testing
* **Core Responsibilities:**
  1. Developed `ScanHistory.java` for local persistent storage in `data/scan_history.csv`.
  2. Implemented RFC 4180 CSV escaping for commas, quotes, and newlines.
  3. Hardened data storage against **CSV Formula Injection** attacks (prepending `'` to `=`, `+`, `-`, `@`, `\t`, `\r`).
  4. Built history table integration in `MainFrame` with click-to-load functionality and clear confirmation dialogs.
  5. Implemented `ReportExporter.java` supporting system clipboard copying and `.txt` file export via `JFileChooser`.
  6. Authored `PhishGuardTestRunner.java` validating 13 automated test suites covering edge cases, empty input, and boundary scores.
* **Viva Focus Areas:** Java File I/O (`BufferedReader`, `BufferedWriter`), Character encoding (UTF-8), Defensive programming, CSV Formula Injection vulnerability, and Automated Testing.

---

### Member 4: Documentation, GitHub Organization & Exhibition Coordination
* **Core Responsibilities:**
  1. Maintained project structure and repository hygiene (`.gitignore`, `LICENSE`, `compile.bat`, `run.bat`, `test.bat`).
  2. Authored the comprehensive college project report (`docs/PROJECT_REPORT.md`).
  3. Documented formal test specifications in `docs/TEST_CASES.md`.
  4. Prepared the 25+ college viva questions and answers in `docs/VIVA_QUESTIONS.md`.
  5. Created the beginner environment onboarding guide in `docs/BEGINNER_SETUP.md`.
  6. Coordinated integration between backend, UI, and test suites, ensuring 100% working buttons.
  7. Designed the 5–7 minute college exhibition live demonstration script.
* **Viva Focus Areas:** Software Engineering Lifecycle, Problem Statement, Heuristic vs Machine Learning trade-offs, Project Limitations, and Demonstration delivery.

---

## 3. Team Readiness & Peer Verification Checklist

- [x] Every team member can explain the overall system architecture.
- [x] Every team member knows why PhishGuard operates 100% offline (ethical and safety considerations).
- [x] Every team member can locate and compile the Java source code from the command line.
- [x] Every team member is prepared to answer questions from `docs/VIVA_QUESTIONS.md`.
- [x] All team member names, roll numbers, and guide details are verified before final submission.

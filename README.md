# 🛡️ PhishGuard — Rule-Based Suspicious URL Analyzer

> **A polished, beginner-friendly Java cybersecurity desktop application developed for the College Java Problem-Based Learning (PBL) Exhibition (12 November 2026).**

[![Java](https://img.shields.io/badge/Java-17%2B%20LTS-007396?style=flat&logo=openjdk&logoColor=white)](https://adoptium.net)
[![GUI](https://img.shields.io/badge/GUI-Java%20Swing-blue?style=flat)](https://docs.oracle.com/en/java/)
[![Architecture](https://img.shields.io/badge/Architecture-Modular%20OOP-success?style=flat)]()
[![Offline](https://img.shields.io/badge/Security-100%25%20Offline%20Heuristics-00E5FF?style=flat)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Project Overview

**PhishGuard** is an interactive desktop application that inspects and evaluates suspicious web links (URLs) using a deterministic, rule-based heuristic scoring engine. Built purely in Java without heavy external dependencies, it demonstrates foundational Object-Oriented Programming (OOP) concepts, graphical user interface (GUI) design with Java Swing, defensive programming, and secure local file I/O.

### Why PhishGuard?
- **100% Offline & Safe by Design:** Operates completely on local machine memory using `java.net.URI`. It **never** sends web traffic, contacts remote servers, downloads payloads, or opens live URLs in a browser.
- **Educational Transparency:** Unlike complex black-box machine learning models, PhishGuard clearly explains **why** an indicator is suspicious (e.g., raw IP hosts, embedded `@` credential tricks, excessive subdomains).
- **College Exhibition Ready:** Features a modern dark navy and cyan dashboard with real-time score indicators, findings breakdowns, scan history tracking, clipboard copying, and text report export.

---

## 🎨 Visual Interface & Dashboard Features

The application is styled with a sleek, cybersecurity-themed dark navy palette:
- **Base Background:** Deep Midnight Navy (`#0B132B`)
- **Card Surfaces:** Rich Navy (`#1C2541`) with smooth antialiased borders
- **Accents:** Electric Cyan (`#00E5FF`) and Oceanic Blue (`#0284C7`)
- **Risk Indicators:** Emerald Green (`Low`), Amber Orange (`Moderate`), Crimson Red (`High`)

### Main Dashboard Components:
1. **Header Emblem:** PhishGuard shield branding and exhibition subtitle.
2. **URL Input Field:** Accepts any URL string for instant inspection (supports Enter key submission).
3. **⚡ Analyze URL Button:** Runs the 10-heuristic rule engine.
4. **🎲 Sample URL Button:** Cycles through 7 pre-curated test cases ranging from clean HTTPS domains to complex phishing simulations.
5. **✖ Clear Button:** Resets all inputs, cards, and indicators.
6. **Risk Score Card:** Visual display of the computed score (0 to 100).
7. **Risk Category Badge:** Dynamic colored pill (`Low Risk Indicators`, `Moderate Risk Indicators`, `High Risk Indicators`).
8. **Summary Panel:** Shows parsed scheme, identified host, length in characters, and validation state.
9. **Findings Breakdown:** Lists each triggered heuristic indicator with severity tags, points awarded, and plain-English explanations.
10. **Action Toolbar:** 
    - `📋 Copy Full Report`: Copies formatted text report to system clipboard.
    - `💾 Export to Text File`: Saves analysis report to `.txt` file via file chooser.
11. **Scan History Tab:** Displays persistent historical records with click-to-reload and clear history confirmation.
12. **About & Limitations Tab:** Clearly explains that static rules are educational heuristics and do not guarantee web safety.

---

## 🧠 Heuristic Detection Rules & Scoring Matrix

The risk score starts at 0, accumulates points based on triggered rules, and is capped at **100**:

| Rule ID | Heuristic Indicator | Penalty | Rationale & Security Context |
|---|---|---|---|
| `RULE_HTTP` | Unencrypted HTTP Protocol | **+10 pts** | Transmits data in cleartext; phishers avoid SSL or use unencrypted connections. |
| `RULE_LENGTH_100` | Length > 100 characters | **+10 pts** | Long URLs obscure the true destination domain in address bars. |
| `RULE_LENGTH_180` | Length > 180 characters | **+10 pts** | Extreme length is heavily correlated with token-stuffing or encoded payloads. |
| `RULE_AT_SYMBOL` | Embedded `@` symbol | **+20 pts** | Exploits browser credential parsing (`legit.com@attacker.com`) to mislead users. |
| `RULE_IP_HOST` | Raw IPv4 Address Hostname | **+20 pts** | Direct IP addresses (e.g., `192.168.1.1`) bypass DNS reputation and domain checks. |
| `RULE_SUSPICIOUS_WORD` | Sensitive Keywords | **+10 pts** | Keywords like `login`, `verify`, `banking`, `account`, `update` lure victims. |
| `RULE_EXCESSIVE_SUBDOMAINS` | Excessive Subdomains (≥ 3) | **+10 pts** | Stacking brand names before attacker domains (e.g. `paypal.com.evil.xyz`). |
| `RULE_PUNYCODE` | Punycode IDN (`xn--`) | **+10 pts** | Homograph attacks using foreign lookalike characters to spoof authentic brands. |
| `RULE_URL_SHORTENER` | Known URL Shortener | **+15 pts** | Services like `bit.ly` or `tinyurl.com` mask the destination domain. |
| `RULE_DIGIT_SEQUENCE` | Long Digit Sequence (≥ 4) | **+5 pts** | Characteristic of dynamically generated or temporary disposable burner domains. |

### Classification Thresholds:
- **0–29 Points:** `Low Risk Indicators` (Clean, standard domains)
- **30–59 Points:** `Moderate Risk Indicators` (Unusual attributes detected)
- **60–100 Points:** `High Risk Indicators` (Multiple severe phishing patterns)

---

## 📂 Project Directory Structure

```
PhishGuard project/
├── src/
│   └── com/
│       └── phishguard/
│           ├── Main.java               # Application entry point & Swing EDT launcher
│           ├── model/
│           │   ├── AnalysisResult.java # URL analysis data model & report generator
│           │   └── RuleViolation.java  # Individual rule violation entity
│           ├── analyzer/
│           │   └── UrlAnalyzer.java    # Pure Java heuristic parsing & scoring engine
│           ├── history/
│           │   └── ScanHistory.java    # Local CSV logger with formula injection protection
│           ├── ui/
│           │   ├── MainFrame.java      # Complete Swing dark navy dashboard
│           │   └── ThemeConstants.java # Design system tokens (colors, fonts, borders)
│           └── util/
│               └── ReportExporter.java # Clipboard copy & file export helper
├── test/
│   └── com/
│       └── phishguard/
│           └── PhishGuardTestRunner.java # Dependency-free automated test runner (13 test suites)
├── docs/
│   ├── BEGINNER_SETUP.md               # Step-by-step setup, compilation, and exhibition demo guide
│   ├── PROJECT_REPORT.md               # Full college project report (abstract, architecture, algorithms)
│   ├── TEST_CASES.md                   # Formal test specification and verification results
│   ├── VIVA_QUESTIONS.md               # 28 technical viva questions and answers
│   └── TEAM_PLAN.md                    # 4-member roles, responsibilities, and placeholders
├── data/
│   └── scan_history.csv                # Persistent local scan log (auto-generated)
├── compile.bat                         # 1-click Windows compilation script
├── run.bat                             # 1-click Windows application launcher
├── test.bat                            # 1-click Windows test suite runner
├── .gitignore                          # Standard git ignore file
├── LICENSE                             # MIT Open-Source License
└── README.md                           # Master project documentation
```

---

## 🚀 Quick Start Guide (Windows)

### Prerequisites:
- **Operating System:** Windows 10 or 11 (also portable to macOS/Linux).
- **Java:** Java 17 LTS or newer.

### 1-Click Execution (No Terminal Required):
1. **Compile:** Double-click `compile.bat`.
2. **Run App:** Double-click `run.bat`.
3. **Run Tests:** Double-click `test.bat`.

### Command-Line Execution (via Terminal):
Open a terminal in the project directory and run:

```powershell
# 1. Compile source and test files into bin/
javac -encoding UTF-8 -d bin src\com\phishguard\model\*.java src\com\phishguard\analyzer\*.java src\com\phishguard\history\*.java src\com\phishguard\util\*.java src\com\phishguard\ui\*.java src\com\phishguard\Main.java test\com\phishguard\PhishGuardTestRunner.java

# 2. Launch the Desktop Application
java -cp bin com.phishguard.Main

# 3. Execute the Automated Test Suite
java -cp bin com.phishguard.PhishGuardTestRunner
```

> **Need help installing Java?** Read our detailed, picture-clear [docs/BEGINNER_SETUP.md](docs/BEGINNER_SETUP.md).

---

## 🧪 Automated Testing & Verification

PhishGuard includes an automated, dependency-free test runner (`PhishGuardTestRunner.java`) that verifies all 13 critical requirements:
- ✅ Empty and whitespace input handling
- ✅ Clean HTTPS baseline domains (0 pts)
- ✅ Unencrypted HTTP detection (+10 pts)
- ✅ Raw IPv4 address detection (+20 pts)
- ✅ Embedded `@` credential spoofing (+20 pts)
- ✅ Length boundary conditions (>100 and >180 chars)
- ✅ Sensitive keyword recognition
- ✅ Punycode IDN homograph detection (`xn--`)
- ✅ Known URL shortener matching
- ✅ Malformed URL input handling
- ✅ Score capping at 100 max
- ✅ Local CSV history persistence and reload
- ✅ CSV Formula Injection neutralization

Run `test.bat` to execute the full suite. All 13 tests execute and pass in under 1 second.

---

## 🌐 GitHub Repository Upload Guide

Follow these beginner steps to upload PhishGuard to GitHub:

1. **Create a GitHub Account:** If you don't have one, visit [https://github.com](https://github.com) and sign up for free.
2. **Create a New Repository:**
   - Click the **`+`** icon in the top right corner and choose **New repository**.
   - Repository Name: `PhishGuard-Java-PBL`
   - Description: `Rule-Based Suspicious URL Analyzer desktop application built in Java Swing for College PBL Exhibition.`
   - Set visibility to **Public**.
   - Do **not** initialize with a README, .gitignore, or license (we already created them locally).
   - Click **Create repository**.
3. **Push from your Terminal:**
   Open the terminal inside `c:\Users\yedav\PhishGuard project` and run:
   ```powershell
   git init
   git add .
   git commit -m "Initial commit: Complete PhishGuard Java PBL Project"
   git branch -M main
   git remote add origin https://github.com/<YOUR-GITHUB-USERNAME>/PhishGuard-Java-PBL.git
   git push -u origin main
   ```
4. **Verify on GitHub:** Refresh your GitHub repository page. You will see your clean Java source code, documentation folder, and batch scripts ready for submission!

---

## 👥 Four-Person College Team Roles

| Member | Full Name (Placeholder) | Roll Number | Primary Assigned Responsibilities |
|---|---|---|---|
| **Member 1** | `[Student 1 Name]` | `[Roll Number 1]` | URL Analyzer logic, URI parsing, scoring rules, and regex heuristics. |
| **Member 2** | `[Student 2 Name]` | `[Roll Number 2]` | Swing GUI dashboard, Theme tokens, layout managers, and interactive controls. |
| **Member 3** | `[Student 3 Name]` | `[Roll Number 3]` | Scan history persistence, CSV formula injection defense, and automated testing. |
| **Member 4** | `[Student 4 Name]` | `[Roll Number 4]` | Project documentation, GitHub management, system integration, and presentation. |

**Faculty Mentor:** `[Prof. / Dr. Faculty Mentor Name]`  
**College:** `[College of Engineering & Technology Name]`  

---

## ⚠️ Important Educational Disclaimer

PhishGuard evaluates URLs strictly using **static educational heuristics**. 
- A **low score** does **NOT** guarantee that a URL or website is harmless.
- A **high score** does **NOT** definitively prove criminal intent.
- Always verify website certificates, enable multi-factor authentication (MFA), and never submit passwords on untrusted pages.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — free for educational and academic use.

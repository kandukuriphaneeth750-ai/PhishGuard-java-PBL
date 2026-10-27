# PhishGuard — Beginner Setup, Execution & Exhibition Guide

Welcome! This guide is written specifically for students and beginners. It explains everything you need to know in simple language, with step-by-step instructions.

---

## 1. Important Concepts: Understanding Your Environment

Before touching any commands, understand these three distinct terms:

1. **Google Antigravity:**  
   This is your development environment and coding agent. You are currently viewing your project inside Antigravity. It provides your file explorer, code editor, and built-in terminal.
2. **JDK (Java Development Kit):**  
   This is the underlying software package required on your Windows computer to build and run Java applications. It contains:
   - `javac`: The compiler that translates your `.java` text code into `.class` bytecode.
   - `java`: The runtime that executes the compiled bytecode.
3. **Java Application (PhishGuard):**  
   This is the software program we built. It lives in this folder and consists of Java source files (`src/com/phishguard/...`).

---

## 2. Locating Your Project Files

Your project is located on your computer at:
```
c:\Users\yedav\PhishGuard project
```

Key folders and files:
- `src/` — Contains all Java source code (`.java` files).
- `test/` — Contains the automated test runner.
- `docs/` — Contains the Project Report, Test Cases, Viva Q&A, and Team Plan.
- `compile.bat` — 1-click Windows compilation script.
- `run.bat` — 1-click script to launch the GUI dashboard.
- `test.bat` — 1-click script to run all 13 automated tests.
- `data/` — Automatically stores your `scan_history.csv` log.

---

## 3. How to Check and Install the Java Development Kit (JDK)

### Step 3.1: Check if Java is Installed
1. In Google Antigravity, open a Terminal (press `` Ctrl + ` `` or select **Terminal > New Terminal** from the menu).
2. Type the following command and press **Enter**:
   ```powershell
   java -version
   javac -version
   ```
3. If both commands print version numbers (e.g., `openjdk version "17.0.x"`), **Java is already installed!** You can jump straight to Section 4.

---

### Step 3.2: If Java is Missing or Not Recognized

If you see an error like:
> *'java' is not recognized as an internal or external command*

Follow these simple steps:

#### Method A: Fast Automated Install via Winget (Recommended)
1. Open your Antigravity terminal (or Windows PowerShell).
2. Type this command and press **Enter**:
   ```powershell
   winget install EclipseAdoptium.Temurin.17.JDK
   ```
3. If Windows displays a User Account Control (UAC) prompt asking for permission, click **Yes**.
4. Once installation finishes, **close the terminal and open a new terminal** in Antigravity.
5. Verify by typing `javac -version`. It will now show `javac 17.x.x`!

#### Method B: Manual Installer Download (Alternative)
1. Open your web browser and go to the official Eclipse Adoptium page:  
   **[https://adoptium.net/temurin/releases/?version=17](https://adoptium.net/temurin/releases/?version=17)**
2. Select:
   - **Operating System:** Windows
   - **Architecture:** x64
   - **Package Type:** JDK
3. Click **Download .msi** (e.g. `OpenJDK17U-jdk_x64_windows_hotspot_17.0.x.msi`).
4. Run the downloaded installer.
5. **IMPORTANT:** On the "Custom Setup" screen during installation, ensure **"Set JAVA_HOME variable"** and **"Add to PATH"** are selected to **"Will be installed on local hard drive"**.
6. Click Next until complete, then restart Antigravity.

---

## 4. How to Compile and Run PhishGuard

### Option 1: Using the 1-Click Batch Scripts (Easiest)

1. Open your Windows File Explorer and navigate to:
   `c:\Users\yedav\PhishGuard project`
2. **Double-click `compile.bat`**:  
   This will automatically build all Java files and create the `bin/` directory.
3. **Double-click `run.bat`**:  
   This launches the PhishGuard desktop cybersecurity dashboard!
4. **Double-click `test.bat`**:  
   This runs the 13 automated test suites and displays the test report.

---

### Option 2: Using the Terminal Commands

If you prefer using the terminal in Antigravity:

1. Open the terminal inside `c:\Users\yedav\PhishGuard project`.
2. Compile the application and test files:
   ```powershell
   javac -encoding UTF-8 -d bin src\com\phishguard\model\*.java src\com\phishguard\analyzer\*.java src\com\phishguard\history\*.java src\com\phishguard\util\*.java src\com\phishguard\ui\*.java src\com\phishguard\Main.java test\com\phishguard\PhishGuardTestRunner.java
   ```
3. Run the GUI Dashboard:
   ```powershell
   java -cp bin com.phishguard.Main
   ```
4. Run the automated tests:
   ```powershell
   java -cp bin com.phishguard.PhishGuardTestRunner
   ```

---

## 5. How to Stop the Application

- To close PhishGuard, simply click the standard window close button (**`X`**) in the top-right corner of the application window.
- If launched from the terminal, you can also press **`Ctrl + C`** in the terminal to terminate it.

---

## 6. How to Make a Safe Backup Before Editing

Before making any changes:
1. Open Windows File Explorer.
2. Select your folder `PhishGuard project`.
3. Press `Ctrl + C` (Copy), then `Ctrl + V` (Paste).
4. Windows will create `PhishGuard project - Copy`.
5. If anything ever breaks while you experiment, your backup copy is safe!

---

## 7. Troubleshooting Common Errors

| Error Message | Cause | Simple Solution |
|---|---|---|
| `'javac' is not recognized` | JDK is missing or not in system PATH | Install JDK 17 using Winget or the Adoptium installer (Section 3). Restart Antigravity after installing. |
| `Could not find or load main class com.phishguard.Main` | Application has not been compiled into `bin/` | Run `compile.bat` or run the `javac` command from Section 4. |
| `Cannot find symbol` during compilation | A file was moved or deleted | Ensure all files in `src/com/phishguard/...` exist as created. |
| UI opens but looks small or distorted | Windows display scaling | Right-click the app window, or adjust Windows display scale to 100% or 125%. |

---

## 8. College Exhibition Live Demonstration Script (5–7 Minutes)

When presenting PhishGuard to professors, external examiners, or exhibition visitors, follow this proven script:

### Minute 1: Problem & Introduction
- *"Respected teachers and visitors, good morning. We are presenting our Java PBL project: **PhishGuard — Rule-Based Suspicious URL Analyzer**."*
- *"Phishing attacks are one of the most common cyber threats today. Many victims click malicious links because modern URLs look confusing or intentionally disguise the true destination."*
- *"PhishGuard is an educational desktop tool built in Java and Java Swing that performs 100% offline heuristic analysis to expose suspicious patterns in URLs without making any risky network connections."*

### Minute 2: Launch & UI Walkthrough
- Open the application using `run.bat`.
- Point to the screen:
  - *"Our interface is designed with a modern dark navy cybersecurity aesthetic."*
  - *"At the top is our target URL input. In the center is our Risk Score card, URL Component breakdown, and Triggered Findings panel."*
  - *"At the bottom, we have quick export tools and a persistent scan history log."*

### Minute 3: Clean URL Demonstration (Baseline)
- Click **"🎲 Sample URL"** until `https://www.google.com/search?q=cybersecurity` is displayed.
- Click **"⚡ Analyze URL"**.
- Explain:
  - *"Notice the score is 0 / 100 with a green 'LOW RISK INDICATORS' badge."*
  - *"The Findings panel confirms that no suspicious anomalies were detected because it uses standard HTTPS, a verified domain, and no deceptive characters."*

### Minute 4: Suspicious URL Demonstration (Multiple Heuristics)
- Click **"🎲 Sample URL"** to select:
  `http://secure-login-account-update.banking-verify.xyz/auth?user=victim`
- Click **"⚡ Analyze URL"**.
- Explain the triggered findings to the examiner:
  1. *"+10 pts for unencrypted HTTP instead of HTTPS."*
  2. *"+10 pts for sensitive keywords ('login', 'account', 'verify', 'update')."*
  3. *"+10 pts for excessive subdomain levels."*
  - *"The overall score rises into the Moderate/High risk range with clear color-coded cards explaining why each indicator matters."*

### Minute 5: Advanced Indicators & Edge Cases
- Test a raw IP address URL: `http://192.168.1.105/login.html` (Flags raw IPv4 host).
- Test credential spoofing: `http://legit.com@attacker-site.com/auth` (Flags embedded `@` symbol).
- Test a blank or invalid input (Demonstrate defensive exception handling and clear user alerts without crashing).

### Minute 6: History Persistence & Export
- Switch to the **"Scan History Log"** tab:
  - *"Every scan is automatically recorded into a local CSV file (`data/scan_history.csv`). Notice that we implemented protection against CSV formula injection attacks."*
  - *"We can click any past row to re-load that URL."*
- Click **"📋 Copy Full Report"** or **"💾 Export to Text File"** to demonstrate report generation.

### Minute 7: Java OOP Concepts & Conclusion
- Summarize the Java concepts used:
  - *Encapsulation in our models (`AnalysisResult`, `RuleViolation`).*
  - *Separation of concerns between logic (`UrlAnalyzer`) and UI (`MainFrame`).*
  - *Safe collections (`ArrayList`, `HashSet`), regex pattern matching, and file I/O.*
- Conclude:
  - *"PhishGuard demonstrates how clean object-oriented Java can be applied to real-world cybersecurity awareness. Thank you, and we welcome your questions!"*

# PhishGuard — Comprehensive College Viva Questions & Answers

**Course:** Problem-Based Learning (PBL) in Java  
**Project:** PhishGuard — Rule-Based Suspicious URL Analyzer  
**Exhibition Date:** 12 November 2026  
**Audience:** College Java Examination, External Examiner Viva Voce  

This guide provides 28 structured viva questions and answers categorized by topic to prepare every team member thoroughly for technical viva questions.

---

## Section 1: Java Core & Object-Oriented Programming (OOP)

### Q1: What is Object-Oriented Programming, and how does PhishGuard implement it?
**Answer:**  
Object-Oriented Programming (OOP) is a programming paradigm based on the concept of "objects", which contain data (fields) and code (methods). PhishGuard implements OOP principles by dividing the application into modular, single-responsibility classes:
- **`UrlAnalyzer`**: Encapsulates parsing and heuristic scoring logic.
- **`AnalysisResult`** and **`RuleViolation`**: Represent immutable data entities holding analysis state.
- **`ScanHistory`**: Manages persistent file operations.
- **`MainFrame`**: Constructs the user interface and coordinates user events.

### Q2: How is Encapsulation demonstrated in PhishGuard?
**Answer:**  
Encapsulation means bundling data and methods inside a class while hiding internal state from the outside world. In `RuleViolation` and `AnalysisResult`, all member variables (such as `score`, `host`, `violations`) are declared `private final`. External classes access these values strictly through `public` getter methods (`getScore()`, `getHost()`), preventing unauthorized mutation.

### Q3: What is the difference between a class and an object?
**Answer:**  
A **class** is a blueprint or template (e.g., `AnalysisResult`), while an **object** is a concrete instance of that class created in memory using the `new` keyword (e.g., the specific result generated when analyzing `"https://example.com"`).

### Q4: Why are constructors used in PhishGuard?
**Answer:**  
Constructors are special methods invoked when an object is instantiated to initialize its state. For instance, `RuleViolation(ruleId, title, points, explanation, severity)` sets all mandatory properties at creation time, ensuring that incomplete or uninitialized violation objects cannot exist.

### Q5: What collections are used in the project and why?
**Answer:**  
- **`ArrayList<RuleViolation>`**: Used to store an ordered list of triggered indicators dynamically as rules are evaluated.
- **`HashSet<String>`**: Used in `UrlAnalyzer` for `SUSPICIOUS_KEYWORDS` and `URL_SHORTENERS` because `Set.contains()` offers fast $O(1)$ average time complexity for lookups.

### Q6: How does PhishGuard handle exceptions defensively?
**Answer:**  
PhishGuard wraps risky operations in `try-catch` blocks:
- In `UrlAnalyzer`, invalid URL strings throw `URISyntaxException`, which is caught and converted into a graceful `AnalysisResult.createInvalid()` rather than crashing the program.
- In `ScanHistory`, file reading/writing uses `try-with-resources` to catch `IOException` and guarantee file streams close automatically.

---

## Section 2: URL Parsing & Heuristic Engine

### Q7: Why use `java.net.URI` instead of `java.net.URL`?
**Answer:**  
`java.net.URL` attempts to resolve hostnames via DNS during `equals()` and `hashCode()` calls, which can cause network blocking and privacy leaks. `java.net.URI` performs purely syntactic parsing according to RFC 2396/3986 without performing any network I/O, ensuring PhishGuard remains 100% offline, fast, and secure.

### Q8: What does the `@` symbol in a URL signify, and why is it dangerous?
**Answer:**  
According to URL specifications, the text between the scheme and the `@` symbol represents user credentials (`http://username:password@actual-domain.com`). Web browsers ignore whatever appears before the `@` and navigate exclusively to the host following it. Phishers use this trick (e.g., `http://paypal.com@attacker-site.com`) to visually deceive users into thinking they are visiting a legitimate site.

### Q9: How does PhishGuard detect if a hostname is an IPv4 address?
**Answer:**  
It uses a compiled Regular Expression (`java.util.regex.Pattern`) that matches four octets separated by dots, where each octet is a decimal number between 0 and 255. Legitimate companies almost always use registered domain names with TLS certificates; raw IP addresses in URLs are strongly correlated with illicit or temporary hosting.

### Q10: What is Punycode and how is it used in phishing (IDN Homograph attacks)?
**Answer:**  
Punycode translates Unicode international domain names into ASCII characters beginning with the prefix `xn--`. Attackers use it to create lookalike domains (e.g., substituting the Latin 'a' with the Cyrillic 'а'). To a user, the URL looks identical to `apple.com`, but the actual domain resolves to `xn--pple-43d.com`.

### Q11: Why are URL shorteners penalized in the scoring heuristics?
**Answer:**  
Services like `bit.ly` or `tinyurl.com` alias a destination URL behind a short link. While legitimate for social media, they conceal the real target domain from the user and security scanners before the link is opened, increasing uncertainty.

### Q12: How is the final risk score calculated and capped?
**Answer:**  
Each triggered rule contributes specific penalty points (e.g., HTTP = 10 pts, IP Host = 20 pts, `@` Symbol = 20 pts). The scores are accumulated and capped at 100 using `Math.min(100, score)`. The score maps to three categories:
- **0–29:** Low Risk Indicators
- **30–59:** Moderate Risk Indicators
- **60–100:** High Risk Indicators

---

## Section 3: Java Swing & UI Architecture

### Q13: What is Java Swing?
**Answer:**  
Java Swing is a GUI toolkit for Java providing lightweight, platform-independent desktop components such as buttons, text fields, tables, and dialogs built on top of the Abstract Window Toolkit (AWT).

### Q14: What is the Event Dispatch Thread (EDT) and why is it critical?
**Answer:**  
Swing components are not thread-safe. All visual rendering and UI events (mouse clicks, key presses) must execute on a single dedicated thread called the **Event Dispatch Thread (EDT)**. In `Main.java`, we invoke `SwingUtilities.invokeLater()` to launch the `MainFrame` safely on the EDT.

### Q15: What Layout Managers are used in PhishGuard?
**Answer:**  
- **`BorderLayout`**: Positions the header (North), dashboard (Center), and status bar (South).
- **`GridLayout`**: Organizes symmetric cards like the Score Card and Summary Panel.
- **`GridBagLayout`**: Centers the score and status badge with precise alignment.
- **`FlowLayout`**: Arranges action buttons horizontally with natural spacing.
- **`BoxLayout`**: Stacks variable lists of findings cards vertically.

### Q16: How does the "Sample URL" button work without hardcoding logic inside the button?
**Answer:**  
An array of curated sample URLs is stored in `MainFrame`. When the user clicks "🎲 Sample URL", an `ActionListener` retrieves the current index, updates the input text field, advances the index cyclically (`(index + 1) % length`), and triggers `performAnalysis()`.

### Q17: How is the modern dark navy theme achieved in Swing?
**Answer:**  
Swing's default look can look dated. We created `ThemeConstants.java` with a custom dark palette (`#0B132B` navy, `#1C2541` card surfaces, `#00E5FF` cyan accent). Panels use overridden `paintComponent()` methods with `Graphics2D` antialiasing to render smooth, rounded card backgrounds and subtle borders.

---

## Section 4: File I/O, Data Safety & Persistence

### Q18: What file format is used for scan history and where is it stored?
**Answer:**  
Scan history is saved as a Comma-Separated Values (`.csv`) file located in `data/scan_history.csv`. CSV is lightweight, human-readable, and standard across platforms without requiring external database drivers.

### Q19: What is CSV Formula Injection and how does PhishGuard prevent it?
**Answer:**  
CSV Formula Injection occurs when an untrusted string begins with execution triggers like `=`, `+`, `-`, `@`, `\t`, or `\r`. If an administrator opens that CSV file in Microsoft Excel or Google Sheets, the spreadsheet software might execute it as a formula or macro (e.g., `=cmd|'calc'!A0`). PhishGuard neutralizes this in `ScanHistory.sanitizeFormulaInjection()` by prepending a single quote (`'`), forcing spreadsheet software to treat the field strictly as plain text.

### Q20: How does PhishGuard handle RFC 4180 CSV escaping?
**Answer:**  
If a field contains a comma, double quotation mark, or newline, `ScanHistory.sanitizeForCsv()` encloses the field in double quotes and escapes any internal double quotes by doubling them (`""`), preventing data corruption when reading back the log.

### Q21: What is `try-with-resources` in Java?
**Answer:**  
Introduced in Java 7, `try-with-resources` automatically closes any resource implementing `AutoCloseable` (such as `BufferedReader`, `BufferedWriter`, or `FileOutputStream`) when the try block terminates, preventing memory leaks and locked file handles even if an unexpected exception occurs.

---

## Section 5: Cybersecurity Concepts & Limitations

### Q22: What is Phishing?
**Answer:**  
Phishing is a social engineering attack where cybercriminals impersonate trustworthy entities (such as banks, email providers, or cloud services) to deceive victims into revealing sensitive information, including usernames, passwords, or credit card numbers.

### Q23: Why does PhishGuard perform 100% offline analysis instead of checking the URL online?
**Answer:**  
1. **Safety:** Visiting malicious websites or requesting web pages from an untrusted URL could expose the user's machine to drive-by downloads or malicious scripts.
2. **Privacy:** Sending URLs to online APIs can leak confidential parameters or tokens.
3. **Exhibition Reliability:** The project operates reliably in any college environment without needing an internet connection.

### Q24: What are the main limitations of static rule-based analysis?
**Answer:**  
- **False Positives:** Legitimate developer URLs or internal tools might use long parameters or IP addresses and get flagged.
- **False Negatives:** An attacker using a newly registered, short HTTPS domain without common keywords will receive a low risk score.
- **No Content Inspection:** Heuristics cannot see what is actually hosted on the web page.

### Q25: Can a low score guarantee that a URL is safe?
**Answer:**  
**No.** A low score simply means the URL did not trigger the specific static indicators configured in PhishGuard. Cybercriminals frequently register legitimate-looking HTTPS domains that appear clean under static rules.

### Q26: Why is HTTP dangerous compared to HTTPS?
**Answer:**  
HTTP transmits all communications in plaintext. Any intermediary on the network (e.g., public Wi-Fi) can read or alter data via Man-In-The-Middle (MITM) attacks. HTTPS encrypts data using Transport Layer Security (TLS), providing confidentiality, integrity, and server authentication.

### Q27: How does PhishGuard facilitate report export?
**Answer:**  
- **Clipboard Copy:** Uses `java.awt.datatransfer.Clipboard` to copy the formatted report string into the operating system clipboard with one click.
- **File Export:** Uses `javax.swing.JFileChooser` to allow the user to select an export path and saves a clean `.txt` document with full timestamps and breakdown details.

### Q28: How could PhishGuard be improved in future versions?
**Answer:**  
Future versions could incorporate:
1. Machine learning classifiers (e.g., Random Forest or Naive Bayes) trained on datasets like PhishTank.
2. Safe sandbox DNS checks to look up domain age and WHOIS registration details.
3. Levenshtein distance calculations to automatically identify typosquatting of famous brand domains (e.g., `goog1e.com` vs `google.com`).

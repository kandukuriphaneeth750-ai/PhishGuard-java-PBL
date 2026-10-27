# PhishGuard — Rule-Based Suspicious URL Analyzer
## College Java Problem-Based Learning (PBL) Project Report

---

### Project Identification & Team Details
- **Project Title:** PhishGuard — Rule-Based Suspicious URL Analyzer
- **Course / Subject:** Problem-Based Learning in Java (PBL)
- **Academic Year:** 2026–2027
- **Submission / Exhibition Date:** 12 November 2026

#### Team Members (4 Members):
1. **`[Student 1 Name]`** — Roll No: `[Roll Number 1]` | Role: Heuristic Scoring Engine & Analysis Logic
2. **`[Student 2 Name]`** — Roll No: `[Roll Number 2]` | Role: Java Swing Dashboard & UI/UX Design
3. **`[Student 3 Name]`** — Roll No: `[Roll Number 3]` | Role: Local Persistence, Data Safety & Automated Testing
4. **`[Student 4 Name]`** — Roll No: `[Roll Number 4]` | Role: Documentation, System Integration & Exhibition Delivery

- **Faculty Guide / Mentor:** `[Prof. / Dr. Faculty Mentor Name]`
- **Department:** `[Department of Computer Engineering / Information Technology]`
- **Institution / College:** `[College of Engineering & Technology Name]`

---

## 1. Abstract
The rapid escalation of social engineering attacks, particularly phishing, poses significant threats to internet users worldwide. Phishing campaigns trick victims into divulging sensitive credentials by distributing deceptive Uniform Resource Locators (URLs). While advanced threat-detection systems often rely on dynamic sandboxing and live network crawling, such mechanisms can be dangerous, resource-intensive, and inappropriate for offline educational environments.

**PhishGuard** is an offline, desktop-based cybersecurity educational tool developed using pure Java (Java 17 LTS) and Java Swing. It parses submitted URLs strictly via RFC-compliant syntactic parsers (`java.net.URI`) and evaluates them against 10 transparent, heuristic risk rules without initiating outbound network connections. The system features a modern, dark navy dashboard with an interactive risk score meter (0–100), categorical threat indicators (Low, Moderate, High), detailed finding cards, persistent CSV scan history with formula injection defenses, and report export capabilities. This project demonstrates core Object-Oriented Programming (OOP) concepts, defensive file I/O, event-driven design, and cybersecurity fundamentals.

---

## 2. Introduction & Background
Phishing remains one of the primary attack vectors for credential theft, identity fraud, and ransomware distribution. Cybercriminals engineer deceptive links that mimic reputable institutions, utilizing obfuscation techniques such as raw IP addresses, userinfo credential spoofing (`@`), multi-layered subdomains, URL shorteners, and Punycode homographs.

Modern security solutions usually inspect URLs through browser extensions, external threat intelligence feeds, or machine learning pipelines. However, in computer science education, students benefit immensely from understanding the structural anatomy of malicious URLs and how deterministic heuristics can expose common deception strategies. PhishGuard was created to bridge this pedagogical gap as a college Java Problem-Based Learning (PBL) initiative.

---

## 3. Problem Statement
Many computer users lack the tools or technical awareness to identify structural anomalies in suspicious web links before clicking them. Furthermore, existing security tools typically require active internet connectivity, third-party subscriptions, or complex browser extensions.

There is a distinct need for a lightweight, self-contained, offline desktop application that:
1. Deconstructs URL syntax locally without exposing the user to live threat vectors.
2. Explains the exact reasoning behind why specific URL patterns are deemed suspicious.
3. Provides an engaging, professional, and accessible user interface suitable for educational demonstrations.

---

## 4. Project Objectives
1. **Educational Awareness:** Educate students and users on how attackers manipulate URL components to deceive victims.
2. **Deterministic Heuristic Engine:** Implement 10 distinct rule-based evaluators covering protocol, length, IP hostnames, userinfo `@`, keyword presence, subdomain depth, Punycode, URL shorteners, and digit sequences.
3. **Robust Java Architecture:** Demonstrate clean Java programming principles, including encapsulation, modular design, exception handling, and regular expressions.
4. **Interactive Swing Interface:** Develop an intuitive desktop dashboard using a modern dark navy and cyan aesthetic.
5. **Safe Local Persistence:** Store scan histories locally in CSV format with safeguards against CSV formula injection.
6. **Safety by Design:** Ensure 100% offline analysis without sending or receiving network packets.

---

## 5. Existing Approaches vs. Proposed PhishGuard System

| Parameter | Traditional Online Scanners | PhishGuard Proposed System |
|---|---|---|
| **Network Reliance** | Requires continuous internet access and API keys | 100% offline; zero outbound network requests |
| **Safety & Privacy** | Submits user URLs to external third-party clouds | Fully private; processed entirely on local memory |
| **Transparency** | Black-box scoring or proprietary machine learning | White-box rules; clear points and plain-English rationales |
| **System Footprint** | Heavy browser extensions or web backends | Lightweight Java Swing desktop application |
| **Educational Value** | Shows binary "Safe/Unsafe" verdict without explanation | Explains every triggered anomaly to educate the user |

---

## 6. System Architecture & Component Design

The application follows a clean layered architecture separating the user interface, business logic, persistence, and data models:

```
+--------------------------------------------------------------+
|                     Java Swing GUI Layer                     |
|           (MainFrame.java, ThemeConstants.java)              |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                   Business Logic Layer                       |
|   (UrlAnalyzer.java - java.net.URI, Regex, Rule Engine)      |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                      Domain Model Layer                      |
|       (AnalysisResult.java, RuleViolation.java)              |
+------------------------------+-------------------------------+
                               |
                               v
+--------------------------------------------------------------+
|                   Persistence & Utilities                    |
|   (ScanHistory.java -> CSV Storage, ReportExporter.java)     |
+--------------------------------------------------------------+
```

### Module Descriptions:
1. **`com.phishguard.model.RuleViolation`**: Represents a single triggered heuristic rule, holding its unique identifier, title, point value, explanation, and severity rating.
2. **`com.phishguard.model.AnalysisResult`**: Aggregates all analysis metrics, parsed components (scheme, host, path, port), validity status, final risk score, and list of violations.
3. **`com.phishguard.analyzer.UrlAnalyzer`**: The core heuristic engine. Parses the URL string into a `java.net.URI` object, applies regex checks, evaluates the 10 detection rules, and computes the risk score.
4. **`com.phishguard.history.ScanHistory`**: Manages reading, writing, and clearing local scan logs in `data/scan_history.csv` while mitigating formula injection vulnerabilities.
5. **`com.phishguard.ui.MainFrame`**: Constructs the Swing user interface, binds action listeners, dynamically updates visual score cards, and coordinates report exporting.
6. **`com.phishguard.util.ReportExporter`**: Copies formatted analysis summaries to the system clipboard or writes them to plain text files.

---

## 7. Heuristic Scoring Algorithm & Rule Specifications

The risk score $S$ is initialized to 0 and capped at a maximum of 100 points ($S = \min(100, \sum P_i)$):

1. **Unencrypted HTTP Protocol ($+10\text{ pts}$):**  
   URLs using `http://` transmit data in cleartext and lack certificate-backed identity verification.
2. **Length Exceeding 100 Characters ($+10\text{ pts}$):**  
   Long URLs are frequently generated to bury malicious domains behind extensive tracking or redirection paths.
3. **Length Exceeding 180 Characters ($+10\text{ additional pts}$):**  
   Extreme length is heavily correlated with embedded payload delivery and token-stuffing attacks.
4. **Embedded `@` Symbol ($+20\text{ pts}$):**  
   Browsers treat text prior to `@` as user credentials and route traffic exclusively to the domain following it, deceiving users.
5. **Raw IPv4 Address Hostname ($+20\text{ pts}$):**  
   Legitimate organizations register domain names; direct IP addresses (e.g. `http://192.168.1.1`) bypass domain name reputation systems.
6. **Sensitive Phishing Keywords ($+10\text{ pts}$):**  
   Presence of words such as `login`, `verify`, `account`, `banking`, `secure`, or `update` in the domain or path indicates credential harvesting.
7. **Excessive Subdomain Depth ($+10\text{ pts}$):**  
   Having 3 or more subdomain levels (e.g., `paypal.com.verify.attacker.xyz`) is a common visual spoofing tactic.
8. **Punycode IDN Homograph Indicator ($+10\text{ pts}$):**  
   Hostnames containing `xn--` often exploit Cyrillic or Greek lookalike characters to spoof authentic brand names.
9. **Known URL Shortener ($+15\text{ pts}$):**  
   Services like `bit.ly`, `tinyurl.com`, or `t.co` conceal the real destination from the user.
10. **Suspicious Sequence of Digits ($+5\text{ pts}$):**  
    Four or more consecutive numbers in a hostname suggest dynamically generated burner domains.

### Risk Level Classifications:
- **0–29 Points:** Low Risk Indicators
- **30–59 Points:** Moderate Risk Indicators
- **60–100 Points:** High Risk Indicators

---

## 8. Implementation Details

- **Language & Runtime:** Java 17 LTS / OpenJDK.
- **GUI Framework:** Java Swing (`JFrame`, `JPanel`, `JButton`, `JTextField`, `JTable`, `JTabbedPane`, `JScrollPane`).
- **Styling:** Custom dark navy design system (`ThemeConstants.java`) with antialiased cards, responsive resizing, and high-contrast typography.
- **Data Persistence:** Standard RFC 4180 CSV with single-quote escaping for formula injection protection.
- **Zero External Dependencies:** Built entirely with standard Java SE libraries (`java.net`, `java.util`, `java.io`, `java.awt`, `javax.swing`).

---

## 9. Testing & Quality Assurance
The system was verified using `com.phishguard.PhishGuardTestRunner`, a dependency-free automated test suite validating 13 distinct test scenarios:
- Empty and whitespace input handling.
- Valid HTTPS clean URLs.
- Insecure HTTP URLs.
- Raw IPv4 hostnames.
- Embedded `@` user credentials spoofing.
- Length boundaries (105 and 195 characters).
- Sensitive keyword matching.
- Punycode IDN homographs.
- Known URL shortener identification.
- Malformed syntax with spaces.
- Risk score capping at 100.
- CSV persistence and reload roundtrips.
- CSV formula injection sanitization.

**Result:** All 13 automated test suites passed with 100% success.

---

## 10. Critical Limitations & Ethical Disclaimer
1. **Static Heuristics Only:** PhishGuard analyzes the textual representation of the URL. It does not perform live DNS lookups, check SSL certificates, or inspect page content.
2. **False Positives:** Legitimate internal network addresses or complex search queries may trigger moderate risk scores.
3. **False Negatives:** Newly registered malicious domains hosted over HTTPS that avoid common keywords may yield low scores.
4. **Educational Scope:** A low score does not guarantee safety, and a high score does not prove malicious intent. Users should never enter sensitive credentials on untrusted websites.

---

## 11. Future Enhancements
1. **WHOIS & Domain Age Lookup:** Integrate safe sandbox queries to assess domain registration dates.
2. **Levenshtein Distance Analysis:** Automatically calculate edit distances to identify typosquatting of popular global brands.
3. **Machine Learning Classifier:** Train a Naive Bayes or Random Forest model on datasets like PhishTank to supplement static heuristics.
4. **Browser Extension Port:** Adapt the heuristic engine into a lightweight client-side browser plugin.

---

## 12. Conclusion
PhishGuard successfully meets all objectives of the College Java Problem-Based Learning (PBL) curriculum. It provides a functional, secure, offline desktop application demonstrating object-oriented architecture, Swing GUI design, secure file handling, and cybersecurity heuristics. By explaining the exact reasons behind each flagged indicator, PhishGuard serves as an effective learning tool for students and an engaging presentation for the college project exhibition.

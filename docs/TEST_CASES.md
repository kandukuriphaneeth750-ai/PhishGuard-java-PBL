# PhishGuard — Formal Test Cases & Verification Document

**Project:** PhishGuard — Rule-Based Suspicious URL Analyzer  
**Course:** Problem-Based Learning (PBL) in Java  
**Exhibition Date:** 12 November 2026  
**Execution Environment:** Windows 10/11, Java 17+ (Temurin / OpenJDK)  
**Test Runner:** `com.phishguard.PhishGuardTestRunner` (Dependency-free automated harness)  

---

## 1. Test Summary

| Total Test Cases | Passed | Failed | Status |
|---|---|---|---|
| 13 | 13 | 0 | **ALL PASSED (100%)** |

All tests use harmless, synthetic, or standard example URLs. **PhishGuard never executes network requests or opens browser sessions during testing or runtime.**

---

## 2. Test Suite Specification Matrix

| Test ID | Test Category | Target Component | Input Data / Condition | Expected Behavior & Criteria | Automated Verification |
|---|---|---|---|---|---|
| **TC-01** | Input Validation | `UrlAnalyzer.java` | Empty string `""`, spaces `"   "`, `null` | Returns `isValid() == false`, score `0`, category `"Invalid Input"`, message `"URL input cannot be blank or empty."` | PASS |
| **TC-02** | Baseline Clean URL | `UrlAnalyzer.java` | `https://example.com/index.html` | Returns `isValid() == true`, scheme `"https"`, host `"example.com"`, score `0`, category `"Low Risk Indicators"`, 0 violations. | PASS |
| **TC-03** | Protocol Detection | `UrlAnalyzer.java` | `http://example.com/` | Flags `RULE_HTTP` (+10 pts), total score `10`, category `"Low Risk Indicators"`. | PASS |
| **TC-04** | IP Hostname Heuristic | `UrlAnalyzer.java` | `http://192.168.1.50/dashboard` | Flags `RULE_IP_HOST` (+20 pts) and `RULE_HTTP` (+10 pts). Total score `>= 30`, category `"Moderate Risk Indicators"`. | PASS |
| **TC-05** | Credential Spoofing | `UrlAnalyzer.java` | `https://trusted-bank.com@attacker-site.org/auth` | Flags `RULE_AT_SYMBOL` (+20 pts). Host extracted safely without crashing. | PASS |
| **TC-06** | Boundary Length Test | `UrlAnalyzer.java` | URL 1: Length 105 chars<br>URL 2: Length 195 chars | URL 1 flags `RULE_LENGTH_100` (+10 pts) only.<br>URL 2 flags both `RULE_LENGTH_100` (+10 pts) and `RULE_LENGTH_180` (+10 pts). | PASS |
| **TC-07** | Sensitive Terminology | `UrlAnalyzer.java` | `https://safe-domain.org/verify-account-update` | Flags `RULE_SUSPICIOUS_WORD` (+10 pts) for keywords `verify`, `account`, `update`. | PASS |
| **TC-08** | IDN Homograph Attack | `UrlAnalyzer.java` | `https://xn--pple-43d.com/login` | Flags `RULE_PUNYCODE` (+10 pts) and `RULE_SUSPICIOUS_WORD` (+10 pts). | PASS |
| **TC-09** | URL Shortener Domain | `UrlAnalyzer.java` | `https://bit.ly/secure-redirect` | Flags `RULE_URL_SHORTENER` (+15 pts) for matching documented list (`bit.ly`, `tinyurl.com`, `t.co`, etc.). | PASS |
| **TC-10** | Syntax Malformation | `UrlAnalyzer.java` | `http://not a valid url with spaces.com` | Rejects spaces and illegal characters gracefully without throwing uncaught exceptions. | PASS |
| **TC-11** | Score Cap & Boundary | `UrlAnalyzer.java` | Compound phishing payload triggering >100 raw points | Final risk score is strictly capped at `100` (`Math.min(100, rawScore)`), category `"High Risk Indicators"`. | PASS |
| **TC-12** | Local Persistence | `ScanHistory.java` | Create, append, reload, and clear temporary history file | Analysis entry persists into CSV, reloads with correct data types, and clears cleanly upon request. | PASS |
| **TC-13** | CSV Safety & Escaping | `ScanHistory.java` | Formula strings: `=cmd|'calc'!A0`, `+123`, `@SUM()`, commas `"A, B"` | Prepends single quote `'` to neutralize formula execution in spreadsheet viewers; wraps fields with commas in quotes. | PASS |

---

## 3. UI Functional Verification Checklist

| UI Component | Action Tested | Expected UI Response | Verification |
|---|---|---|---|
| **Analyze Button** | Click with valid URL | Updates Score, Risk Badge, Summary labels, and populates Findings list. | Verified |
| **Analyze Button** | Click with empty input | Displays clear warning dialog prompt; does not crash. | Verified |
| **Sample Button** | Click repeatedly | Cycles through 7 pre-curated test cases representing clean, moderate, and extreme URLs. | Verified |
| **Clear Button** | Click | Clears URL input field, resets Score to `-- / 100`, resets summary cards. | Verified |
| **Copy Report** | Click after analysis | Copies full plain text analysis report to system clipboard. | Verified |
| **Export Report** | Click after analysis | Opens file chooser dialog, saves `.txt` report with custom or default filename. | Verified |
| **History Table** | Click any previous row | Automatically loads the clicked URL back into the input field for re-inspection. | Verified |
| **Clear History** | Click | Shows confirmation modal; upon clicking 'Yes', deletes history and refreshes table. | Verified |

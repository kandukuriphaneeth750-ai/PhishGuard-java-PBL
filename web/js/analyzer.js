/**
 * PhishGuard URL Analyzer — JavaScript Port
 * ==========================================
 * Faithfully replicates the 10-rule heuristic engine from:
 *   src/com/phishguard/analyzer/UrlAnalyzer.java
 *
 * This file performs ZERO network requests.
 * All analysis is purely local string and regex operations.
 */

// --- Constants (identical to Java source) ---

const IPV4_PATTERN = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const DIGIT_SEQUENCE_PATTERN = /\d{4,}/;

const SUSPICIOUS_KEYWORDS = new Set([
    'login', 'verify', 'verification', 'account', 'secure', 'security',
    'update', 'banking', 'signin', 'sign-in', 'password', 'credential',
    'confirm', 'wallet', 'authenticate', 'auth', 'support-billing'
]);

const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrand.ly', 'cutt.ly', 'goo.gl', 'bit.do', 'shorte.st'
]);

// --- Sample URLs for the "Try Sample" button ---

const SAMPLE_URLS = [
    'https://www.google.com',
    'http://example.com/login/account',
    'http://192.168.1.1/admin/panel',
    'https://secure-login.com@phishing-site.com/verify',
    'https://bit.ly/3xKf2mN',
    'https://xn--80ak6aa92e.com/account',
    'http://paypal.com.secure.account.login.verify-identity12345.evil.xyz/update?token=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890def123ghi456jkl789mno012pqr345stu678vwx901'
];

// --- Helper functions (ported from UrlAnalyzer.java) ---

/**
 * Creates an invalid analysis result.
 * Mirrors: AnalysisResult.createInvalid()
 */
function createInvalidResult(inputUrl, reason) {
    return {
        originalUrl: inputUrl,
        scheme: 'Invalid',
        host: 'None',
        path: 'None',
        port: -1,
        valid: false,
        validationMessage: reason,
        score: 0,
        riskCategory: 'Invalid Input',
        violations: [],
        timestamp: new Date()
    };
}

/**
 * Checks if a host string is an IPv4 address.
 * Mirrors: UrlAnalyzer.isIpv4Address()
 */
function isIpv4Address(host) {
    if (!host) return false;
    return IPV4_PATTERN.test(host.trim());
}

/**
 * Counts subdomain levels in a hostname (excluding domain + TLD).
 * "mail.google.com" → 1 subdomain
 * "a.b.c.google.com" → 3 subdomains
 * Mirrors: UrlAnalyzer.countSubdomains()
 */
function countSubdomains(host) {
    if (!host || host === '') return 0;
    const parts = host.split('.');
    return Math.max(0, parts.length - 2);
}

/**
 * Finds distinct suspicious keywords, longest-first to avoid sub-string duplicates.
 * Mirrors: UrlAnalyzer.findSuspiciousKeywords()
 */
function findSuspiciousKeywords(text) {
    const matched = [];
    const sortedKeywords = Array.from(SUSPICIOUS_KEYWORDS).sort((a, b) => b.length - a.length);

    for (const kw of sortedKeywords) {
        if (text.includes(kw)) {
            let redundant = false;
            for (const existing of matched) {
                if (existing.includes(kw)) {
                    redundant = true;
                    break;
                }
            }
            if (!redundant) {
                matched.push(kw);
            }
        }
    }
    return matched;
}

/**
 * Checks if host matches a known URL shortening service.
 * Mirrors: UrlAnalyzer.isKnownUrlShortener()
 */
function isKnownUrlShortener(host) {
    if (!host) return false;
    let cleanHost = host.toLowerCase();
    if (cleanHost.startsWith('www.')) {
        cleanHost = cleanHost.substring(4);
    }
    return URL_SHORTENERS.has(cleanHost);
}

// --- Main Analysis Engine ---

/**
 * Analyzes a URL string and computes risk metrics using 10 heuristic rules.
 * This is a faithful port of UrlAnalyzer.analyze() from the Java source.
 *
 * @param {string} rawInput - The URL string submitted by the user.
 * @returns {object} Analysis result with score, category, violations, and parsed components.
 */
function analyzeUrl(rawInput) {
    // Validate input
    if (!rawInput || rawInput.trim() === '') {
        return createInvalidResult('', 'URL input cannot be blank or empty.');
    }

    const input = rawInput.trim();

    // Check for disallowed whitespace within the URL
    if (/[ \t\n]/.test(input)) {
        return createInvalidResult(input, 'URL cannot contain spaces or newline characters.');
    }

    // Determine if scheme was explicitly provided
    const hasExplicitScheme = /^(https?:\/\/|ftp:\/\/)/i.test(input);
    const parseCandidate = hasExplicitScheme ? input : 'http://' + input;

    // Parse the URL
    let parsedUrl;
    try {
        parsedUrl = new URL(parseCandidate);
    } catch (e) {
        return createInvalidResult(input, 'Malformed URL format: ' + e.message);
    }

    const scheme = parsedUrl.protocol.replace(':', '');
    let host = parsedUrl.hostname;
    const path = parsedUrl.pathname || '/';
    const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : -1;

    // Validate host extraction
    if (!host || host.trim() === '') {
        return createInvalidResult(input, 'Unable to extract a valid domain or host name from the URL.');
    }

    const normalizedHost = host.toLowerCase();
    const fullUrlLower = input.toLowerCase();

    const violations = [];
    let score = 0;

    // ─────────────────────────────────────────────
    // RULE 1: HTTP instead of HTTPS (+10 points)
    // ─────────────────────────────────────────────
    if (scheme.toLowerCase() === 'http') {
        violations.push({
            ruleId: 'RULE_HTTP',
            title: 'Unencrypted HTTP Protocol',
            points: 10,
            explanation: 'The URL uses unencrypted HTTP instead of HTTPS. Phishing campaigns frequently avoid SSL certificates or operate on unencrypted connections.',
            severity: 'MODERATE'
        });
        score += 10;
    }

    // ─────────────────────────────────────────────
    // RULE 2: URL length > 100 characters (+10 pts)
    // ─────────────────────────────────────────────
    if (input.length > 100) {
        violations.push({
            ruleId: 'RULE_LENGTH_100',
            title: 'Long URL (> 100 chars)',
            points: 10,
            explanation: 'The URL length is ' + input.length + ' characters. Excessively long URLs are often used to conceal target domains and evade quick inspection.',
            severity: 'MODERATE'
        });
        score += 10;
    }

    // ─────────────────────────────────────────────
    // RULE 3: URL length > 180 characters (+10 pts)
    // ─────────────────────────────────────────────
    if (input.length > 180) {
        violations.push({
            ruleId: 'RULE_LENGTH_180',
            title: 'Very Long URL (> 180 chars)',
            points: 10,
            explanation: 'The URL exceeds 180 characters, strongly associated with obfuscated tokens, deep subdomains, or encoded exploit payloads.',
            severity: 'HIGH'
        });
        score += 10;
    }

    // ─────────────────────────────────────────────
    // RULE 4: '@' symbol in the URL (+20 points)
    // ─────────────────────────────────────────────
    if (input.includes('@')) {
        violations.push({
            ruleId: 'RULE_AT_SYMBOL',
            title: "Embedded '@' Symbol in URL",
            points: 20,
            explanation: "The '@' character instructs browsers to treat preceding text as user credentials and navigate only to the domain following it, a classic phishing trick.",
            severity: 'HIGH'
        });
        score += 20;
    }

    // ─────────────────────────────────────────────
    // RULE 5: Host is an IPv4 address (+20 points)
    // ─────────────────────────────────────────────
    if (isIpv4Address(normalizedHost)) {
        violations.push({
            ruleId: 'RULE_IP_HOST',
            title: 'IP Address Used as Hostname',
            points: 20,
            explanation: 'The host is an explicit IPv4 address (' + normalizedHost + '). Legitimate organizations use registered domain names; direct IP addresses often conceal rogue servers.',
            severity: 'HIGH'
        });
        score += 20;
    }

    // ─────────────────────────────────────────────
    // RULE 6: Suspicious keywords (+10 pts each)
    // ─────────────────────────────────────────────
    const matchedKeywords = findSuspiciousKeywords(fullUrlLower);
    for (const kw of matchedKeywords) {
        violations.push({
            ruleId: 'RULE_SUSPICIOUS_WORD',
            title: "Sensitive Keyword Detected ('" + kw + "')",
            points: 10,
            explanation: 'The URL contains security-sensitive or financial keywords designed to induce urgency or spoof authentication portals.',
            severity: 'MODERATE'
        });
        score += 10;
    }

    // ─────────────────────────────────────────────
    // RULE 7: Excessive subdomains >= 3 (+10 pts)
    // ─────────────────────────────────────────────
    const subdomainCount = countSubdomains(normalizedHost);
    if (subdomainCount >= 3 && !isIpv4Address(normalizedHost)) {
        violations.push({
            ruleId: 'RULE_EXCESSIVE_SUBDOMAINS',
            title: 'Excessive Subdomains (' + subdomainCount + ' levels)',
            points: 10,
            explanation: 'The hostname contains ' + subdomainCount + ' subdomain levels. Attackers stack subdomains (e.g., paypal.com.account-update.xyz) to simulate authentic brands.',
            severity: 'MODERATE'
        });
        score += 10;
    }

    // ─────────────────────────────────────────────
    // RULE 8: Punycode IDN 'xn--' (+10 points)
    // ─────────────────────────────────────────────
    if (normalizedHost.includes('xn--')) {
        violations.push({
            ruleId: 'RULE_PUNYCODE',
            title: "Punycode / IDN Domain ('xn--')",
            points: 10,
            explanation: 'The host utilizes Punycode encoding, commonly used in Internationalized Domain Name (IDN) homograph attacks to mimic well-known ASCII brand names.',
            severity: 'HIGH'
        });
        score += 10;
    }

    // ─────────────────────────────────────────────
    // RULE 9: Known URL Shortener (+15 points)
    // ─────────────────────────────────────────────
    if (isKnownUrlShortener(normalizedHost)) {
        violations.push({
            ruleId: 'RULE_URL_SHORTENER',
            title: 'Known URL Shortener Service',
            points: 15,
            explanation: 'The hostname matches a known URL shortening provider (' + normalizedHost + '). Shorteners mask the true destination domain until the link is opened.',
            severity: 'MODERATE'
        });
        score += 15;
    }

    // ─────────────────────────────────────────────
    // RULE 10: Long digit sequence in host (+5 pts)
    // ─────────────────────────────────────────────
    if (DIGIT_SEQUENCE_PATTERN.test(normalizedHost) && !isIpv4Address(normalizedHost)) {
        violations.push({
            ruleId: 'RULE_DIGIT_SEQUENCE',
            title: 'Long Digit Sequence in Hostname',
            points: 5,
            explanation: 'The domain name contains 4 or more consecutive numeric digits, characteristic of dynamically generated or temporary disposable phishing domains.',
            severity: 'INFO'
        });
        score += 5;
    }

    // Cap score at 100
    const finalScore = Math.min(100, Math.max(0, score));

    // Determine Risk Category (same thresholds as Java)
    let riskCategory;
    if (finalScore <= 29) {
        riskCategory = 'Low Risk Indicators';
    } else if (finalScore <= 59) {
        riskCategory = 'Moderate Risk Indicators';
    } else {
        riskCategory = 'High Risk Indicators';
    }

    return {
        originalUrl: input,
        scheme: scheme,
        host: host,
        path: path,
        port: port,
        valid: true,
        validationMessage: 'Valid',
        score: finalScore,
        riskCategory: riskCategory,
        violations: violations,
        timestamp: new Date()
    };
}

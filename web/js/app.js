/**
 * PhishGuard Web — Application Controller (app.js)
 * Connects the web UI to the offline heuristic analyzer.
 * ZERO external network traffic is generated.
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const urlInput = document.getElementById('url-input');
    const btnAnalyze = document.getElementById('btn-analyze');
    const btnSample = document.getElementById('btn-sample');
    const btnClear = document.getElementById('btn-clear');
    const btnCopyReport = document.getElementById('btn-copy-report');

    const resultsContainer = document.getElementById('results-container');
    const scoreText = document.getElementById('score-text');
    const scoreCircle = document.getElementById('score-circle');
    const riskBadge = document.getElementById('risk-badge');

    const metaTarget = document.getElementById('meta-target');
    const metaScheme = document.getElementById('meta-scheme');
    const metaHost = document.getElementById('meta-host');
    const metaLength = document.getElementById('meta-length');
    const metaStatus = document.getElementById('meta-status');

    const findingsCount = document.getElementById('findings-count');
    const violationsList = document.getElementById('violations-list');
    const noViolations = document.getElementById('no-violations');

    let currentResult = null;
    let sampleIndex = 0;

    // Radius of circular score gauge (SVG circle)
    const CIRCUMFERENCE = 2 * Math.PI * 60; // r=60 -> ~377

    // --- Action: Run Analysis ---
    function performScan() {
        const input = urlInput.value.trim();
        if (!input) {
            urlInput.focus();
            return;
        }

        const result = analyzeUrl(input);
        currentResult = result;
        displayResults(result);
    }

    // --- Render Results to DOM ---
    function displayResults(result) {
        resultsContainer.classList.add('active');

        // 1. Update Score & Animated Gauge
        const score = result.score;
        scoreText.innerHTML = `${score}<small>/100</small>`;

        // SVG stroke offset (0 score = 377, 100 score = 0)
        const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
        scoreCircle.style.strokeDashoffset = offset;

        // Color coding for score & gauge
        let color = 'var(--risk-low)';
        let badgeClass = 'low';

        if (score > 59) {
            color = 'var(--risk-high)';
            badgeClass = 'high';
        } else if (score > 29) {
            color = 'var(--risk-moderate)';
            badgeClass = 'moderate';
        }

        scoreCircle.style.stroke = color;
        riskBadge.className = `risk-badge ${badgeClass}`;
        riskBadge.textContent = result.riskCategory;

        // 2. Metadata Breakdown
        metaTarget.textContent = result.originalUrl || '(Empty)';
        metaScheme.textContent = (result.scheme || 'None').toUpperCase();
        metaHost.textContent = result.host || 'None';
        metaLength.textContent = `${result.originalUrl.length} characters`;
        metaStatus.textContent = result.valid ? 'Valid Format' : `Invalid (${result.validationMessage})`;
        metaStatus.style.color = result.valid ? 'var(--risk-low)' : 'var(--risk-high)';

        // 3. Findings Breakdown
        const violations = result.violations;
        findingsCount.textContent = `${violations.length} indicator${violations.length === 1 ? '' : 's'}`;

        if (violations.length === 0) {
            noViolations.style.display = 'flex';
            violationsList.innerHTML = '';
        } else {
            noViolations.style.display = 'none';
            violationsList.innerHTML = violations.map(v => {
                let pointClass = 'high';
                if (v.severity === 'MODERATE') pointClass = 'mod';
                if (v.severity === 'INFO') pointClass = 'info';

                return `
                    <div class="violation-item ${v.severity}">
                        <div class="violation-top">
                            <span class="violation-name">${escapeHtml(v.title)}</span>
                            <span class="violation-points ${pointClass}">+${v.points} pts &bull; ${v.severity}</span>
                        </div>
                        <div class="violation-desc">${escapeHtml(v.explanation)}</div>
                    </div>
                `;
            }).join('');
        }

        // Smoothly scroll to results on mobile devices
        if (window.innerWidth < 768) {
            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    // --- Action: Cycle Pre-curated Sample URLs ---
    btnSample.addEventListener('click', () => {
        urlInput.value = SAMPLE_URLS[sampleIndex];
        sampleIndex = (sampleIndex + 1) % SAMPLE_URLS.length;
        performScan();
    });

    // --- Action: Clear Inputs & Results ---
    btnClear.addEventListener('click', () => {
        urlInput.value = '';
        currentResult = null;
        resultsContainer.classList.remove('active');
        urlInput.focus();
    });

    // --- Action: Submit Scan ---
    btnAnalyze.addEventListener('click', performScan);

    urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            performScan();
        }
    });

    // --- Action: Copy Full Report ---
    btnCopyReport.addEventListener('click', async () => {
        if (!currentResult) return;

        const report = generateFullTextReport(currentResult);
        try {
            await navigator.clipboard.writeText(report);
            const originalText = btnCopyReport.innerHTML;
            btnCopyReport.innerHTML = '✅ Copied!';
            setTimeout(() => {
                btnCopyReport.innerHTML = originalText;
            }, 2000);
        } catch (err) {
            alert('Failed to copy to clipboard.');
        }
    });

    // --- Generate Text Report (Mirrors AnalysisResult.toFullReport() in Java) ---
    function generateFullTextReport(res) {
        const dateStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
        let out = '';
        out += '=================================================================\n';
        out += '         PHISHGUARD — SUSPICIOUS URL ANALYSIS REPORT             \n';
        out += '=================================================================\n';
        out += `Generated On     : ${dateStr}\n`;
        out += `Target URL       : ${res.originalUrl}\n`;
        out += `Validity Status  : ${res.valid ? 'Valid Format' : 'Invalid (' + res.validationMessage + ')'}\n`;
        out += `Protocol / Scheme: ${res.scheme}\n`;
        out += `Identified Host  : ${res.host}\n`;
        out += `Path Component   : ${res.path}\n`;
        if (res.port !== -1) {
            out += `Custom Port      : ${res.port}\n`;
        }
        out += '-----------------------------------------------------------------\n';
        out += `OVERALL RISK SCORE : ${res.score} / 100\n`;
        out += `RISK CLASSIFICATION: ${res.riskCategory}\n`;
        out += '-----------------------------------------------------------------\n';
        out += 'HEURISTIC FINDINGS:\n';

        if (res.violations.length === 0) {
            out += '  [OK] No suspicious indicators were flagged by the rule engine.\n';
        } else {
            res.violations.forEach((v, idx) => {
                out += `  ${idx + 1}. [${v.severity}] (+${v.points} pts) ${v.title}\n`;
                out += `     Rationale: ${v.explanation}\n`;
            });
        }
        out += '-----------------------------------------------------------------\n';
        out += 'DISCLAIMER:\n';
        out += '  PhishGuard evaluates URLs using static educational heuristics.\n';
        out += '  - A low score DOES NOT guarantee that a URL or website is safe.\n';
        out += '  - A high score DOES NOT prove malicious intent.\n';
        out += '  - Never enter passwords or sensitive data on untrusted sites.\n';
        out += '=================================================================\n';
        return out;
    }

    // Helper: Escape HTML strings to prevent XSS
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
});

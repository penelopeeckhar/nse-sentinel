#!/bin/bash

set -u

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target>"
    exit 1
fi

RAW_DIR="reports/raw"
OUTPUT_DIR="reports/generated"
OUTPUT_FILE="${OUTPUT_DIR}/${TARGET}-security-report.html"

mkdir -p "$OUTPUT_DIR"

html_escape() {
    printf '%s' "$1" |
        sed \
            -e 's/&/\&amp;/g' \
            -e 's/</\&lt;/g' \
            -e 's/>/\&gt;/g' \
            -e 's/"/\&quot;/g'
}

get_score() {
    local file="$1"

    grep -oE 'Risk Score: [0-9]+/100' "$file" 2>/dev/null |
        head -n 1 |
        sed -E 's/Risk Score: ([0-9]+)\/100/\1/' || true
}

get_level() {
    local file="$1"

    grep -oE 'Risk Level: [A-Z]+' "$file" 2>/dev/null |
        head -n 1 |
        sed -E 's/Risk Level: //' || true
}

level_class() {
    case "$1" in
        CRITICAL) echo "critical" ;;
        HIGH) echo "high" ;;
        MEDIUM) echo "medium" ;;
        LOW) echo "low" ;;
        INFORMATIONAL) echo "info" ;;
        *) echo "info" ;;
    esac
}

audit_name() {
    case "$1" in
        *http-security-audit*)
            echo "HTTP Security Audit"
            ;;
        *ssh-security-audit*)
            echo "SSH Security Audit"
            ;;
        *ftp-security-audit*)
            echo "FTP Security Audit"
            ;;
        *smb-security-audit*)
            echo "SMB Security Audit"
            ;;
        *mysql-security-audit*)
            echo "MySQL Security Audit"
            ;;
        *info-disclosure-audit*)
            echo "Information Disclosure Audit"
            ;;
        *)
            echo "$(basename "$1" .txt)"
            ;;
    esac
}

GENERATED="$(date '+%Y-%m-%d %H:%M:%S')"

declare -a AUDIT_FILES
declare -a AUDIT_NAMES
declare -a AUDIT_SCORES
declare -a AUDIT_LEVELS

TOTAL_AUDITS=0
HIGHEST_SCORE=0
HIGHEST_AUDIT=""
HIGHEST_LEVEL="INFORMATIONAL"

for report in \
    "$RAW_DIR/${TARGET}-ssh-security-audit.txt" \
    "$RAW_DIR/${TARGET}-ftp-security-audit.txt" \
    "$RAW_DIR/${TARGET}-smb-security-audit.txt" \
    "$RAW_DIR/${TARGET}-http-security-audit.txt" \
    "$RAW_DIR/${TARGET}-info-disclosure-audit.txt" \
    "$RAW_DIR/${TARGET}-mysql-security-audit.txt"
do
    [[ -f "$report" ]] || continue

    SCORE="$(get_score "$report")"
    LEVEL="$(get_level "$report")"

    [[ -n "$SCORE" ]] || SCORE=0
    [[ -n "$LEVEL" ]] || LEVEL="INFORMATIONAL"

    NAME="$(audit_name "$report")"

    AUDIT_FILES+=("$report")
    AUDIT_NAMES+=("$NAME")
    AUDIT_SCORES+=("$SCORE")
    AUDIT_LEVELS+=("$LEVEL")

    TOTAL_AUDITS=$((TOTAL_AUDITS + 1))

    if (( SCORE > HIGHEST_SCORE )); then
        HIGHEST_SCORE="$SCORE"
        HIGHEST_AUDIT="$NAME"
        HIGHEST_LEVEL="$LEVEL"
    fi
done

if (( HIGHEST_SCORE >= 80 )); then
    OVERALL_LEVEL="CRITICAL"
elif (( HIGHEST_SCORE >= 60 )); then
    OVERALL_LEVEL="HIGH"
elif (( HIGHEST_SCORE >= 30 )); then
    OVERALL_LEVEL="MEDIUM"
elif (( HIGHEST_SCORE > 0 )); then
    OVERALL_LEVEL="LOW"
else
    OVERALL_LEVEL="INFORMATIONAL"
fi

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

FINDINGS_HTML=""

for report in "${AUDIT_FILES[@]}"; do

    AUDIT="$(audit_name "$report")"

    while IFS= read -r line; do

        if [[ "$line" =~ \|[[:space:]]+(.+)[[:space:]]\[([A-Z]+)\][[:space:]]*$ ]]; then

            FINDING="${BASH_REMATCH[1]}"
            SEVERITY="${BASH_REMATCH[2]}"

            case "$SEVERITY" in
                CRITICAL)
                    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
                    ;;
                HIGH)
                    HIGH_COUNT=$((HIGH_COUNT + 1))
                    ;;
                MEDIUM)
                    MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
                    ;;
                LOW)
                    LOW_COUNT=$((LOW_COUNT + 1))
                    ;;
                INFO|INFORMATIONAL)
                    INFO_COUNT=$((INFO_COUNT + 1))
                    ;;
                *)
                    continue
                    ;;
            esac

            CLASS="$(level_class "$SEVERITY")"

            ESCAPED_AUDIT="$(html_escape "$AUDIT")"
            ESCAPED_FINDING="$(html_escape "$FINDING")"

            FINDINGS_HTML+="
            <div class=\"finding ${CLASS}\">
                <div class=\"finding-header\">
                    <span class=\"badge ${CLASS}\">${SEVERITY}</span>
                    <span class=\"finding-audit\">${ESCAPED_AUDIT}</span>
                </div>
                <div class=\"finding-name\">${ESCAPED_FINDING}</div>
            </div>
            "

        fi

    done < "$report"

done

TOTAL_FINDINGS=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + INFO_COUNT))

TARGET_ESCAPED="$(html_escape "$TARGET")"
OVERALL_CLASS="$(level_class "$OVERALL_LEVEL")"

AUDIT_ROWS=""
AUDIT_CARDS=""

for ((i=0; i<TOTAL_AUDITS; i++)); do

    NAME="${AUDIT_NAMES[$i]}"
    SCORE="${AUDIT_SCORES[$i]}"
    LEVEL="${AUDIT_LEVELS[$i]}"

    CLASS="$(level_class "$LEVEL")"

    AUDIT_ROWS+="
        <tr>
            <td>$(html_escape "$NAME")</td>
            <td><strong>${SCORE}/100</strong></td>
            <td><span class=\"badge ${CLASS}\">${LEVEL}</span></td>
        </tr>
    "

    FILLED=$((SCORE / 5))
    EMPTY=$((20 - FILLED))

    BAR=""
    for ((x=0; x<FILLED; x++)); do
        BAR+="█"
    done

    for ((x=0; x<EMPTY; x++)); do
        BAR+="░"
    done

    AUDIT_CARDS+="
        <div class=\"service-card\">
            <div class=\"service-top\">
                <span>$(html_escape "$NAME")</span>
                <span class=\"badge ${CLASS}\">${LEVEL}</span>
            </div>

            <div class=\"service-score\">
                ${SCORE}/100
            </div>

            <div class=\"progress\">
                <div class=\"progress-fill ${CLASS}\" style=\"width:${SCORE}%\"></div>
            </div>
        </div>
    "
done

cat > "$OUTPUT_FILE" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>NSE-Sentinel Security Report - ${TARGET_ESCAPED}</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #f4f6f8;
    color: #1f2937;
    font-family:
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        Roboto,
        Arial,
        sans-serif;
}

.container {
    max-width: 1200px;
    margin: auto;
    padding: 35px 25px 60px;
}

.header {
    background: #111827;
    color: white;
    padding: 35px;
    border-radius: 16px;
    margin-bottom: 25px;
}

.header h1 {
    margin: 0 0 10px;
    font-size: 32px;
}

.header p {
    margin: 5px 0;
    color: #cbd5e1;
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 18px;
    margin-bottom: 25px;
}

.card {
    background: white;
    border-radius: 14px;
    padding: 24px;
    box-shadow: 0 2px 10px rgba(0,0,0,.06);
}

.card h3 {
    margin-top: 0;
    color: #6b7280;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: .05em;
}

.big-number {
    font-size: 34px;
    font-weight: 700;
}

.risk-card {
    border-left: 6px solid;
}

.risk-card.critical {
    border-color: #991b1b;
}

.risk-card.high {
    border-color: #dc2626;
}

.risk-card.medium {
    border-color: #d97706;
}

.risk-card.low {
    border-color: #2563eb;
}

.risk-card.info {
    border-color: #6b7280;
}

.section {
    background: white;
    border-radius: 14px;
    padding: 25px;
    margin-bottom: 25px;
    box-shadow: 0 2px 10px rgba(0,0,0,.06);
}

.section h2 {
    margin-top: 0;
    font-size: 21px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 14px 12px;
    border-bottom: 1px solid #e5e7eb;
}

th {
    background: #f9fafb;
    color: #4b5563;
}

.badge {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
}

.badge.critical {
    background: #fee2e2;
    color: #991b1b;
}

.badge.high {
    background: #fecaca;
    color: #991b1b;
}

.badge.medium {
    background: #fef3c7;
    color: #92400e;
}

.badge.low {
    background: #dbeafe;
    color: #1d4ed8;
}

.badge.info {
    background: #e5e7eb;
    color: #374151;
}

.distribution {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px;
}

.distribution-item {
    padding: 18px;
    border-radius: 10px;
    background: #f9fafb;
    text-align: center;
}

.distribution-item strong {
    display: block;
    font-size: 28px;
}

.finding {
    border: 1px solid #e5e7eb;
    border-left: 5px solid;
    border-radius: 9px;
    padding: 16px;
    margin-bottom: 12px;
}

.finding.critical {
    border-left-color: #991b1b;
}

.finding.high {
    border-left-color: #dc2626;
}

.finding.medium {
    border-left-color: #d97706;
}

.finding.low {
    border-left-color: #2563eb;
}

.finding.info {
    border-left-color: #6b7280;
}

.finding-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 9px;
}

.finding-audit {
    color: #6b7280;
    font-size: 14px;
}

.finding-name {
    font-weight: 600;
}

.service-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 18px;
}

.service-card {
    background: #f9fafb;
    border-radius: 12px;
    padding: 20px;
}

.service-top {
    display: flex;
    justify-content: space-between;
    gap: 10px;
    font-weight: 600;
}

.service-score {
    font-size: 28px;
    font-weight: 700;
    margin: 15px 0;
}

.progress {
    height: 12px;
    background: #e5e7eb;
    border-radius: 999px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    border-radius: 999px;
}

.progress-fill.critical {
    background: #991b1b;
}

.progress-fill.high {
    background: #dc2626;
}

.progress-fill.medium {
    background: #d97706;
}

.progress-fill.low {
    background: #2563eb;
}

.progress-fill.info {
    background: #6b7280;
}

.remediation {
    display: grid;
    gap: 12px;
}

.remediation-item {
    padding: 17px;
    border-radius: 10px;
    background: #f9fafb;
}

.remediation-item strong {
    display: block;
    margin-bottom: 5px;
}

.footer {
    text-align: center;
    color: #6b7280;
    padding-top: 15px;
    font-size: 13px;
}

@media (max-width: 650px) {

    .container {
        padding: 15px;
    }

    .header {
        padding: 25px;
    }

    .header h1 {
        font-size: 25px;
    }

    table {
        font-size: 14px;
    }

}

</style>
</head>

<body>

<div class="container">

    <header class="header">

        <h1>NSE-Sentinel Security Report</h1>

        <p><strong>Target:</strong> ${TARGET_ESCAPED}</p>

        <p><strong>Generated:</strong> ${GENERATED}</p>

        <p><strong>Audits executed:</strong> ${TOTAL_AUDITS}</p>

    </header>


    <div class="grid">

        <div class="card risk-card ${OVERALL_CLASS}">

            <h3>Overall Risk</h3>

            <div class="big-number">
                ${HIGHEST_SCORE}/100
            </div>

            <span class="badge ${OVERALL_CLASS}">
                ${OVERALL_LEVEL}
            </span>

        </div>


        <div class="card">

            <h3>Highest Risk Audit</h3>

            <div class="big-number" style="font-size:22px;">
                $(html_escape "$HIGHEST_AUDIT")
            </div>

            <p>
                ${HIGHEST_SCORE}/100 —
                ${HIGHEST_LEVEL}
            </p>

        </div>


        <div class="card">

            <h3>Total Findings</h3>

            <div class="big-number">
                ${TOTAL_FINDINGS}
            </div>

        </div>

    </div>


    <section class="section">

        <h2>Audit Results</h2>

        <table>

            <thead>

                <tr>
                    <th>Audit</th>
                    <th>Score</th>
                    <th>Risk</th>
                </tr>

            </thead>

            <tbody>

                ${AUDIT_ROWS}

            </tbody>

        </table>

    </section>


    <section class="section">

        <h2>Risk Distribution</h2>

        <div class="distribution">

            <div class="distribution-item">
                <span class="badge critical">CRITICAL</span>
                <strong>${CRITICAL_COUNT}</strong>
                findings
            </div>

            <div class="distribution-item">
                <span class="badge high">HIGH</span>
                <strong>${HIGH_COUNT}</strong>
                findings
            </div>

            <div class="distribution-item">
                <span class="badge medium">MEDIUM</span>
                <strong>${MEDIUM_COUNT}</strong>
                findings
            </div>

            <div class="distribution-item">
                <span class="badge low">LOW</span>
                <strong>${LOW_COUNT}</strong>
                findings
            </div>

            <div class="distribution-item">
                <span class="badge info">INFO</span>
                <strong>${INFO_COUNT}</strong>
                findings
            </div>

        </div>

    </section>


    <section class="section">

        <h2>Findings</h2>

        ${FINDINGS_HTML}

    </section>


    <section class="section">

        <h2>Priority Remediation</h2>

        <div class="remediation">

            <div class="remediation-item">

                <span class="badge critical">CRITICAL</span>

                <strong>Immediate action</strong>

                Address critical security weaknesses before exposing the affected service to untrusted networks.

            </div>


            <div class="remediation-item">

                <span class="badge high">HIGH</span>

                <strong>High priority</strong>

                Prioritize weak cryptographic algorithms, legacy protocols, authentication weaknesses and insecure service configurations.

            </div>


            <div class="remediation-item">

                <span class="badge medium">MEDIUM</span>

                <strong>Hardening required</strong>

                Review security headers, encryption configuration and other medium-risk weaknesses.

            </div>


            <div class="remediation-item">

                <span class="badge low">LOW</span>

                <strong>Security improvement</strong>

                Reduce information disclosure and apply additional hardening measures.

            </div>

        </div>

    </section>


    <section class="section">

        <h2>Service Risk Overview</h2>

        <div class="service-grid">

            ${AUDIT_CARDS}

        </div>

    </section>


    <footer class="footer">

        Generated by <strong>NSE-Sentinel</strong> —
        Custom Nmap Security Auditing Toolkit

    </footer>

</div>

</body>
</html>
EOF

echo
echo "[+] HTML security report generated:"
echo "    $OUTPUT_FILE"
echo

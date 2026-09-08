#!/usr/bin/env bash

set -u

TARGET="${1:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="$SCRIPT_DIR/reports/raw"
GENERATED_DIR="$SCRIPT_DIR/reports/generated"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target>"
    echo
    echo "Example:"
    echo "  $0 192.168.56.107"
    exit 1
fi

mkdir -p "$GENERATED_DIR"

SUMMARY="$GENERATED_DIR/${TARGET}-security-summary.txt"

# --------------------------------------------------
# Global counters
# --------------------------------------------------

AUDITS=0

CRITICAL_AUDITS=0
HIGH_AUDITS=0
MEDIUM_AUDITS=0
LOW_AUDITS=0
INFO_AUDITS=0

CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
MEDIUM_FINDINGS=0
LOW_FINDINGS=0

HIGHEST_SCORE=-1
HIGHEST_LEVEL="INFORMATIONAL"
HIGHEST_AUDIT="None"

# Temporary files
AUDIT_DATA=$(mktemp)
FINDING_DATA=$(mktemp)

cleanup() {
    rm -f "$AUDIT_DATA" "$FINDING_DATA"
}

trap cleanup EXIT

# --------------------------------------------------
# Helpers
# --------------------------------------------------

normalize_audit_name() {
    local name="$1"

    case "$name" in
        ftp-security-audit)
            echo "FTP Security Audit"
            ;;
        http-security-audit)
            echo "HTTP Security Audit"
            ;;
        info-disclosure-audit)
            echo "Information Disclosure Audit"
            ;;
        mysql-security-audit)
            echo "MySQL Security Audit"
            ;;
        smb-security-audit)
            echo "SMB Security Audit"
            ;;
        ssh-security-audit)
            echo "SSH Security Audit"
            ;;
        *)
            echo "$name"
            ;;
    esac
}

# --------------------------------------------------
# Parse reports
# --------------------------------------------------

for REPORT in "$REPORT_DIR"/"${TARGET}"-*.txt; do

    [[ -f "$REPORT" ]] || continue

    # Ignore baseline
    [[ "$REPORT" == *"-baseline.txt" ]] && continue

    SCORE=$(grep -oE 'Risk Score: [0-9]+/100' "$REPORT" |
        head -n 1 |
        sed -E 's/Risk Score: ([0-9]+)\/100/\1/' || true)

    LEVEL=$(grep -oE 'Risk Level: [A-Z]+' "$REPORT" |
        head -n 1 |
        cut -d' ' -f3 || true)

    [[ -z "$SCORE" ]] && continue

    [[ -z "$LEVEL" ]] && LEVEL="INFORMATIONAL"

    FILE_NAME=$(basename "$REPORT")

    AUDIT_NAME="${FILE_NAME#${TARGET}-}"
    AUDIT_NAME="${AUDIT_NAME%.txt}"

    DISPLAY_NAME=$(normalize_audit_name "$AUDIT_NAME")

    AUDITS=$((AUDITS + 1))

    # Audit risk distribution
    case "$LEVEL" in
        CRITICAL)
            CRITICAL_AUDITS=$((CRITICAL_AUDITS + 1))
            ;;
        HIGH)
            HIGH_AUDITS=$((HIGH_AUDITS + 1))
            ;;
        MEDIUM)
            MEDIUM_AUDITS=$((MEDIUM_AUDITS + 1))
            ;;
        LOW)
            LOW_AUDITS=$((LOW_AUDITS + 1))
            ;;
        INFORMATIONAL)
            INFO_AUDITS=$((INFO_AUDITS + 1))
            ;;
    esac

    # Highest audit
    if (( SCORE > HIGHEST_SCORE )); then
        HIGHEST_SCORE="$SCORE"
        HIGHEST_LEVEL="$LEVEL"
        HIGHEST_AUDIT="$DISPLAY_NAME"
    fi

    printf "%s|%s|%s\n" \
        "$DISPLAY_NAME" \
        "$SCORE" \
        "$LEVEL" >> "$AUDIT_DATA"

    # --------------------------------------------------
    # Parse findings
    # --------------------------------------------------

    while IFS= read -r LINE; do

        FINDING=$(echo "$LINE" |
            sed -E 's/.*Findings:[[:space:]]+//' |
            sed -E 's/\[([A-Z]+)\].*$/[\1]/')

        SEVERITY=$(echo "$LINE" |
            grep -oE '\[(CRITICAL|HIGH|MEDIUM|LOW)\]' |
            tail -n 1 |
            tr -d '[]' || true)

        if [[ -n "$SEVERITY" ]]; then

            DESCRIPTION=$(echo "$LINE" |
                sed -E 's/^[[:space:]]*\|[[:space:]]*//' |
                sed -E 's/\[[A-Z]+\]//' |
                sed -E 's/[[:space:]]+$//')

            printf "%s|%s|%s\n" \
                "$DISPLAY_NAME" \
                "$SEVERITY" \
                "$DESCRIPTION" >> "$FINDING_DATA"

            case "$SEVERITY" in
                CRITICAL)
                    CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                    ;;
                HIGH)
                    HIGH_FINDINGS=$((HIGH_FINDINGS + 1))
                    ;;
                MEDIUM)
                    MEDIUM_FINDINGS=$((MEDIUM_FINDINGS + 1))
                    ;;
                LOW)
                    LOW_FINDINGS=$((LOW_FINDINGS + 1))
                    ;;
            esac
        fi

    done < <(
        grep -E '^[|][[:space:]]+[A-Za-z0-9].*\[(CRITICAL|HIGH|MEDIUM|LOW)\]' "$REPORT" |
        grep -vE 'Risk Level|Risk Score'
    )

done

# --------------------------------------------------
# Calculate overall risk
# --------------------------------------------------

OVERALL_SCORE="$HIGHEST_SCORE"

if (( OVERALL_SCORE < 0 )); then
    OVERALL_SCORE=0
fi

# Additional weight for multiple critical/high audit areas
if (( CRITICAL_AUDITS > 1 )); then
    OVERALL_SCORE=$((OVERALL_SCORE + (CRITICAL_AUDITS - 1) * 10))
fi

if (( HIGH_AUDITS > 1 )); then
    OVERALL_SCORE=$((OVERALL_SCORE + (HIGH_AUDITS - 1) * 5))
fi

if (( OVERALL_SCORE > 100 )); then
    OVERALL_SCORE=100
fi

if (( OVERALL_SCORE >= 80 )); then
    OVERALL_LEVEL="CRITICAL"
elif (( OVERALL_SCORE >= 60 )); then
    OVERALL_LEVEL="HIGH"
elif (( OVERALL_SCORE >= 30 )); then
    OVERALL_LEVEL="MEDIUM"
elif (( OVERALL_SCORE > 0 )); then
    OVERALL_LEVEL="LOW"
else
    OVERALL_LEVEL="INFORMATIONAL"
fi

# --------------------------------------------------
# Generate report
# --------------------------------------------------

{
    echo "=============================================================="
    echo "                 NSE-Sentinel Security Report"
    echo "=============================================================="
    echo
    echo "Target:       $TARGET"
    echo "Generated:    $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Audits:       $AUDITS"
    echo

    echo "=============================================================="
    echo "                     OVERALL RISK"
    echo "=============================================================="
    echo
    echo "  Overall Score: $OVERALL_SCORE/100"
    echo "  Overall Level: $OVERALL_LEVEL"
    echo
    echo "  Highest Risk Audit:"
    echo "    $HIGHEST_AUDIT"
    echo "    Score: $HIGHEST_SCORE/100"
    echo "    Level: $HIGHEST_LEVEL"
    echo

    echo "=============================================================="
    echo "                   AUDIT RESULTS"
    echo "=============================================================="
    echo

    printf "  %-32s %-10s %-15s\n" "Audit" "Score" "Risk"
    printf "  %-32s %-10s %-15s\n" \
        "--------------------------------" \
        "----------" \
        "---------------"

    sort -t'|' -k2,2nr "$AUDIT_DATA" |
    while IFS='|' read -r NAME SCORE LEVEL; do
        printf "  %-32s %-10s %-15s\n" \
            "$NAME" \
            "${SCORE}/100" \
            "$LEVEL"
    done

    echo

    echo "=============================================================="
    echo "                   RISK DISTRIBUTION"
    echo "=============================================================="
    echo

    echo "  Audit Risk:"
    echo "    Critical:       $CRITICAL_AUDITS"
    echo "    High:           $HIGH_AUDITS"
    echo "    Medium:         $MEDIUM_AUDITS"
    echo "    Low:            $LOW_AUDITS"
    echo "    Informational:  $INFO_AUDITS"
    echo

    echo "  Finding Severity:"
    echo "    Critical:       $CRITICAL_FINDINGS"
    echo "    High:           $HIGH_FINDINGS"
    echo "    Medium:         $MEDIUM_FINDINGS"
    echo "    Low:            $LOW_FINDINGS"
    echo

    echo "=============================================================="
    echo "                    FINDINGS"
    echo "=============================================================="
    echo

    if [[ -s "$FINDING_DATA" ]]; then

        while IFS='|' read -r SERVICE SEVERITY DESCRIPTION; do

            echo "  [$SEVERITY] $SERVICE"
            echo "      $DESCRIPTION"
            echo

        done < <(
            sort -t'|' -k2,2 -k1,1 "$FINDING_DATA"
        )

    else
        echo "  No security findings detected."
        echo
    fi

    echo "=============================================================="
    echo "                 PRIORITY REMEDIATION"
    echo "=============================================================="
    echo

    if (( CRITICAL_FINDINGS > 0 )); then
        echo "  [CRITICAL]"
        echo "    Address all critical findings immediately."
        echo
    fi

    if (( HIGH_FINDINGS > 0 )); then
        echo "  [HIGH]"
        echo "    Prioritize high-severity findings before lower-risk issues."
        echo
    fi

    if (( MEDIUM_FINDINGS > 0 )); then
        echo "  [MEDIUM]"
        echo "    Review and remediate medium-severity configuration weaknesses."
        echo
    fi

    if (( LOW_FINDINGS > 0 )); then
        echo "  [LOW]"
        echo "    Review information disclosure and hardening recommendations."
        echo
    fi

    if (( CRITICAL_FINDINGS == 0 &&
          HIGH_FINDINGS == 0 &&
          MEDIUM_FINDINGS == 0 &&
          LOW_FINDINGS == 0 )); then

        echo "  No remediation actions are currently required."
        echo
    fi

    echo "=============================================================="
    echo "                  SERVICE RISK OVERVIEW"
    echo "=============================================================="
    echo

    sort -t'|' -k2,2nr "$AUDIT_DATA" |
    while IFS='|' read -r NAME SCORE LEVEL; do

        BAR_LENGTH=$((SCORE / 5))

        BAR=""

        for ((i=0; i<BAR_LENGTH; i++)); do
            BAR="${BAR}#"
        done

        printf "  %-30s [% -20s] %3s/100 %-12s\n" \
            "$NAME" \
            "$BAR" \
            "$SCORE" \
            "$LEVEL"

    done

    echo

    echo "=============================================================="
    echo "                  END OF SECURITY REPORT"
    echo "=============================================================="

} > "$SUMMARY"

cat "$SUMMARY"

echo
echo "[+] Detailed report saved to:"
echo "    $SUMMARY"

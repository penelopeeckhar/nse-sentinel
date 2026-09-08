#!/usr/bin/env bash

set -u

TARGET="${1:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NSE_DIR="$SCRIPT_DIR/nse"
REPORT_DIR="$SCRIPT_DIR/reports/raw"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target>"
    echo
    echo "Example:"
    echo "  $0 192.168.56.107"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run with sudo."
    echo "    Example: sudo $0 $TARGET"
    exit 1
fi

mkdir -p "$REPORT_DIR"

echo "=============================================="
echo "        NSE-Sentinel Security Scanner"
echo "=============================================="
echo "[+] Target: $TARGET"
echo "[+] Reports: $REPORT_DIR"
echo

echo "[+] Running service discovery..."

BASELINE="$REPORT_DIR/${TARGET}-baseline.txt"

nmap -Pn -sV \
    "$TARGET" \
    -oN "$BASELINE"

if [[ $? -ne 0 ]]; then
    echo "[!] Nmap service discovery failed."
    exit 1
fi

echo
echo "[+] Service discovery completed."
echo

run_audit() {
    local name="$1"
    local ports="$2"
    local script="$3"
    local report="$4"

    echo "----------------------------------------------"
    echo "[+] Running: $name"
    echo "[+] Ports: $ports"
    echo "----------------------------------------------"

    nmap -Pn \
        -p"$ports" \
        --script "$NSE_DIR/$script" \
        "$TARGET" \
        -oN "$REPORT_DIR/$report"

    if [[ $? -eq 0 ]]; then
        echo "[+] $name completed."
    else
        echo "[!] $name failed."
    fi

    echo
}

BASELINE_CONTENT="$(cat "$BASELINE")"

if echo "$BASELINE_CONTENT" | grep -Eq '^[0-9]+/tcp[[:space:]]+open[[:space:]]+.*http'; then
    HTTP_PORTS=$(echo "$BASELINE_CONTENT" |
        awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" && $3 ~ /http/ {
            split($1,p,"/");
            print p[1]
        }' |
        paste -sd, -)

    if [[ -n "$HTTP_PORTS" ]]; then

        run_audit \
            "HTTP Security Audit" \
            "$HTTP_PORTS" \
            "http-security-audit.nse" \
            "${TARGET}-http-security-audit.txt"

        run_audit \
            "Information Disclosure Audit" \
            "$HTTP_PORTS" \
            "info-disclosure-audit.nse" \
            "${TARGET}-info-disclosure-audit.txt"

    fi
fi

SSH_PORTS=$(echo "$BASELINE_CONTENT" |
    awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" && $3 == "ssh" {
        split($1,p,"/");
        print p[1]
    }' |
    paste -sd, -)

if [[ -n "$SSH_PORTS" ]]; then
    run_audit \
        "SSH Security Audit" \
        "$SSH_PORTS" \
        "ssh-security-audit.nse" \
        "${TARGET}-ssh-security-audit.txt"
fi

FTP_PORTS=$(echo "$BASELINE_CONTENT" |
    awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" && $3 ~ /ftp/ {
        split($1,p,"/");
        print p[1]
    }' |
    paste -sd, -)

if [[ -n "$FTP_PORTS" ]]; then
    run_audit \
        "FTP Security Audit" \
        "$FTP_PORTS" \
        "ftp-security-audit.nse" \
        "${TARGET}-ftp-security-audit.txt"
fi

SMB_PORTS=$(echo "$BASELINE_CONTENT" |
    awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" &&
        ($3 == "microsoft-ds" || $3 == "netbios-ssn") {
        split($1,p,"/");
        print p[1]
    }' |
    paste -sd, -)

if [[ -n "$SMB_PORTS" ]]; then
    run_audit \
        "SMB Security Audit" \
        "$SMB_PORTS" \
        "smb-security-audit.nse" \
        "${TARGET}-smb-security-audit.txt"
fi

MYSQL_PORTS=$(echo "$BASELINE_CONTENT" |
    awk '$1 ~ /^[0-9]+\/tcp$/ && $2 == "open" && $3 == "mysql" {
        split($1,p,"/");
        print p[1]
    }' |
    paste -sd, -)

if [[ -n "$MYSQL_PORTS" ]]; then
    run_audit \
        "MySQL Security Audit" \
        "$MYSQL_PORTS" \
        "mysql-security-audit.nse" \
        "${TARGET}-mysql-security-audit.txt"
fi

echo "=============================================="
echo "          Generating Risk Summary"
echo "=============================================="
echo

"$SCRIPT_DIR/sentinel-report.sh" "$TARGET"
"$SCRIPT_DIR/sentinel-report-html.sh" "$TARGET"

echo

echo "=============================================="
echo "              Scan Completed"
echo "=============================================="
echo
echo "[+] Target: $TARGET"
echo "[+] Reports generated:"
echo

find "$REPORT_DIR" \
    -maxdepth 1 \
    -type f \
    -name "${TARGET}-*.txt" \
    -printf "    %f\n" |
    sort

echo
echo "[+] NSE-Sentinel finished successfully."

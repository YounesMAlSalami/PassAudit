#!/usr/bin/env bash
set -euo pipefail

WEAK_USER="younes"
STRONG_USER="younesalsalami"
WORDLIST="$(mktemp)"
REPORT_DIR="$(mktemp -d)"

cleanup() {
    if id "$WEAK_USER" >/dev/null 2>&1; then
        userdel "$WEAK_USER" >/dev/null 2>&1 || true
    fi
    if id "$STRONG_USER" >/dev/null 2>&1; then
        userdel "$STRONG_USER" >/dev/null 2>&1 || true
    fi
    rm -f "$WORDLIST"
}
trap cleanup EXIT

if [[ "$EUID" -ne 0 ]]; then
    echo "Run this script with sudo on an isolated Ubuntu test VM."
    exit 2
fi

printf "12345678\n" > "$WORDLIST"

read -rsp "Enter the controlled weak password for $WEAK_USER: " WEAK_PASSWORD
echo
read -rsp "Enter the controlled strong password for $STRONG_USER: " STRONG_PASSWORD
echo

useradd -m "$WEAK_USER"
useradd -m "$STRONG_USER"

printf '%s:%s\n' "$WEAK_USER" "$WEAK_PASSWORD" | chpasswd
printf '%s:%s\n' "$STRONG_USER" "$STRONG_PASSWORD" | chpasswd

unset WEAK_PASSWORD STRONG_PASSWORD

python3 main.py audit-linux \
    --wordlist "$WORDLIST" \
    --out "$REPORT_DIR"

audit_status=$?
if [[ "$audit_status" -eq 0 || "$audit_status" -eq 1 ]]; then
    echo "Linux audit completed. Reports: $REPORT_DIR"
    echo "Password values were not written to reports."
    exit "$audit_status"
fi

echo "Linux audit did not complete successfully."
exit "$audit_status"

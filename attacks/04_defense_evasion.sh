#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Defense Evasion / Log Tampering
# MITRE ATT&CK: T1070.002 (Clear Linux/Mac System Logs)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #5: Defense Evasion (T1070.002/003)${NC}"
echo -e "${YELLOW} Attempt to clear logs and history${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Method 1: Truncate bash history (safe — we save and restore)
HIST_BAK=$(mktemp)
if [ -f ~/.bash_history ]; then
    cp ~/.bash_history "$HIST_BAK"
fi

echo -e "  ${RED}Truncating ~/.bash_history${NC}"
: > ~/.bash_history  2>/dev/null || true
echo "  → Zion should flag this as LOG TAMPERING (T1070.003)"

# Restore
if [ -f "$HIST_BAK" ]; then
    cp "$HIST_BAK" ~/.bash_history 2>/dev/null || true
    rm -f "$HIST_BAK"
    echo -e "  ${GREEN}History restored.${NC}"
fi

# Method 2: Attempt to read /var/log/auth.log (triggers file monitor)
echo -e "  ${RED}Accessing /var/log/auth.log${NC}"
cat /var/log/auth.log > /dev/null 2>&1 || true
echo "  → Zion should flag log access"

echo -e "  All defense evasion simulations complete."

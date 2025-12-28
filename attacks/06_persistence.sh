#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Persistence via Crontab
# MITRE ATT&CK: T1053.003 (Cron)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #6: Persistence (T1053.003)${NC}"
echo -e "${YELLOW} Add and remove a crontab entry${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Add a malicious cron job to system-wide cron.d
# This uses openat() which our sensor monitors.
echo -e "  ${RED}Creating malicious cron file /etc/cron.d/zion_test...${NC}"
echo "* * * * * root /tmp/.zion_backdoor.sh" | tee /etc/cron.d/zion_test >/dev/null
echo "  → Zion should flag this as PERSISTENCE (T1053.003)"

sleep 1

# Cleanup
echo -e "  ${GREEN}Removing malicious entry (cleanup)...${NC}"
rm -f /etc/cron.d/zion_test

echo -e "  Persistence simulation complete."

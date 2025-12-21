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

# Save current crontab
CRON_BAK=$(mktemp)
crontab -l > "$CRON_BAK" 2>/dev/null || echo "" > "$CRON_BAK"

# Add a malicious crontab entry (backdoor persistence)
echo -e "  ${RED}Adding malicious crontab entry...${NC}"
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.zion_backdoor.sh # ZION_TEST") | crontab - 2>/dev/null || true
echo "  → Zion should flag this as PERSISTENCE (T1053.003)"

sleep 1

# Immediately remove it
echo -e "  ${GREEN}Removing malicious entry (cleanup)...${NC}"
crontab "$CRON_BAK" 2>/dev/null || crontab -r 2>/dev/null || true
rm -f "$CRON_BAK"

echo -e "  Persistence simulation complete."

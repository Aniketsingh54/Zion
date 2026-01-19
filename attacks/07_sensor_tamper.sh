#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Sensor Tampering
# MITRE ATT&CK: T1562 (Impair Defenses)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #8: Sensor Tampering (T1562)${NC}"
echo -e "${YELLOW} Attempt to kill the Zion process${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Find Zion's PID
ZION_PID=$(pgrep -f "^./zion$" | head -1 || true)

if [ -z "$ZION_PID" ]; then
    ZION_PID=$(pgrep -x "zion" | head -1 || true)
fi

if [ -z "$ZION_PID" ]; then
    echo -e "  ${RED}Zion process not found! Make sure Zion is running.${NC}"
    exit 1
fi

echo -e "  Found Zion at PID: $ZION_PID"

# Send SIGTERM (15) — Zion's eBPF probe will catch this BEFORE it arrives
echo -e "  ${RED}Sending SIGTERM to Zion (PID: $ZION_PID)...${NC}"
kill -15 "$ZION_PID" 2>/dev/null || true
echo "  → Zion should flag this as SENSOR TAMPERING (T1562)"
echo "  → Zion's eBPF probe detects the kill() syscall targeting its own PID"

echo ""
echo -e "  Note: Zion will detect the attempt but may still shut down"
echo -e "  from SIGTERM. In armed mode, it would kill the attacker first."

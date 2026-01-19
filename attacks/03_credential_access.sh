#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Credential Access
# MITRE ATT&CK: T1003.008 (/etc/shadow)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #4: Credential Access (T1003.008)${NC}"
echo -e "${YELLOW} Attempt to read /etc/shadow${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Method 1: Direct read of /etc/shadow
echo -e "  ${RED}Reading /etc/shadow...${NC}"
cat /etc/shadow > /dev/null 2>&1 || true
echo "  → Zion should flag this as CRITICAL"

# Method 2: Read /etc/gshadow
echo -e "  ${RED}Reading /etc/gshadow...${NC}"
cat /etc/gshadow > /dev/null 2>&1 || true
echo "  → Zion should flag this as CRITICAL"

# Method 3: Attempt to read SSH keys
echo -e "  ${RED}Reading /proc/self/maps (memory mapping)...${NC}"
cat /proc/self/maps > /dev/null 2>&1 || true
echo "  → Zion should flag this as CREDENTIAL DUMPING"

echo -e "  All credential access simulations complete."

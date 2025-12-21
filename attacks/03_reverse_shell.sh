#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Reverse Shell
# MITRE ATT&CK: T1059.004 (Unix Shell)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #3: Reverse Shell (T1059.004)${NC}"
echo -e "${YELLOW} Attempt outbound shell connection${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Method 1: nc (netcat) — will trigger exec pattern + connect detection
echo -e "  ${RED}Method 1: nc (netcat) → 127.0.0.1:4444${NC}"
timeout 1 nc -w 1 127.0.0.1 4444 2>/dev/null || true
echo "  → Connection failed (expected, no listener)"

# Method 2: ncat — triggers offensive tool exec detection
echo -e "  ${RED}Method 2: ncat → 127.0.0.1:4444${NC}"
timeout 1 ncat -w 1 127.0.0.1 4444 2>/dev/null || true
echo "  → Connection failed (expected)"

# Method 3: bash reverse shell (safe — to localhost, will fail)
echo -e "  ${RED}Method 3: bash -i connect to 127.0.0.1:4444${NC}"
timeout 1 bash -c 'exec 5<>/dev/tcp/127.0.0.1/4444' 2>/dev/null || true
echo "  → Connection failed (expected)"

echo -e "  All reverse shell simulations complete."

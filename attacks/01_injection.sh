#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Process Injection via ptrace
# MITRE ATT&CK: T1055 (Process Injection)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #1: Process Injection (T1055)${NC}"
echo -e "${YELLOW} Attach strace to a running process${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Start a dummy target process
sleep 300 &
TARGET_PID=$!
echo -e "  Target process: sleep (PID: ${TARGET_PID})"
echo -e "  ${RED}Attacking with: strace -p ${TARGET_PID}${NC}"
echo ""

# strace will trigger PTRACE_ATTACH → Zion should catch this
timeout 2 strace -p "$TARGET_PID" 2>/dev/null || true

# Cleanup
kill "$TARGET_PID" 2>/dev/null || true
echo -e "  Cleanup complete."

#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion — Run All Attack Simulations
#
# Usage: sudo ./attacks/run_all.sh
#
# Runs in Terminal 2 while Zion monitors in Terminal 1:
#   Terminal 1: sudo ./zion --no-kill --verbose
#   Terminal 2: sudo ./attacks/run_all.sh
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          ⚡ ZION ATTACK SIMULATION SUITE                 ║${NC}"
echo -e "${CYAN}║       8 Attacks · 8 MITRE ATT&CK Techniques             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${YELLOW}Make sure Zion is running in another terminal:${NC}"
echo -e "  ${GREEN}sudo ./zion --no-kill --verbose${NC}"
echo ""
echo -e "  Starting in 3 seconds..."
sleep 3

PAUSE=5

# ── Attack 1: Process Injection ─────────────────────────
echo ""
echo -e "${CYAN}━━━ [1/8] Process Injection (T1055) ━━━${NC}"
bash "$SCRIPT_DIR/01_injection.sh" || true
echo -e "  ${YELLOW}⏳ Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

# ── Attack 2: Privilege Escalation ──────────────────────
echo ""
echo -e "${CYAN}━━━ [2/8] Privilege Escalation (T1068) ━━━${NC}"
bash "$SCRIPT_DIR/02_privesc.sh" || true
echo -e "  ${YELLOW}⏳ Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

# ── Attack 3: Reverse Shell ─────────────────────────────
echo ""
echo -e "${CYAN}━━━ [3/8] Reverse Shell (T1059.004) ━━━${NC}"
bash "$SCRIPT_DIR/03_reverse_shell.sh" || true
echo -e "  ${YELLOW}⏳ Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

# ── Attack 4: Credential Access ─────────────────────────
echo ""
echo -e "${CYAN}━━━ [4/8] Credential Access (T1003.008) ━━━${NC}"
bash "$SCRIPT_DIR/04_credential_access.sh" || true
echo -e "  ${YELLOW}⏳ Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

# ── Attack 5: Defense Evasion ───────────────────────────
echo ""
echo -e "${CYAN}━━━ [5/8] Defense Evasion (T1070) ━━━${NC}"
bash "$SCRIPT_DIR/05_defense_evasion.sh" || true
echo -e "  ${YELLOW}⏳ Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

# ── Attack 6: Persistence ──────────────────────────────
echo ""
echo -e "${CYAN}━━━ [6/8] Persistence (T1053.003) ━━━${NC}"
bash "$SCRIPT_DIR/06_persistence.sh" || true
echo -e "  ${YELLOW}⏳ Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

# ── Attack 7: Fileless Execution ───────────────────────
echo ""
echo -e "${CYAN}━━━ [7/8] Fileless Execution (T1620) ━━━${NC}"
bash "$SCRIPT_DIR/07_fileless.sh" || true
echo -e "  ${YELLOW}⏳ Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

# ── Attack 8: Sensor Tampering ─────────────────────────
echo ""
echo -e "${CYAN}━━━ [8/8] Sensor Tampering (T1562) ━━━${NC}"
echo -e "  ${RED}⚠️  This will send SIGTERM to Zion — run last!${NC}"
bash "$SCRIPT_DIR/08_sensor_tamper.sh" || true

# ── Summary ────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              SIMULATION COMPLETE                         ║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║  8/8 attacks executed (sensor tamper included)            ║${NC}"
echo -e "${CYAN}║  Check Zion terminal for CRITICAL alerts                 ║${NC}"
echo -e "${CYAN}║  Check ./logs/ for JSON event log                        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"

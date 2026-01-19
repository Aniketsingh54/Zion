#!/bin/bash
# Zion -- run all attack simulations
# Usage: sudo ./attacks/run_all.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo -e "${CYAN}+========================================================+${NC}"
echo -e "${CYAN}|          ZION ATTACK SIMULATION SUITE                   |${NC}"
echo -e "${CYAN}|       7 Attacks / 7 MITRE ATT&CK Techniques            |${NC}"
echo -e "${CYAN}+========================================================+${NC}"
echo ""
echo -e "  ${YELLOW}Make sure Zion is running in another terminal:${NC}"
echo -e "  ${GREEN}sudo ./zion --enforce${NC}"
echo ""
echo -e "  Starting in 3 seconds..."
sleep 3

PAUSE=5

echo ""
echo -e "${CYAN}--- [1/7] Process Injection (T1055) ---${NC}"
bash "$SCRIPT_DIR/01_injection.sh" || true
echo -e "  ${YELLOW}Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

echo ""
echo -e "${CYAN}--- [2/7] Privilege Escalation (T1068) ---${NC}"
bash "$SCRIPT_DIR/02_privesc.sh" || true
echo -e "  ${YELLOW}Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

echo ""
echo -e "${CYAN}--- [3/7] Credential Access (T1003.008) ---${NC}"
bash "$SCRIPT_DIR/03_credential_access.sh" || true
echo -e "  ${YELLOW}Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

echo ""
echo -e "${CYAN}--- [4/7] Defense Evasion (T1070) ---${NC}"
bash "$SCRIPT_DIR/04_defense_evasion.sh" || true
echo -e "  ${YELLOW}Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

echo ""
echo -e "${CYAN}--- [5/7] Persistence (T1053.003) ---${NC}"
bash "$SCRIPT_DIR/05_persistence.sh" || true
echo -e "  ${YELLOW}Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

echo ""
echo -e "${CYAN}--- [6/7] Fileless Execution (T1620) ---${NC}"
bash "$SCRIPT_DIR/06_fileless.sh" || true
echo -e "  ${YELLOW}Next attack in ${PAUSE}s...${NC}"
sleep $PAUSE

echo ""
echo -e "${CYAN}--- [7/7] Sensor Tampering (T1562) ---${NC}"
echo -e "  ${RED}This will send SIGTERM to Zion${NC}"
bash "$SCRIPT_DIR/07_sensor_tamper.sh" || true

echo ""
echo -e "${CYAN}+========================================================+${NC}"
echo -e "${CYAN}|              SIMULATION COMPLETE                        |${NC}"
echo -e "${CYAN}+--------------------------------------------------------+${NC}"
echo -e "${CYAN}|  7/7 attacks executed                                   |${NC}"
echo -e "${CYAN}|  Check Zion terminal for alerts                         |${NC}"
echo -e "${CYAN}|  Check ./logs/ for JSON event log                       |${NC}"
echo -e "${CYAN}+========================================================+${NC}"

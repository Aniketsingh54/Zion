#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Kill Switch — manual threat termination
# Usage: sudo ./scripts/kill_switch.sh <PID> [capture]
# ─────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <PID> [capture]${NC}"
    echo "  PID      - Process ID to terminate"
    echo "  capture  - Optional: capture 60s of network traffic"
    exit 1
fi

TARGET_PID=$1
CAPTURE=${2:-""}

# Get process info before killing
PROC_NAME=$(ps -p "$TARGET_PID" -o comm= 2>/dev/null || echo "unknown")

echo -e "${YELLOW}╔═══════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  ZION MANUAL KILL SWITCH              ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════╝${NC}"
echo -e "  Target: ${RED}${PROC_NAME}${NC} (PID: ${TARGET_PID})"

# Kill the process
if kill -9 "$TARGET_PID" 2>/dev/null; then
    echo -e "  Status: ${GREEN}✅ Process terminated${NC}"
else
    echo -e "  Status: ${RED}❌ Failed to kill (already dead?)${NC}"
fi

# Optional: capture traffic
if [ "$CAPTURE" = "capture" ]; then
    PCAP_DIR="./captures"
    mkdir -p "$PCAP_DIR"
    PCAP_FILE="${PCAP_DIR}/zion_manual_$(date +%Y%m%d_%H%M%S).pcap"
    echo -e "  ${YELLOW}📡 Capturing 60s of traffic → ${PCAP_FILE}${NC}"
    timeout 60 tcpdump -i any -w "$PCAP_FILE" 2>/dev/null &
    echo -e "  ${GREEN}Capture running in background (PID: $!)${NC}"
fi

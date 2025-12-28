#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Privilege Escalation via setuid
# MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #2: Privilege Escalation (T1068)${NC}"
echo -e "${YELLOW} Compile and run a setuid(0) exploit${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Create a minimal C exploit that calls setuid(0)
EXPLOIT_SRC=$(mktemp /tmp/zion_exploit_XXXXX.c)
EXPLOIT_BIN=$(mktemp /tmp/zion_exploit_XXXXX)

cat > "$EXPLOIT_SRC" << 'EOF'
#include <unistd.h>
#include <stdio.h>
int main() {
    printf("[EXPLOIT] Attempting setuid(0)...\n");
    if (setuid(0) == 0) {
        printf("[EXPLOIT] Got root!\n");
    } else {
        printf("[EXPLOIT] setuid(0) failed (expected in simulation)\n");
    }
    return 0;
}
EOF

echo -e "  Compiling exploit: ${EXPLOIT_SRC}"
gcc -o "$EXPLOIT_BIN" "$EXPLOIT_SRC" 2>/dev/null


echo -e "  Attempting to run exploit as the original user (to trigger detection)..."
if [ -n "${SUDO_USER:-}" ]; then
    echo "  Running as: $SUDO_USER"
    sudo -u "$SUDO_USER" "$EXPLOIT_BIN" || true
else
    echo "  Running as current user (root?)"
    "$EXPLOIT_BIN" || true
fi

# Cleanup
rm -f "$EXPLOIT_SRC" "$EXPLOIT_BIN"
echo -e "  Cleanup complete."

#!/bin/bash
# ─────────────────────────────────────────────────────────
# Zion Attack Simulation: Fileless Execution
# MITRE ATT&CK: T1620 (Reflective Code Loading)
# ─────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW} ATTACK #7: Fileless Execution (T1620)${NC}"
echo -e "${YELLOW} Execute code directly from memory (memfd_create)${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
echo ""

# Compile a minimal program that uses memfd_create
FILELESS_SRC=$(mktemp /tmp/zion_fileless_XXXXX.c)
FILELESS_BIN=$(mktemp /tmp/zion_fileless_XXXXX)

cat > "$FILELESS_SRC" << 'CEOF'
#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    // Create an anonymous in-memory file descriptor
    int fd = memfd_create("payload", 0);
    if (fd < 0) {
        perror("memfd_create");
        return 1;
    }

    // Write a simple shell script "payload" into memory
    const char *payload = "#!/bin/sh\necho '[PAYLOAD] Executed from memory!'\n";
    write(fd, payload, strlen(payload));

    printf("[FILELESS] memfd_create succeeded → fd=%d\n", fd);
    printf("[FILELESS] Payload loaded in RAM (no file on disk)\n");

    // In a real attack, fexecve() would be used here to execute the payload
    // We skip that for safety
    close(fd);
    return 0;
}
CEOF

echo -e "  Compiling fileless loader: ${FILELESS_SRC}"
gcc -o "$FILELESS_BIN" "$FILELESS_SRC" 2>/dev/null

echo -e "  ${RED}Executing: memfd_create(\"payload\")${NC}"
"$FILELESS_BIN" || true
echo "  → Zion should flag this as FILELESS EXECUTION (T1620)"

# Cleanup
rm -f "$FILELESS_SRC" "$FILELESS_BIN"
echo -e "  Cleanup complete."

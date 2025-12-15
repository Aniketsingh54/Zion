#!/usr/bin/env python3
"""
Zion Enforcer — automated response daemon.

Listens on a Unix domain socket for JSON kill orders from the Go engine.
On receiving an order:
  1. Terminates the threat process with SIGKILL.
  2. Optionally captures 60s of network traffic to a .pcap file.

Usage:
    sudo python3 response/enforcer.py
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SOCKET_PATH = "/tmp/zion_enforcer.sock"
PCAP_DIR = Path("./captures")


def kill_process(pid: int, comm: str) -> bool:
    """Send SIGKILL to a process. Returns True if successful."""
    try:
        os.kill(pid, signal.SIGKILL)
        print(f"[ENFORCER] ✅ Killed process {comm} (PID: {pid})")
        return True
    except ProcessLookupError:
        print(f"[ENFORCER] ⚠️  Process {pid} already dead")
        return False
    except PermissionError:
        print(f"[ENFORCER] ❌ No permission to kill PID {pid}")
        return False


def capture_traffic(duration: int = 60):
    """Capture network traffic to a .pcap file using tcpdump."""
    PCAP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = PCAP_DIR / f"zion_capture_{timestamp}.pcap"

    print(f"[ENFORCER] 📡 Capturing {duration}s of traffic → {pcap_file}")
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", "any", "-w", str(pcap_file), "-G", str(duration), "-W", "1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.wait(timeout=duration + 5)
        print(f"[ENFORCER] 📁 Capture saved: {pcap_file}")
    except FileNotFoundError:
        print("[ENFORCER] ⚠️  tcpdump not found, skipping capture")
    except subprocess.TimeoutExpired:
        proc.terminate()
        print(f"[ENFORCER] 📁 Capture saved: {pcap_file}")


def handle_order(data: bytes):
    """Process a kill order received from the Go engine."""
    try:
        order = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError:
        print(f"[ENFORCER] ❌ Invalid JSON: {data}")
        return

    pid = order.get("pid", 0)
    comm = order.get("comm", "unknown")
    action = order.get("action", "kill")
    capture = order.get("capture", False)

    print(f"\n{'='*60}")
    print(f"[ENFORCER] 🚨 KILL ORDER RECEIVED")
    print(f"  Target: {comm} (PID: {pid})")
    print(f"  Action: {action}")
    print(f"{'='*60}")

    # Action 1: Kill the process
    kill_process(pid, comm)

    # Action 2: Capture traffic if requested
    if capture:
        capture_traffic()


def main():
    # Clean up stale socket
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)

    # Allow non-root Go process to connect (though Zion runs as root)
    os.chmod(SOCKET_PATH, 0o777)

    print(f"[ENFORCER] 🛡️  Zion Enforcer listening on {SOCKET_PATH}")
    print(f"[ENFORCER] Waiting for kill orders from Zion engine...")

    try:
        while True:
            conn, _ = server.accept()
            data = conn.recv(4096)
            if data:
                handle_order(data)
            conn.close()
    except KeyboardInterrupt:
        print("\n[ENFORCER] Shutting down.")
    finally:
        server.close()
        os.unlink(SOCKET_PATH)


if __name__ == "__main__":
    main()

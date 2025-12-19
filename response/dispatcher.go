package response

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// KillOrder is the JSON payload sent to the Python enforcer.
type KillOrder struct {
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Action     string `json:"action"`
	Capture    bool   `json:"capture"`
	Reason     string `json:"reason"`
	SocketPath string `json:"-"` // Not serialized — used internally to find enforcer
}

// enforcerAvailable checks if the Python enforcer is listening.
func enforcerAvailable(socketPath string) bool {
	_, err := os.Stat(socketPath)
	return err == nil
}

// Dispatch sends a kill order to the Python enforcer via Unix socket.
// If the enforcer is not running, it falls back to a direct SIGKILL.
func Dispatch(order KillOrder) {
	socketPath := order.SocketPath
	if socketPath == "" {
		socketPath = "/tmp/zion_enforcer.sock"
	}

	if !enforcerAvailable(socketPath) {
		// Fallback: kill directly from Go if enforcer isn't running
		log.Printf("[DISPATCH] Enforcer not available, direct kill PID %d", order.PID)
		directKill(order.PID, order.Comm)
		return
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		log.Printf("[DISPATCH] Failed to connect to enforcer: %v", err)
		directKill(order.PID, order.Comm)
		return
	}
	defer conn.Close()

	data, err := json.Marshal(order)
	if err != nil {
		log.Printf("[DISPATCH] Failed to marshal kill order: %v", err)
		return
	}

	_, err = conn.Write(data)
	if err != nil {
		log.Printf("[DISPATCH] Failed to send kill order: %v", err)
		directKill(order.PID, order.Comm)
		return
	}

	fmt.Printf("[ZION] 🗡️  Kill order dispatched → PID %d (%s)\n", order.PID, order.Comm)
}

// directKill is the fallback — kills the process directly from Go.
func directKill(pid uint32, comm string) {
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		log.Printf("[DISPATCH] Process %d not found: %v", pid, err)
		return
	}

	if err := proc.Signal(os.Kill); err != nil {
		log.Printf("[DISPATCH] Failed to kill PID %d: %v", pid, err)
	} else {
		fmt.Printf("[ZION] 🗡️  Direct kill → %s (PID: %d)\n", comm, pid)
	}
}

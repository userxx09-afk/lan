//go:build windows

// NetInventory Remote: the remote control agent. A second agent, separate from the inventory agent, that only does
// remote control sessions started from the NetInventory dashboard.
//
// Security model (see README "Remote control"):
//   - Nothing listens on the PC. The service keeps one outbound WebSocket over TLS to the NetInventory server
//     (the server's certificate is pinned by SHA-256), signed with this PC's own secret (HMAC-SHA256).
//   - The server can only ask for a session. The agent asks the signed-in user (Yes/No, default No, times out to
//     No) unless the server says the technician may connect directly (a member of the "connect without asking" AD
//     group). Policy AlwaysAsk=1 (GPO) forces the question whatever the server says; Disabled=1 turns sessions off.
//   - Each session gets its own one-time token. The screen is streamed by a helper process started in the user's
//     session for that one session only, with a visible "remote control by ..." bar and an End button.
//   - No clipboard, no file transfer, no commands: screen out, mouse and keyboard in.
//
// Modes (first argument): service (run by the Service Control Manager), helper (started by the service),
// configure (run by the MSI), cleanup (run by the MSI on uninstall), debug (the service loop in a console).
package main

import (
	"fmt"
	"os"
	"strings"
)

var version = "dev" // set by the build: -ldflags "-X main.version=1.2.3"

func main() {
	mode := "service"
	if len(os.Args) > 1 {
		mode = strings.ToLower(strings.TrimLeft(os.Args[1], "-/"))
	}
	var err error
	switch mode {
	case "service":
		err = runService(false)
	case "debug":
		err = runService(true)
	case "helper":
		err = runHelper()
	case "configure":
		err = configure(os.Args[2:])
	case "cleanup":
		err = cleanup()
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown mode %q (service, debug, configure, cleanup, version)", mode)
	}
	if err != nil {
		logf("error: %v", err)
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

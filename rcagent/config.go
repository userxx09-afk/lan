//go:build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	serviceName = "NetInventoryRemote"
	policyKey   = `SOFTWARE\Policies\NetInventory\Remote`
	eventSource = "NetInventory Remote"
)

var serverRe = regexp.MustCompile(`^https://[A-Za-z0-9.\-]+(:\d{1,5})?$`)

type Config struct {
	Server      string   `json:"Server"`
	EnrollToken string   `json:"EnrollToken"`
	Pin         string   `json:"Pin"`
	AlwaysAsk   bool     `json:"-"`
	Disabled    bool     `json:"-"`
	Pins        []string `json:"-"`
}

type State struct {
	AgentID string `json:"agent_id"`
	Secret  string `json:"secret"` // DPAPI (LocalMachine) protected, base64
	key     []byte
}

func dataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "NetInventory Remote")
}

var logMu sync.Mutex

func logf(format string, a ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	f := filepath.Join(dataDir(), "agent.log")
	if st, err := os.Stat(f); err == nil && st.Size() > 512*1024 {
		_ = os.Rename(f, f+".1")
	}
	h, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer h.Close()
	fmt.Fprintf(h, "%s %s\n", time.Now().UTC().Format("2006-01-02 15:04:05Z"), fmt.Sprintf(format, a...))
}

// Event log entries on the PC itself, so a local admin can see every session without the server.
func eventf(warn bool, format string, a ...any) {
	l, err := eventlog.Open(eventSource)
	if err != nil {
		return
	}
	defer l.Close()
	msg := fmt.Sprintf(format, a...)
	if warn {
		_ = l.Warning(2, msg)
	} else {
		_ = l.Info(1, msg)
	}
}

func loadConfig() (*Config, error) {
	c := &Config{}
	if b, err := os.ReadFile(filepath.Join(dataDir(), "config.json")); err == nil {
		_ = json.Unmarshal(b, c)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, policyKey, registry.QUERY_VALUE); err == nil {
		for name, dst := range map[string]*string{"Server": &c.Server, "EnrollToken": &c.EnrollToken, "Pin": &c.Pin} {
			if v, _, err := k.GetStringValue(name); err == nil && v != "" {
				*dst = v
			}
		}
		if v, _, err := k.GetIntegerValue("AlwaysAsk"); err == nil && v != 0 {
			c.AlwaysAsk = true
		}
		if v, _, err := k.GetIntegerValue("Disabled"); err == nil && v != 0 {
			c.Disabled = true
		}
		k.Close()
	}
	c.Server = strings.TrimRight(strings.TrimSpace(c.Server), "/")
	if !serverRe.MatchString(c.Server) {
		return c, fmt.Errorf("server must look like https://netinv.corp.local:8080 (got %q)", c.Server)
	}
	for _, p := range strings.FieldsFunc(c.Pin, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		p = strings.ToUpper(strings.ReplaceAll(p, ":", ""))
		if len(p) == 64 {
			c.Pins = append(c.Pins, p)
		}
	}
	return c, nil
}

func loadState() (*State, error) {
	b, err := os.ReadFile(filepath.Join(dataDir(), "state.json"))
	if err != nil {
		return nil, err
	}
	s := &State{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	enc, err := base64.StdEncoding.DecodeString(s.Secret)
	if err != nil {
		return nil, err
	}
	if s.key, err = unprotect(enc); err != nil {
		return nil, fmt.Errorf("can't decrypt the agent secret: %w", err)
	}
	return s, nil
}

func saveState(agentID string, secret []byte) error {
	enc, err := protect(secret)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(State{AgentID: agentID, Secret: base64.StdEncoding.EncodeToString(enc)})
	return os.WriteFile(filepath.Join(dataDir(), "state.json"), b, 0o600)
}

func dropState() { _ = os.Remove(filepath.Join(dataDir(), "state.json")) }

// The enrollment token (a one-time push ticket, or the site token) is only needed once: forget it after enrolling.
func forgetToken() {
	f := filepath.Join(dataDir(), "config.json")
	c := &Config{}
	if b, err := os.ReadFile(f); err == nil && json.Unmarshal(b, c) == nil && c.EnrollToken != "" {
		c.EnrollToken = ""
		b, _ := json.Marshal(c)
		_ = os.WriteFile(f, b, 0o600)
	}
}

// ------------------------------------------------------------------ DPAPI, machine scope (only SYSTEM/admins can
// read the file, the secret is tied to this PC)
func protect(b []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty")
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// ------------------------------------------------------------------ install / uninstall steps (run by the MSI as SYSTEM)
func configure(args []string) error {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	server := fs.String("server", "", "https://server:port")
	token := fs.String("token", "", "enrollment token or one-time push ticket")
	pin := fs.String("pin", "", "SHA-256 of the server certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// No inheritance; SYSTEM and Administrators only. Users can't read the config or the secret.
	if out, err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), dir, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput(); err != nil {
		return fmt.Errorf("icacls: %v %s", err, out)
	}
	f := filepath.Join(dir, "config.json")
	c := &Config{}
	if b, err := os.ReadFile(f); err == nil {
		_ = json.Unmarshal(b, c)
	}
	if s := strings.TrimRight(strings.TrimSpace(*server), "/"); s != "" {
		if !serverRe.MatchString(s) {
			return fmt.Errorf("server must look like https://netinv.corp.local:8080")
		}
		c.Server = s
	}
	if t := strings.TrimSpace(*token); t != "" {
		c.EnrollToken = t
		if c.Server != "" {
			dropState() // a new token means a new enrollment (a push from the dashboard)
		}
	}
	if p := strings.TrimSpace(*pin); p != "" {
		c.Pin = p
	}
	b, _ := json.Marshal(c)
	if err := os.WriteFile(f, b, 0o600); err != nil {
		return err
	}
	_ = eventlog.InstallAsEventCreate(eventSource, eventlog.Error|eventlog.Warning|eventlog.Info)
	// Ctrl+Alt+Del from a session needs software SAS generation allowed for services (1). Leave a stricter or
	// broader value an admin or GPO set alone.
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE|registry.SET_VALUE); err == nil {
		if _, _, err := k.GetIntegerValue("SoftwareSASGeneration"); err != nil {
			_ = k.SetDWordValue("SoftwareSASGeneration", 1)
		}
		k.Close()
	}
	logf("configured (server %s)", c.Server)
	return nil
}

func cleanup() error {
	_ = eventlog.Remove(eventSource)
	return os.RemoveAll(dataDir())
}

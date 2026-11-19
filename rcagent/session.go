//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// One remote control session at a time on a PC.
type sessionMgr struct {
	mu   sync.Mutex
	sid  string
	proc windows.Handle
	why  string
}

var sess sessionMgr

func (s *sessionMgr) active(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sid != "" && s.sid == sid
}

func (s *sessionMgr) claim(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sid != "" {
		return false
	}
	s.sid = sid
	return true
}

func (s *sessionMgr) release(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sid == sid {
		s.sid, s.proc, s.why = "", 0, ""
	}
}

// end stops the session's helper, or, while the user is still being asked, makes sure it never starts.
func (s *sessionMgr) end(sid, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sid == sid {
		s.why = why
		if s.proc != 0 {
			_ = windows.TerminateProcess(s.proc, 0)
		}
	}
}

func (s *sessionMgr) ended(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sid == sid && s.why != ""
}

func (s *sessionMgr) stop(why string) {
	s.mu.Lock()
	sid := s.sid
	s.mu.Unlock()
	if sid != "" {
		s.end(sid, why)
	}
}

func startSession(ctx context.Context, ctl *control, cfg *Config, sid, tech, reason string, ask bool, wait int, nouser, token string) {
	reply := func(result, user, detail string) {
		ctl.send(map[string]any{"t": "consent", "sid": sid, "result": result, "user": user, "detail": detail})
	}
	if cfg == nil || cfg.Disabled {
		reply("disabled", "", "remote control is turned off on this PC (policy Disabled=1)")
		return
	}
	if len(token) < 32 || len(token) > 128 {
		reply("error", "", "bad session token")
		return
	}
	if !sess.claim(sid) {
		reply("busy", "", "another remote control session is already running on this PC")
		return
	}
	defer sess.release(sid)
	ws := windows.WTSGetActiveConsoleSessionId()
	user := ""
	if ws != 0xFFFFFFFF {
		user = sessionUser(ws)
	}
	if user == "" {
		if nouser != "allow" {
			reply("nouser-denied", "", "nobody is signed in to this PC, and NetInventory is set to refuse then")
			return
		}
		if ws == 0xFFFFFFFF {
			reply("error", "", "no console session")
			return
		}
		reply("nouser-allowed", "", "nobody is signed in")
	} else if ask {
		wait = min(max(wait, 10), 300)
		msg := fmt.Sprintf("%s wants to see and control this computer with NetInventory remote control.", tech)
		if reason != "" {
			msg += "\n\nReason: " + reason
		}
		msg += fmt.Sprintf("\n\nAllow it? (If you don't answer within %d seconds, the answer is No.)\nYou can end the session at any time with End on the bar at the top of the screen.", wait)
		switch askUser(ws, "Remote control request", msg, wait) {
		case idYes:
			reply("accepted", user, "")
			eventf(false, "Remote control by %s accepted by %s.", tech, user)
		case idTimeout:
			reply("timeout", user, "")
			eventf(true, "Remote control request by %s: no answer from %s.", tech, user)
			return
		default:
			reply("denied", user, "")
			eventf(true, "Remote control request by %s refused by %s.", tech, user)
			return
		}
	} else {
		reply("direct", user, "")
	}
	if sess.ended(sid) { // the technician gave up while the user was being asked
		logf("session %s by %s: ended before it started", sid[:8], tech)
		return
	}
	eventf(false, "Remote control session by %s started (session %s).", tech, sid[:8])
	why, err := runHelperIn(ctx, ws, sid, token, tech)
	if err != nil {
		why = "couldn't start the screen helper: " + err.Error()
	}
	logf("session %s by %s ended: %s", sid[:8], tech, why)
	eventf(false, "Remote control session by %s ended: %s.", tech, why)
	ctl.send(map[string]any{"t": "ended", "sid": sid, "why": why})
}

// runHelperIn starts this exe as "helper" in the user's session, as SYSTEM (so it can see the secure desktop:
// sign-in screen, UAC prompts), and waits for it. The session id and token go to it over a pipe, never on the
// command line.
func runHelperIn(ctx context.Context, wsid uint32, sid, token, tech string) (string, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_SESSIONID|windows.TOKEN_ADJUST_DEFAULT, &self); err != nil {
		return "", err
	}
	defer self.Close()
	var tok windows.Token
	if err := windows.DuplicateTokenEx(self, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	if err := windows.SetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&wsid)), 4); err != nil {
		return "", fmt.Errorf("set session: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	// stdin pipe: the child's end is inheritable, ours isn't
	var rd, wr windows.Handle
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err := windows.CreatePipe(&rd, &wr, &sa, 0); err != nil {
		return "", err
	}
	_ = windows.SetHandleInformation(wr, windows.HANDLE_FLAG_INHERIT, 0)
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desk,
		Flags: windows.STARTF_USESTDHANDLES, StdInput: rd}
	var pi windows.ProcessInformation
	cmd, _ := windows.UTF16PtrFromString(windows.EscapeArg(exe) + " helper")
	exe16, _ := windows.UTF16PtrFromString(exe)
	err = windows.CreateProcessAsUser(tok, exe16, cmd, nil, nil, true, windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT, nil, nil, &si, &pi)
	windows.CloseHandle(rd)
	if err != nil {
		windows.CloseHandle(wr)
		return "", err
	}
	windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	b, _ := json.Marshal(helperArgs{Sid: sid, Token: token, Tech: tech})
	var n uint32
	_ = windows.WriteFile(wr, b, &n, nil)
	windows.CloseHandle(wr)
	sess.mu.Lock()
	sess.proc = pi.Process
	sess.mu.Unlock()
	// wait for the helper, or the service stopping
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	go func() {
		<-wctx.Done()
		if ctx.Err() != nil {
			sess.end(sid, "the agent stopped")
		}
	}()
	_, _ = windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	var code uint32
	_ = windows.GetExitCodeProcess(pi.Process, &code)
	sess.mu.Lock()
	why := sess.why
	sess.mu.Unlock()
	if why == "" {
		why = map[uint32]string{0: "ended", exitUserEnded: "ended by the user at the PC", exitServer: "the connection to NetInventory ended",
			exitIdle: "no viewer", exitError: "helper error"}[code]
		if why == "" {
			why = fmt.Sprintf("helper exit code %d", code)
		}
	}
	return why, nil
}

const (
	exitUserEnded = 10
	exitServer    = 11
	exitIdle      = 12
	exitError     = 13
)

type helperArgs struct {
	Sid   string `json:"sid"`
	Token string `json:"token"`
	Tech  string `json:"tech"`
}

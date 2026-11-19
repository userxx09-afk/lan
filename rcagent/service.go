//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/sys/windows/svc"
)

const controlPath = "/api/rc/agent/control"

var sidRe = regexp.MustCompile(`^[A-Za-z0-9_\-]{16,64}$`)

type svcHandler struct{}

func (svcHandler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { controlLoop(ctx); close(done) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
			}
			return false, 0
		}
	}
	return false, 0
}

func runService(console bool) error {
	if console {
		controlLoop(context.Background())
		return nil
	}
	return svc.Run(serviceName, svcHandler{})
}

// controlLoop keeps the one outbound control connection open, reconnecting with backoff.
func controlLoop(ctx context.Context) {
	logf("NetInventory Remote %s starting", version)
	wait := 5 * time.Second
	lastErr := ""
	for ctx.Err() == nil {
		start := time.Now()
		err := controlOnce(ctx)
		if ctx.Err() != nil {
			break
		}
		if time.Since(start) > 2*time.Minute {
			wait = 5 * time.Second // it was up for a while: a normal drop
		}
		msg := fmt.Sprint(err)
		if msg != lastErr { // don't fill the log with the same error every minute
			logf("error: %s", msg)
			lastErr = msg
		}
		var he *httpError
		if errors.As(err, &he) && he.code == 403 {
			wait = max(wait, time.Minute) // waiting for approval, or turned off on the server
		}
		jitter := time.Duration(rand.Int64N(int64(wait / 2)))
		select {
		case <-ctx.Done():
		case <-time.After(wait + jitter):
		}
		wait = min(wait*2, 2*time.Minute)
	}
	sess.stop("the agent stopped")
	logf("stopped")
}

func controlOnce(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	st, err := loadState()
	if err != nil {
		if st, err = enroll(ctx, cfg); err != nil {
			return fmt.Errorf("enrollment: %w", err)
		}
	}
	h := http.Header{}
	sign(h, st, controlPath, nil)
	h.Set("X-Agent-Version", version)
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	conn, err := dial(dctx, cfg, controlPath, h)
	dcancel()
	if err != nil {
		var he *httpError
		if errors.As(err, &he) && he.code == 401 { // unknown or revoked: enroll again (needs a new token)
			dropState()
		}
		return err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(64 << 10)
	logf("connected to %s", cfg.Server)
	ctl := &control{conn: conn}
	ctl.send(map[string]any{"t": "hello", "host": hostname(), "version": version, "user": consoleUser(),
		"always_ask": cfg.AlwaysAsk, "disabled": cfg.Disabled})
	// keepalive: a ping every 30 s, so dead connections (sleep, network change) are noticed within a minute
	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pctx.Done():
				return
			case <-t.C:
				c, cancel := context.WithTimeout(pctx, 20*time.Second)
				err := conn.Ping(c)
				cancel()
				if err != nil {
					conn.CloseNow()
					return
				}
			}
		}
	}()
	for {
		_, b, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		var m struct {
			T      string `json:"t"`
			Sid    string `json:"sid"`
			Tech   string `json:"tech"`
			Ask    bool   `json:"ask"`
			Wait   int    `json:"wait"`
			NoUser string `json:"nouser"`
			Token  string `json:"token"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(b, &m) != nil || !sidRe.MatchString(m.Sid) {
			continue
		}
		switch m.T {
		case "session":
			cfg, _ := loadConfig() // re-read: GPO may have changed AlwaysAsk/Disabled
			go startSession(ctx, ctl, cfg, m.Sid, clean(m.Tech, 64), clean(m.Reason, 200), m.Ask || cfg.AlwaysAsk, m.Wait, m.NoUser, m.Token)
		case "end":
			sess.end(m.Sid, "ended from NetInventory")
		case "cad":
			if sess.active(m.Sid) {
				sendSAS()
			}
		}
	}
}

type control struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (c *control) send(v any) {
	b, _ := json.Marshal(v)
	c.mu.Lock()
	defer c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.conn.Write(ctx, websocket.MessageText, b)
}

// clean keeps text from the server short and printable (it is shown to the user in the question and the bar).
func clean(s string, n int) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && (r < 0x80 || r >= 0xa0) {
			out = append(out, r)
		}
		if len(out) >= n {
			break
		}
	}
	return string(out)
}

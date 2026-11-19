//go:build windows

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const streamPath = "/api/rc/agent/stream"

var codeRe = regexp.MustCompile(`^[A-Za-z0-9]{1,24}$`)

// What the viewer may send (relayed and checked by the server, checked again here).
type inMsg struct {
	T  string `json:"t"`
	X  int    `json:"x"`
	Y  int    `json:"y"`
	B  int    `json:"b"`
	DX int    `json:"dx"`
	DY int    `json:"dy"`
	C  string `json:"c"`
	I  int    `json:"i"`
	V  int    `json:"v"`
}

// runHelper runs in the user's Windows session for one remote control session.
func runHelper() error {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return err
	}
	var a helperArgs
	if err := json.Unmarshal(b, &a); err != nil || !sidRe.MatchString(a.Sid) {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	setDPIAware()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := http.Header{}
	h.Set("X-Rc-Session", a.Sid)
	h.Set("X-Rc-Token", a.Token)
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	conn, err := dial(dctx, cfg, streamPath, h)
	dcancel()
	if err != nil {
		logf("session %s: stream: %v", a.Sid[:8], err)
		os.Exit(exitServer)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(16 << 10)

	exit := make(chan int, 4)
	bar := startBanner(a.Tech, func() { exit <- exitUserEnded })
	defer bar.close()

	d := newDesk(conn)
	go d.run(ctx)
	go func() {
		for {
			_, msg, err := conn.Read(ctx)
			if err != nil {
				exit <- exitServer
				return
			}
			var m inMsg
			if json.Unmarshal(msg, &m) != nil {
				continue
			}
			switch m.T {
			case "ack":
				d.ack()
			case "end":
				exit <- exitServer
				return
			case "mm", "md", "mu", "wh", "kd", "ku", "mon", "q", "full", "rel":
				if (m.T == "kd" || m.T == "ku") && !codeRe.MatchString(m.C) {
					continue
				}
				select {
				case d.in <- m:
				default: // the PC can't keep up: drop input rather than queue it forever
				}
			}
		}
	}()
	code := <-exit
	d.releaseKeys()
	time.Sleep(100 * time.Millisecond)
	if code == exitUserEnded {
		ctx2, c2 := context.WithTimeout(context.Background(), 3*time.Second)
		b, _ := json.Marshal(map[string]string{"t": "bye", "why": "ended by the user at the PC"})
		_ = conn.Write(ctx2, websocket.MessageText, b)
		c2()
		conn.Close(websocket.StatusNormalClosure, "ended at the PC")
	}
	os.Exit(code)
	return nil
}

// desk owns the thread that is attached to the input desktop (Default, Winlogon or the UAC prompt): it captures
// the screen and sends input there.
type desk struct {
	conn    *websocket.Conn
	in      chan inMsg
	acked   chan struct{}
	mu      sync.Mutex
	pressed map[string]bool
}

func newDesk(c *websocket.Conn) *desk {
	return &desk{conn: c, in: make(chan inMsg, 256), acked: make(chan struct{}, 1), pressed: map[string]bool{}}
}

func (d *desk) ack() {
	select {
	case d.acked <- struct{}{}:
	default:
	}
}

func (d *desk) releaseKeys() {
	d.mu.Lock()
	keys := make([]string, 0, len(d.pressed))
	for k := range d.pressed {
		keys = append(keys, k)
	}
	d.mu.Unlock()
	for _, k := range keys {
		select {
		case d.in <- inMsg{T: "ku", C: k}:
		default:
		}
	}
}

func (d *desk) run(ctx context.Context) {
	runtime.LockOSThread() // SetThreadDesktop is per thread; this goroutine never leaves it
	cap := &capturer{quality: 70}
	defer cap.free()
	var mons []monitor
	mon := 0
	sendInfo := func() {
		mons = monitors()
		if mon >= len(mons) {
			mon = 0
		}
		info := map[string]any{"t": "info", "mon": mon, "mons": mons, "desk": cap.deskName}
		b, _ := json.Marshal(info)
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = d.conn.Write(c, websocket.MessageText, b)
		cancel()
	}
	cap.attach()
	sendInfo()
	inFlight := false
	var sentAt time.Time
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-d.in:
			if cap.attach() {
				sendInfo()
			}
			switch m.T {
			case "mon":
				if m.I >= 0 && m.I < len(mons) {
					mon = m.I
					cap.full = true
					sendInfo()
				}
			case "q":
				cap.quality = min(max(m.V, 20), 95)
				cap.full = true
			case "full":
				cap.full = true
			case "rel": // the viewer lost focus: let go of every key it still holds down
				d.mu.Lock()
				for k := range d.pressed {
					key(k, false)
				}
				d.pressed = map[string]bool{}
				d.mu.Unlock()
			case "kd", "ku":
				if key(m.C, m.T == "kd") {
					d.mu.Lock()
					if m.T == "kd" {
						d.pressed[m.C] = true
					} else {
						delete(d.pressed, m.C)
					}
					d.mu.Unlock()
				}
			default:
				if mon < len(mons) {
					mouse(mons[mon], m)
				}
			}
		case <-d.acked:
			inFlight = false
		case <-tick.C:
			if inFlight && time.Since(sentAt) < 3*time.Second {
				continue
			}
			if cap.attach() {
				sendInfo()
			}
			if len(mons) == 0 {
				sendInfo()
				continue
			}
			msg := cap.frame(mons[mon])
			if msg == nil {
				continue
			}
			c, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := d.conn.Write(c, websocket.MessageBinary, msg)
			cancel()
			if err != nil {
				return
			}
			inFlight, sentAt = true, time.Now()
		}
	}
}

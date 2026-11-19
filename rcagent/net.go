//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/sys/windows/registry"
)

// httpClient: TLS 1.2+, no proxy, no redirects. With a pin, the server's leaf certificate must match it (the
// usual case: the NetInventory server often has a self-signed or internal-CA certificate); without one it must be
// trusted by Windows.
func httpClient(c *Config) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(c.Pins) > 0 {
		pins := c.Pins
		tc.InsecureSkipVerify = true // replaced by the pin check below, which always runs
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server sent no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			got := strings.ToUpper(hex.EncodeToString(sum[:]))
			for _, p := range pins {
				if hmac.Equal([]byte(p), []byte(got)) {
					return nil
				}
			}
			return fmt.Errorf("server certificate %s doesn't match the pinned one", got[:16])
		}
	} else if pool, err := x509.SystemCertPool(); err == nil {
		tc.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:               nil,
		TLSClientConfig:     tc,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   false, // WebSocket upgrades need HTTP/1.1
	}
	return &http.Client{Transport: tr, Timeout: 0,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func sign(h http.Header, st *State, path string, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nb := make([]byte, 16)
	_, _ = rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	bh := sha256.Sum256(body)
	m := hmac.New(sha256.New, st.key)
	m.Write([]byte(ts + "\n" + nonce + "\n" + path + "\n" + hex.EncodeToString(bh[:])))
	h.Set("X-Agent-Id", st.AgentID)
	h.Set("X-Agent-Ts", ts)
	h.Set("X-Agent-Nonce", nonce)
	h.Set("X-Agent-Sig", hex.EncodeToString(m.Sum(nil)))
}

func hostname() string {
	h, _ := os.Hostname()
	return strings.ToUpper(strings.SplitN(h, ".", 2)[0])
}

func machineGUID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("MachineGuid")
	return v
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return fmt.Sprintf("server said %d: %s", e.code, e.msg) }

func detail(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 2048))
	var j struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(b, &j) == nil && j.Detail != nil {
		return fmt.Sprint(j.Detail)
	}
	return strings.TrimSpace(string(b))
}

// enroll trades the enrollment token for this PC's own secret.
func enroll(ctx context.Context, c *Config) (*State, error) {
	if c.EnrollToken == "" {
		return nil, errors.New("not enrolled and no enrollment token: push the remote control agent again from the dashboard")
	}
	fqdn, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{"token": c.EnrollToken, "hostname": hostname(), "fqdn": fqdn,
		"machine_guid": machineGUID(), "version": version})
	req, _ := http.NewRequestWithContext(ctx, "POST", c.Server+"/api/rc/agent/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NetInventoryRemote/"+version)
	resp, err := httpClient(c).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &httpError{resp.StatusCode, detail(resp.Body)}
	}
	var out struct {
		AgentID string `json:"agent_id"`
		Secret  string `json:"secret"`
		Status  string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&out); err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(out.Secret)
	if err != nil || len(key) < 32 || out.AgentID == "" {
		return nil, errors.New("bad enrollment answer")
	}
	if err := saveState(out.AgentID, key); err != nil {
		return nil, err
	}
	forgetToken()
	logf("enrolled as %s (%s)", out.AgentID, out.Status)
	return &State{AgentID: out.AgentID, key: key}, nil
}

func wsURL(c *Config, path string) string {
	return "wss://" + strings.TrimPrefix(c.Server, "https://") + path
}

func dial(ctx context.Context, c *Config, path string, h http.Header) (*websocket.Conn, error) {
	h.Set("User-Agent", "NetInventoryRemote/"+version)
	conn, resp, err := websocket.Dial(ctx, wsURL(c, path), &websocket.DialOptions{HTTPClient: httpClient(c), HTTPHeader: h})
	if err != nil {
		if resp != nil && resp.StatusCode >= 400 {
			return nil, &httpError{resp.StatusCode, detail(resp.Body)}
		}
		return nil, err
	}
	return conn, nil
}

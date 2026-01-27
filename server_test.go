package masktunnel

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func disableEnvProxy(t *testing.T) {
	t.Helper()
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("no_proxy", "*")
}

func TestHandleHTTPUsesUpstreamProxy(t *testing.T) {
	disableEnvProxy(t)

	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("X-Upstream-Proxy", "1")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(upstream.Close)

	cfg := &Config{UpstreamProxy: upstream.URL}
	s := NewServer(cfg)

	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/hello", nil)
	rr := httptest.NewRecorder()

	s.ServeHTTP(rr, req)

	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("expected status 200, got %d, body=%q", res.StatusCode, string(body))
	}
	if upstreamHits.Load() == 0 {
		t.Fatalf("expected request to hit upstream proxy")
	}
	if res.Header.Get("X-Upstream-Proxy") != "1" {
		t.Fatalf("expected upstream header to be forwarded")
	}
	body, _ := io.ReadAll(res.Body)
	if string(body) != "upstream-ok" {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestHandleWebSocketUpgradeUsesUpstreamProxy(t *testing.T) {
	disableEnvProxy(t)

	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.Header().Set("X-Upstream-Proxy", "1")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked by upstream"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := &Config{UpstreamProxy: upstream.URL}
	s := NewServer(cfg)

	req := httptest.NewRequest(http.MethodGet, "http://example.invalid/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	req.Header.Set("Sec-WebSocket-Version", "13")

	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)

	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("expected status 403, got %d, body=%q", res.StatusCode, string(body))
	}
	if upstreamHits.Load() == 0 {
		t.Fatalf("expected websocket upgrade request to hit upstream proxy")
	}
	if res.Header.Get("X-Upstream-Proxy") != "1" {
		t.Fatalf("expected upstream header to be forwarded")
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "blocked by upstream") {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestSetUpstreamProxyEndpointReadsFullBody(t *testing.T) {
	cfg := &Config{}
	s := NewServer(cfg)

	proxyURL := "http://127.0.0.1:12345"
	body := strings.Repeat(" ", 2048) + proxyURL

	req := httptest.NewRequest(http.MethodPost, "http://masktunnel.local/__masktunnel__/proxy", strings.NewReader(body))
	rr := httptest.NewRecorder()

	s.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("expected status 200, got %d, body=%q", res.StatusCode, string(b))
	}
	if cfg.UpstreamProxy != proxyURL {
		t.Fatalf("expected upstream proxy %q, got %q", proxyURL, cfg.UpstreamProxy)
	}
}

func TestOriginFormRequestIsForwarded(t *testing.T) {
	disableEnvProxy(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("target-ok"))
	}))
	t.Cleanup(target.Close)

	tu, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("failed to parse target url: %v", err)
	}

	s := NewServer(&Config{})

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Path: "/"},
		Header:     make(http.Header),
		Host:       tu.Host,
		RequestURI: "/",
		Body:       http.NoBody,
	}
	rr := httptest.NewRecorder()

	s.ServeHTTP(rr, req)
	res := rr.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("expected status 200, got %d, body=%q", res.StatusCode, string(b))
	}
	b, _ := io.ReadAll(res.Body)
	if string(b) != "target-ok" {
		t.Fatalf("unexpected body: %q", string(b))
	}
}

func TestStartWithIPv6Addr(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	_ = ln.Close()

	s := NewServer(&Config{Addr: "::1", Port: "0"})

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.ActualAddr() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if s.ActualAddr() == "" {
		_ = s.Stop()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("server failed to start: %v", err)
			}
		default:
		}
		t.Fatalf("server did not report actual address")
	}

	host, port, err := net.SplitHostPort(s.ActualAddr())
	if err != nil {
		_ = s.Stop()
		<-errCh
		t.Fatalf("invalid actual address %q: %v", s.ActualAddr(), err)
	}
	if host != "::1" {
		_ = s.Stop()
		<-errCh
		t.Fatalf("expected host ::1, got %q", host)
	}
	if port == "" || port == "0" {
		_ = s.Stop()
		<-errCh
		t.Fatalf("expected non-zero port, got %q", port)
	}

	if err := s.Stop(); err != nil {
		<-errCh
		t.Fatalf("stop failed: %v", err)
	}
	if err := <-errCh; err != nil && err != http.ErrServerClosed {
		t.Fatalf("unexpected start error: %v", err)
	}
}

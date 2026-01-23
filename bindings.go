package masktunnel

import (
	"encoding/json"
	"fmt"
	"net"
)

// Python bindings: gopy-friendly API surface.

// ServerOption describes server configuration for bindings.
// Keep fields as basic types to ensure gopy can map them.
type ServerOption struct {
	Addr          string
	Port          string
	UserAgent     string
	Payload       string
	UpstreamProxy string
	Username      string
	Password      string
	Verbose       int
}

// DefaultServerOption returns default options.
func DefaultServerOption() *ServerOption {
	return &ServerOption{
		Port:    "8080",
		Verbose: 0,
	}
}

// ServerHandle wraps *Server for Python.
// Note: gopy doesn't like interfaces or embedded complex fields; keep it simple.
type ServerHandle struct {
	s *Server
}

// NewServerHandle creates a new server handle.
func NewServerHandle(opt *ServerOption) *ServerHandle {
	if opt == nil {
		opt = DefaultServerOption()
	}
	cfg := &Config{
		Addr:          opt.Addr,
		Port:          opt.Port,
		UserAgent:     opt.UserAgent,
		Payload:       opt.Payload,
		UpstreamProxy: opt.UpstreamProxy,
		Username:      opt.Username,
		Password:      opt.Password,
		Verbose:       opt.Verbose,
	}
	return &ServerHandle{s: NewServer(cfg)}
}

// Start starts the proxy server (blocking).
func (h *ServerHandle) Start() error {
	if h == nil || h.s == nil {
		return fmt.Errorf("server not initialized")
	}
	return h.s.Start()
}

// Stop stops the proxy server.
func (h *ServerHandle) Stop() error {
	if h == nil || h.s == nil {
		return nil
	}
	return h.s.Stop()
}

// Close is an alias of Stop.
func (h *ServerHandle) Close() error {
	return h.Stop()
}

// Addr returns the effective listen address (host:port).
func (h *ServerHandle) Addr() string {
	if h == nil || h.s == nil || h.s.config == nil {
		return ""
	}
	return net.JoinHostPort(h.s.config.Addr, h.s.config.Port)
}

// SetUpstreamProxy sets the upstream proxy and resets sessions.
func (h *ServerHandle) SetUpstreamProxy(proxyURL string) error {
	if h == nil || h.s == nil || h.s.config == nil {
		return fmt.Errorf("server not initialized")
	}
	h.s.config.UpstreamProxy = proxyURL
	if h.s.sessionManager != nil {
		h.s.sessionManager.CloseAll()
	}
	return nil
}

// ResetSessions closes all cached TLS sessions.
func (h *ServerHandle) ResetSessions() int {
	if h == nil || h.s == nil || h.s.sessionManager == nil {
		return 0
	}
	count := h.s.sessionManager.GetSessionCount()
	h.s.sessionManager.CloseAll()
	return count
}

// GetSupportedBrowsersForPython returns the list of supported browser names.
func GetSupportedBrowsersForPython() []string {
	return GetSupportedBrowsers()
}

// GetSupportedVersionsForPython returns the supported major versions for a browser.
func GetSupportedVersionsForPython(browserName string) []int {
	return GetSupportedVersions(browserName)
}

// GetBrowserFingerprintJSON returns a JSON string describing the fingerprint.
func GetBrowserFingerprintJSON(userAgent string) (string, error) {
	fp, err := GetBrowserFingerprint(userAgent)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(fp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GetCAPEM returns the in-memory CA certificate in PEM format.
func (h *ServerHandle) GetCAPEM() []byte {
	if h == nil || h.s == nil || h.s.certManager == nil {
		return nil
	}
	return h.s.certManager.GetCACertPEM()
}

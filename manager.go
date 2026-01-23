package masktunnel

import (
	"fmt"
	"sync"

	"github.com/Noooste/azuretls-client"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Manager manages all azuretls sessions
type Manager struct {
	sessions map[string]*azuretls.Session
	mu       sync.RWMutex
	logger   zerolog.Logger
}

// NewManager creates a new session manager
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*azuretls.Session),
		logger:   log.Logger,
	}
}

// NewManagerWithLogger creates a new session manager with custom logger
func NewManagerWithLogger(logger zerolog.Logger) *Manager {
	return &Manager{
		sessions: make(map[string]*azuretls.Session),
		logger:   logger,
	}
}

// GetSession gets or creates session based on configuration
func (m *Manager) GetSession(userAgent, upstreamProxy string) (*azuretls.Session, error) {
	sessionKey := fmt.Sprintf("%s:%s", userAgent, upstreamProxy)

	m.mu.RLock()
	if session, exists := m.sessions[sessionKey]; exists {
		m.mu.RUnlock()
		return session, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check
	if session, exists := m.sessions[sessionKey]; exists {
		return session, nil
	}

	// Create new session
	session, err := m.createSession(userAgent, upstreamProxy)
	if err != nil {
		return nil, err
	}

	m.sessions[sessionKey] = session
	return session, nil
}

// createSession creates new azuretls session
func (m *Manager) createSession(userAgent, upstreamProxy string) (*azuretls.Session, error) {
	// Parse browser fingerprint
	browserFingerprint, err := GetBrowserFingerprint(userAgent)
	if err != nil {
		m.logger.Debug().Err(err).Msg("Failed to parse User-Agent, using default Chrome")
		// Use default Chrome fingerprint
		browserFingerprint = &BrowserFingerprint{
			Browser:          "Chrome",
			HTTP2Fingerprint: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,s,a,p",
			TLSProfile:       "133",
		}
	}

	// Log session creation with structured logging
	m.logger.Debug().
		Str("type", "session_creation").
		Str("user_agent", userAgent).
		Str("browser", browserFingerprint.Browser).
		Str("tls_profile", browserFingerprint.TLSProfile).
		Str("http2_fingerprint", browserFingerprint.HTTP2Fingerprint).
		Str("upstream_proxy", upstreamProxy).
		Msg("Creating new session")

	// Create azuretls session
	session := azuretls.NewSession()

	// Configure browser type and TLS fingerprint
	err = m.configureTLSFingerprint(session, browserFingerprint.Browser)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS fingerprint: %v", err)
	}

	m.logger.Debug().Str("browser", browserFingerprint.Browser).Msg("TLS ClientHello configured")

	// Configure HTTP/2 fingerprint
	err = session.ApplyHTTP2(browserFingerprint.HTTP2Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to configure HTTP/2 fingerprint: %v", err)
	}

	m.logger.Debug().Str("fingerprint", browserFingerprint.HTTP2Fingerprint).Msg("Applied HTTP/2 fingerprint successfully")

	// Set User-Agent
	session.UserAgent = userAgent

	// Configure proxy
	if upstreamProxy != "" {
		err = session.SetProxy(upstreamProxy)
		if err != nil {
			return nil, fmt.Errorf("failed to set proxy: %v", err)
		}
		m.logger.Debug().Str("proxy", upstreamProxy).Msg("Configured upstream proxy")
	}

	// Disable auto decompression
	session.DisableAutoDecompression = true

	// Disable license checking
	session.InsecureSkipVerify = true

	return session, nil
}

// configureTLSFingerprint configures TLS fingerprint
func (m *Manager) configureTLSFingerprint(session *azuretls.Session, browser string) error {
	switch browser {
	case "Chrome":
		session.Browser = azuretls.Chrome
		session.GetClientHelloSpec = azuretls.GetLastChromeVersion

	case "Firefox":
		session.Browser = azuretls.Firefox
		session.GetClientHelloSpec = azuretls.GetLastFirefoxVersion

	case "Safari":
		session.Browser = azuretls.Safari
		session.GetClientHelloSpec = azuretls.GetLastSafariVersion

	case "Edge":
		session.Browser = azuretls.Edge
		session.GetClientHelloSpec = azuretls.GetLastChromeVersion // Edge is based on Chromium

	case "iOS":
		session.Browser = azuretls.Ios
		session.GetClientHelloSpec = azuretls.GetLastIosVersion

	default:
		// Default to Chrome
		session.Browser = azuretls.Chrome
		session.GetClientHelloSpec = azuretls.GetLastChromeVersion
		m.logger.Debug().Str("browser", browser).Msg("Unknown browser, using default Chrome configuration")
	}

	return nil
}

// CloseAll closes all sessions
func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, session := range m.sessions {
		session.Close()
		delete(m.sessions, key)
	}

	m.logger.Info().Msg("Closed all sessions")
}

// GetSessionCount returns current session count
func (m *Manager) GetSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

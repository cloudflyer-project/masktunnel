package masktunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Server represents the MaskTunnel proxy server
type Server struct {
	config          *Config
	sessionManager  *Manager
	payloadInjector *PayloadInjector
	auth            *BasicAuth
	certManager     *CertManager
	httpServer      *http.Server
	listener        net.Listener
	actualAddr      string
	logger          zerolog.Logger
}

// NewServer creates a new proxy server instance
func NewServer(config *Config) *Server {
	// Use custom logger if provided, otherwise use global logger
	var logger zerolog.Logger
	if config.Logger != nil {
		logger = *config.Logger
	} else {
		logger = log.Logger
	}

	var certManager *CertManager
	var err error
	if config != nil && config.CertFile != "" && config.KeyFile != "" {
		certManager, err = NewCertManagerFromFiles(config.CertFile, config.KeyFile)
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to create certificate manager")
			return nil
		}
	} else {
		certManager, err = NewCertManager()
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to create certificate manager")
			return nil
		}
	}

	return &Server{
		config:          config,
		sessionManager:  NewManagerWithLogger(logger),
		payloadInjector: NewPayloadInjector(config.Payload),
		auth:            NewBasicAuth(config.Username, config.Password),
		certManager:     certManager,
		logger:          logger,
	}
}

// Start starts the proxy server
func (s *Server) Start() error {
	addr := net.JoinHostPort(s.config.Addr, s.config.Port)

	// Create listener first to get the actual bound address (important when port is 0)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = listener
	s.actualAddr = listener.Addr().String()

	s.httpServer = &http.Server{
		Handler: s,
		// Configure reasonable timeouts
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s.httpServer.Serve(listener)
}

// ActualAddr returns the actual listening address (host:port).
// This is useful when port 0 is specified to get the OS-assigned port.
func (s *Server) ActualAddr() string {
	return s.actualAddr
}

// Stop stops the proxy server
func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.sessionManager.CloseAll()
	return s.httpServer.Shutdown(ctx)
}

// ServeHTTP implements http.Handler interface
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Validate proxy authentication
	if !s.auth.Validate(r) {
		s.sendAuthRequired(w)
		return
	}

	// Handle internal control API (must be checked before CONNECT)
	if r.Method == "POST" && r.URL.Path == "/__masktunnel__/reset" {
		s.handleResetSessions(w, r)
		return
	}

	if r.Method == "POST" && r.URL.Path == "/__masktunnel__/proxy" {
		s.handleSetProxy(w, r)
		return
	}

	// Handle CONNECT method (HTTPS tunneling)
	if r.Method == "CONNECT" {
		s.handleConnect(w, r)
		return
	}

	// Handle WebSocket Upgrade requests for HTTP
	if s.isWebSocketUpgrade(r) {
		s.handleWebSocketUpgrade(w, r)
		return
	}

	// Handle regular HTTP requests
	s.handleHTTP(w, r)
}

// handleResetSessions handles the internal API to reset all TLS sessions
func (s *Server) handleResetSessions(w http.ResponseWriter, r *http.Request) {
	count := s.sessionManager.GetSessionCount()
	s.sessionManager.CloseAll()
	s.logger.Info().Int("closed_sessions", count).Msg("Reset all TLS sessions via API")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"success":true,"closed_sessions":%d}`, count)))
}

// handleSetProxy handles the internal API to set upstream proxy
func (s *Server) handleSetProxy(w http.ResponseWriter, r *http.Request) {
	// Read proxy URL from request body
	body := make([]byte, 1024)
	n, _ := r.Body.Read(body)
	proxyURL := strings.TrimSpace(string(body[:n]))

	// Update config
	oldProxy := s.config.UpstreamProxy
	s.config.UpstreamProxy = proxyURL

	// Close all existing sessions to force new connections with new proxy
	count := s.sessionManager.GetSessionCount()
	s.sessionManager.CloseAll()

	s.logger.Info().
		Str("old_proxy", oldProxy).
		Str("new_proxy", proxyURL).
		Int("closed_sessions", count).
		Msg("Updated upstream proxy via API")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"success":true,"proxy":"%s","closed_sessions":%d}`, proxyURL, count)))
}

// sendAuthRequired sends 407 Proxy Authentication Required response
func (s *Server) sendAuthRequired(w http.ResponseWriter) {
	resp := s.auth.GetAuthRequiredResponse()

	// Copy headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write([]byte("Proxy authentication required"))
}

// handleConnect handles CONNECT method with MITM capability
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Log simple CONNECT request
	s.logger.Debug().
		Str("type", "connect").
		Str("target", r.RequestURI).
		Msg("CONNECT tunnel established")

	// Send 200 Connection Established first
	w.WriteHeader(http.StatusOK)

	// Hijack the connection to get raw TCP access
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hijack connection")
		return
	}
	defer clientConn.Close()

	// All CONNECT requests go through MITM for protocol detection
	s.handleMITM(clientConn, r.RequestURI)
}

// handleHTTP handles regular HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.logger.Info().
		Str("type", "http_request").
		Str("method", r.Method).
		Str("url", r.RequestURI).
		Msg("Handling plain HTTP request")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	outReq, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	outReq.Header = make(http.Header)
	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeaders(outReq.Header)

	if s.config.UserAgent != "" {
		outReq.Header.Set("User-Agent", s.config.UserAgent)
	}

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		s.logger.Error().Err(err).Msg("HTTP upstream request failed")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")

	if !s.payloadInjector.ShouldInject(contentType) {
		removeHopByHopHeaders(resp.Header)
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		flusher, ok := w.(http.Flusher)
		if !ok {
			// Fallback for non-flushable writers, though rare for HTTP
			if _, err := io.Copy(w, resp.Body); err != nil {
				s.logger.Error().Err(err).Msg("Error streaming HTTP response (fallback)")
			}
			return
		}

		// Explicitly flush headers to the client immediately
		flusher.Flush()

		// Use a manual loop with flushing to ensure true streaming
		buf := make([]byte, 32*1024) // 32KB buffer, a common size
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					s.logger.Error().Err(writeErr).Msg("Error writing chunk to client")
					break
				}
				flusher.Flush() // Flush after each chunk is written
			}
			if err == io.EOF {
				break // End of stream
			}
			if err != nil {
				s.logger.Error().Err(err).Msg("Error reading from upstream response")
				break
			}
		}
		return
	}

	s.logger.Debug().Str("content_type", contentType).Msg("Payload injection required for HTTP request, buffering response")
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to read response body for injection")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	processedBody, _, err := injectWithReencode(s.payloadInjector, bodyBytes, contentType, contentEncoding)
	if err != nil {
		s.logger.Error().Err(err).Str("content_encoding", contentEncoding).Msg("Failed to re-encode body, sending original.")
		processedBody = bodyBytes
	} else {
		s.logger.Debug().Str("content_type", contentType).Msg("Payload injected into HTTP response")
	}

	removeHopByHopHeaders(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(processedBody)))

	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(processedBody); err != nil {
		s.logger.Error().Err(err).Msg("Error writing injected HTTP response")
	}
}

// copyHeaders copies all headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// removeHopByHopHeaders removes headers that are not meant to be forwarded.
func removeHopByHopHeaders(h http.Header) {
	// https://www.rfc-editor.org/rfc/rfc2616#section-13.5.1
	hopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// removeHopByHopHeadersExceptWebSocket removes hop-by-hop headers but preserves WebSocket-specific headers
func removeHopByHopHeadersExceptWebSocket(h http.Header) {
	// For WebSocket, we need to preserve Connection, Upgrade, and WebSocket-specific headers
	hopHeaders := []string{
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
	}
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request
func (s *Server) isWebSocketUpgrade(r *http.Request) bool {
	upgrade := r.Header.Get("Upgrade")
	connection := r.Header.Get("Connection")
	wsKey := r.Header.Get("Sec-WebSocket-Key")

	isUpgrade := strings.ToLower(upgrade) == "websocket"
	hasConnection := strings.Contains(strings.ToLower(connection), "upgrade")
	hasWSKey := wsKey != ""

	s.logger.Debug().
		Str("upgrade", upgrade).
		Str("connection", connection).
		Str("ws_key", wsKey).
		Bool("is_websocket", isUpgrade && hasConnection && hasWSKey).
		Msg("Checking WebSocket upgrade in MITM")

	return isUpgrade && hasConnection && hasWSKey
}

// handleWebSocketUpgrade handles HTTP WebSocket upgrade requests by proxying them
func (s *Server) handleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug().
		Str("type", "websocket_upgrade").
		Str("url", r.RequestURI).
		Msg("Handling HTTP WebSocket upgrade request")

	// Create upstream request
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	outReq, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Copy headers, preserving WebSocket-specific ones
	outReq.Header = make(http.Header)
	copyHeaders(outReq.Header, r.Header)
	removeHopByHopHeadersExceptWebSocket(outReq.Header)

	if s.config.UserAgent != "" {
		outReq.Header.Set("User-Agent", s.config.UserAgent)
	}

	// Make the upstream request
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		s.logger.Error().Err(err).Msg("WebSocket upstream request failed")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Check if upstream accepted the WebSocket upgrade
	if resp.StatusCode != http.StatusSwitchingProtocols {
		s.logger.Error().Int("status", resp.StatusCode).Msg("Upstream rejected WebSocket upgrade")
		defer resp.Body.Close()

		// Forward the rejection response
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	// Copy response headers for successful upgrade
	removeHopByHopHeadersExceptWebSocket(resp.Header)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(http.StatusSwitchingProtocols)

	// Get the hijacker to access raw connections
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hijack client connection")
		return
	}
	defer clientConn.Close()

	// Get the upstream connection
	upstreamConn, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		s.logger.Error().Msg("Upstream connection is not a ReadWriteCloser")
		return
	}
	defer upstreamConn.Close()

	s.logger.Debug().Str("url", r.RequestURI).Msg("HTTP WebSocket tunnel established")

	// Start bidirectional copying
	go func() {
		defer clientConn.Close()
		defer upstreamConn.Close()
		io.Copy(upstreamConn, clientConn)
	}()

	defer clientConn.Close()
	defer upstreamConn.Close()
	io.Copy(clientConn, upstreamConn)
}

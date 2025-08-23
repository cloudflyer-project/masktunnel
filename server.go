package masktunnel

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Noooste/azuretls-client"
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
}

// NewServer creates a new proxy server instance
func NewServer(config *Config) *Server {
	certManager, err := NewCertManager()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create certificate manager")
		return nil
	}

	return &Server{
		config:          config,
		sessionManager:  NewManager(),
		payloadInjector: NewPayloadInjector(config.Payload),
		auth:            NewBasicAuth(config.Username, config.Password),
		certManager:     certManager,
	}
}

// Start starts the proxy server
func (s *Server) Start() error {
	addr := s.config.Addr + ":" + s.config.Port

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: s,
		// Configure reasonable timeouts
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s.httpServer.ListenAndServe()
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

	// Handle CONNECT method (HTTPS tunneling)
	if r.Method == "CONNECT" {
		s.handleConnect(w, r)
		return
	}

	// Handle regular HTTP requests
	s.handleHTTP(w, r)
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
	// Get User-Agent for fingerprinting
	userAgent := r.Header.Get("User-Agent")
	if s.config.UserAgent != "" {
		userAgent = s.config.UserAgent
	}

	// Log simple CONNECT request
	log.Debug().
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
		log.Error().Err(err).Msg("Failed to hijack connection")
		return
	}
	defer clientConn.Close()

	// Start MITM handling
	s.handleMITM(clientConn, r.RequestURI, userAgent)
}

// handleHTTP handles regular HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Get or override User-Agent
	userAgent := r.Header.Get("User-Agent")

	logEvent := log.Debug().
		Str("type", "http_request").
		Str("method", r.Method).
		Str("url", r.RequestURI)

	if s.config.UserAgent != "" && userAgent != s.config.UserAgent {
		logEvent.Str("original_user_agent", userAgent)
		userAgent = s.config.UserAgent
		r.Header.Set("User-Agent", userAgent)
	} else if s.config.UserAgent != "" {
		userAgent = s.config.UserAgent
		r.Header.Set("User-Agent", userAgent)
	}

	logEvent.Str("user_agent", userAgent).Msg("HTTP request")

	if userAgent == "" {
		http.Error(w, "User-Agent header required", http.StatusBadRequest)
		return
	}

	// Parse target URL
	targetURL, err := url.Parse(r.RequestURI)
	if err != nil {
		http.Error(w, "Invalid request URI", http.StatusBadRequest)
		return
	}

	// Get azuretls session
	sess, err := s.sessionManager.GetSession(userAgent, s.config.UpstreamProxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Debug().Str("url", targetURL.String()).Msg("Using fingerprinted session")

	// Create azuretls request using OrderedHeaders
	azureReq := &azuretls.Request{
		Method: r.Method,
		Url:    targetURL.String(),
		Body:   r.Body,
	}

	// Convert headers to OrderedHeaders
	if len(r.Header) > 0 {
		azureReq.OrderedHeaders = azuretls.OrderedHeaders{}
		for name, values := range r.Header {
			for _, value := range values {
				azureReq.OrderedHeaders = append(azureReq.OrderedHeaders, []string{name, value})
			}
		}
	}

	// Send request using azuretls
	resp, err := sess.Do(azureReq)
	if err != nil {
		log.Error().Err(err).Msg("Request failed")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Process response body with payload injection
	body := resp.Body
	contentType := resp.Header.Get("Content-Type")

	if s.payloadInjector.ShouldInject(contentType) {
		body = s.payloadInjector.InjectIntoResponse(body, contentType)
		log.Info().Str("content_type", contentType).Msg("Payload injected")
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Update Content-Length if body was modified
	if len(body) != len(resp.Body) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}

	// Write response
	w.WriteHeader(resp.StatusCode)
	w.Write(body)

	log.Debug().
		Str("type", "http_response").
		Int("status", resp.StatusCode).
		Int("size", len(body)).
		Msg("HTTP response")
}

// GetStats returns server statistics
func (s *Server) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"active_sessions": s.sessionManager.GetSessionCount(),
		"payload_enabled": s.config.Payload != "",
		"auth_enabled":    s.auth.IsEnabled(),
		"upstream_proxy":  s.config.UpstreamProxy != "",
	}
}

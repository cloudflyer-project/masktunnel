package masktunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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

	// Fast path: for plain HTTP requests, stream via net/http to avoid buffering
	if strings.EqualFold(targetURL.Scheme, "http") {
		outReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		// Copy headers while dropping hop-by-hop headers
		hopHeaders := map[string]struct{}{
			"Proxy-Connection": {}, "Proxy-Authenticate": {}, "Proxy-Authorization": {},
			"Connection": {}, "Keep-Alive": {}, "TE": {}, "Trailer": {},
			"Transfer-Encoding": {}, "Upgrade": {},
		}
		outReq.Header = make(http.Header, len(r.Header))
		for k, vv := range r.Header {
			if _, hop := hopHeaders[http.CanonicalHeaderKey(k)]; hop {
				continue
			}
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
		// Ensure desired User-Agent is set
		outReq.Header.Set("User-Agent", userAgent)

		transport := &http.Transport{
			DisableCompression: true,
		}
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := client.Do(outReq)
		if err != nil {
			log.Error().Err(err).Msg("HTTP upstream request failed")
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers (drop hop-by-hop and content-length when streaming)
		for k, vv := range resp.Header {
			if _, hop := hopHeaders[http.CanonicalHeaderKey(k)]; hop {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		contentType := resp.Header.Get("Content-Type")
		if s.payloadInjector.ShouldInject(contentType) {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Error().Err(err).Msg("Failed to read HTTP response for injection")
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
				return
			}
			injected := s.payloadInjector.InjectIntoResponse(bodyBytes, contentType)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(injected)))
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(injected)
			log.Debug().Int("status", resp.StatusCode).Int("size", len(injected)).Msg("HTTP injected response")
			return
		}

		// If upstream provided Content-Length and we are not modifying the body,
		// set it to allow client to know exact length and keep-alive.
		if resp.ContentLength >= 0 {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
			w.WriteHeader(resp.StatusCode)
			if _, err := io.Copy(w, resp.Body); err != nil {
				log.Error().Err(err).Msg("Error streaming HTTP response")
			}
		} else {
			// Unknown length: chunked with flush
			w.WriteHeader(resp.StatusCode)
			buf := make([]byte, 32<<10)
			for {
				n, readErr := resp.Body.Read(buf)
				if n > 0 {
					if _, err := w.Write(buf[:n]); err != nil {
						log.Error().Err(err).Msg("Error writing HTTP streamed chunk")
						break
					}
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
				}
				if readErr == io.EOF {
					break
				}
				if readErr != nil {
					log.Error().Err(readErr).Msg("Error reading HTTP upstream stream")
					break
				}
			}
		}
		log.Debug().Int("status", resp.StatusCode).Msg("HTTP streamed response")
		return
	}

	// Fallback path: for any non-HTTP scheme here, stream via net/http as well
	// This keeps behavior consistent and avoids azuretls in server.go.
	outReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	// Copy headers with hop-by-hop filtering
	hopHeaders := map[string]struct{}{
		"Proxy-Connection": {}, "Proxy-Authenticate": {}, "Proxy-Authorization": {},
		"Connection": {}, "Keep-Alive": {}, "TE": {}, "Trailer": {},
		"Transfer-Encoding": {}, "Upgrade": {},
	}
	outReq.Header = make(http.Header, len(r.Header))
	for k, vv := range r.Header {
		if _, hop := hopHeaders[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Header.Set("User-Agent", userAgent)

	transport := &http.Transport{
		DisableCompression: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // allow local self-signed in tests
		},
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	resp2, err := client.Do(outReq)
	if err != nil {
		log.Error().Err(err).Msg("Upstream request failed")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp2.Body.Close()

	for k, vv := range resp2.Header {
		if _, hop := hopHeaders[http.CanonicalHeaderKey(k)]; hop || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	ct := resp2.Header.Get("Content-Type")
	if s.payloadInjector.ShouldInject(ct) {
		b, err := io.ReadAll(resp2.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response for injection")
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		inj := s.payloadInjector.InjectIntoResponse(b, ct)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(inj)))
		w.WriteHeader(resp2.StatusCode)
		_, _ = w.Write(inj)
		log.Debug().Int("status", resp2.StatusCode).Int("size", len(inj)).Msg("HTTP(S) injected response")
		return
	}

	w.WriteHeader(resp2.StatusCode)
	if _, err := io.Copy(w, resp2.Body); err != nil {
		log.Error().Err(err).Msg("Error streaming upstream response")
	}
	log.Debug().Int("status", resp2.StatusCode).Msg("HTTP(S) streamed response")
}

package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// TestServer holds test server instances
type TestServer struct {
	HTTPServer  *http.Server
	HTTPSServer *http.Server
	WSServer    *http.Server
	HTTPPort    string
	HTTPSPort   string
	WSPort      string
}

// NewTestServer creates test servers for HTTP, HTTPS, and WebSocket
func NewTestServer(httpPort, httpsPort, wsPort string) *TestServer {
	return &TestServer{
		HTTPPort:  httpPort,
		HTTPSPort: httpsPort,
		WSPort:    wsPort,
	}
}

// Start starts all test servers
func (ts *TestServer) Start() error {
	// HTTP server
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", ts.handleHTTP)
	httpMux.HandleFunc("/keepalive", ts.handleKeepAlive)
	httpMux.HandleFunc("/slow", ts.handleSlow)

	ts.HTTPServer = &http.Server{
		Addr:    ":" + ts.HTTPPort,
		Handler: httpMux,
	}

	// HTTPS server
	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", ts.handleHTTPS)

	cert, err := ts.generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	ts.HTTPSServer = &http.Server{
		Addr:    ":" + ts.HTTPSPort,
		Handler: httpsMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// WebSocket server
	wsMux := http.NewServeMux()
	wsMux.HandleFunc("/ws", ts.handleWebSocket)

	ts.WSServer = &http.Server{
		Addr:    ":" + ts.WSPort,
		Handler: wsMux,
	}

	// Start servers in background
	go func() {
		if err := ts.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("HTTP test server error")
		}
	}()

	go func() {
		if err := ts.HTTPSServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("HTTPS test server error")
		}
	}()

	go func() {
		if err := ts.WSServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("WebSocket test server error")
		}
	}()

	// Wait for servers to start
	time.Sleep(time.Second)
	log.Info().Str("http", ts.HTTPPort).Str("https", ts.HTTPSPort).Str("ws", ts.WSPort).Msg("Test servers started")
	return nil
}

// Stop stops all test servers
func (ts *TestServer) Stop() {
	if ts.HTTPServer != nil {
		ts.HTTPServer.Close()
	}
	if ts.HTTPSServer != nil {
		ts.HTTPSServer.Close()
	}
	if ts.WSServer != nil {
		ts.WSServer.Close()
	}
	log.Info().Msg("Test servers stopped")
}

// HTTP request handler
func (ts *TestServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"method":     r.Method,
		"url":        r.URL.String(),
		"headers":    r.Header,
		"user_agent": r.Header.Get("User-Agent"),
		"timestamp":  time.Now().Unix(),
		"protocol":   "http",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Type", "http")
	json.NewEncoder(w).Encode(response)
}

// HTTPS request handler
func (ts *TestServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"method":     r.Method,
		"url":        r.URL.String(),
		"headers":    r.Header,
		"user_agent": r.Header.Get("User-Agent"),
		"timestamp":  time.Now().Unix(),
		"protocol":   "https",
		"tls":        r.TLS != nil,
	}

	if r.TLS != nil {
		response["tls_version"] = r.TLS.Version
		response["cipher_suite"] = r.TLS.CipherSuite
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Type", "https")
	json.NewEncoder(w).Encode(response)
}

// Keep-alive request handler
func (ts *TestServer) handleKeepAlive(w http.ResponseWriter, r *http.Request) {
	requestNum := r.Header.Get("X-Request-Number")
	if requestNum == "" {
		requestNum = "1"
	}

	response := map[string]interface{}{
		"method":      r.Method,
		"url":         r.URL.String(),
		"request_num": requestNum,
		"connection":  r.Header.Get("Connection"),
		"timestamp":   time.Now().Unix(),
		"protocol":    "http",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Type", "keepalive")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Keep-Alive", "timeout=30")
	json.NewEncoder(w).Encode(response)
}

// Slow response handler (for long connection testing)
func (ts *TestServer) handleSlow(w http.ResponseWriter, r *http.Request) {
	delayStr := r.URL.Query().Get("delay")
	delay := 2 * time.Second
	if delayStr != "" {
		if d, err := time.ParseDuration(delayStr + "s"); err == nil {
			delay = d
		}
	}

	// Simulate slow response
	time.Sleep(delay)

	response := map[string]interface{}{
		"method":    r.Method,
		"url":       r.URL.String(),
		"delay":     delay.String(),
		"timestamp": time.Now().Unix(),
		"protocol":  "http",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Type", "slow")
	json.NewEncoder(w).Encode(response)
}

// WebSocket handler
func (ts *TestServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow connections from any origin for testing
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}
	defer conn.Close()

	log.Info().Str("remote_addr", r.RemoteAddr).Msg("WebSocket connection established")

	// Send welcome message
	welcomeMsg := map[string]interface{}{
		"type":       "welcome",
		"timestamp":  time.Now().Unix(),
		"user_agent": r.Header.Get("User-Agent"),
	}

	if err := conn.WriteJSON(welcomeMsg); err != nil {
		log.Error().Err(err).Msg("Failed to send welcome message")
		return
	}

	// Handle messages
	for {
		var msg map[string]interface{}
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Error().Err(err).Msg("WebSocket read error")
			}
			break
		}

		// Echo back the message
		response := map[string]interface{}{
			"type":      "echo",
			"received":  msg,
			"timestamp": time.Now().Unix(),
		}

		if err := conn.WriteJSON(response); err != nil {
			log.Error().Err(err).Msg("Failed to send echo message")
			break
		}

		// Check for close message
		if msgType, ok := msg["type"].(string); ok && msgType == "close" {
			log.Info().Msg("Received close message, terminating WebSocket connection")
			break
		}
	}

	log.Info().Msg("WebSocket connection closed")
}

// Generate self-signed certificate for HTTPS testing
func (ts *TestServer) generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"MaskTunnel Test"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return cert, nil
}

// UserAgents for testing different browser fingerprints with distinct versions
var UserAgents = map[string]string{
	"Chrome":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
	"Firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Safari":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Edge":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36 Edg/85.0.564.70",
}

// CreateProxyClient creates an HTTP client configured to use the proxy
func CreateProxyClient(proxyPort string, userAgent string) (*http.Client, error) {
	proxyURL := fmt.Sprintf("http://localhost:%s", proxyPort)
	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return client, nil
}

// CreateDirectClient creates a direct HTTP client (no proxy)
func CreateDirectClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// CreateTCPConnection creates a raw TCP connection for CONNECT testing
func CreateTCPConnection(proxyPort, target string) (net.Conn, error) {
	// Connect to proxy
	conn, err := net.Dial("tcp", "localhost:"+proxyPort)
	if err != nil {
		return nil, err
	}

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, err
	}

	// Read CONNECT response
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		conn.Close()
		return nil, err
	}

	response := string(buffer[:n])
	if !containsIgnoreCase(response, "200") {
		conn.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", response)
	}

	return conn, nil
}

// containsIgnoreCase checks if string contains substring (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] &&
				s[i+j] != substr[j]+32 &&
				s[i+j] != substr[j]-32 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

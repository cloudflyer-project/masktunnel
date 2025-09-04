package test

import (
	"bytes"
	"compress/gzip"
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
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// TestServer holds test server instances
type TestServer struct {
	HTTPServer  *http.Server
	HTTPSServer *http.Server
	HTTPPort    string
	HTTPSPort   string
}

// NewTestServer creates test servers for HTTP, HTTPS, and WebSocket
func NewTestServer(httpPort, httpsPort string) *TestServer {
	return &TestServer{
		HTTPPort:  httpPort,
		HTTPSPort: httpsPort,
	}
}

// Start starts all test servers
func (ts *TestServer) Start() error {
	// HTTP server
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", ts.handleHTTP)
	httpMux.HandleFunc("/redirect/302", ts.handleRedirect302)
	httpMux.HandleFunc("/redirect/target", ts.handleRedirectTarget)
	httpMux.HandleFunc("/stream", ts.handleStreamChunked)         // backward-compatible chunked
	httpMux.HandleFunc("/stream/chunked", ts.handleStreamChunked) // explicit chunked
	httpMux.HandleFunc("/html", ts.handleHTML)
	httpMux.HandleFunc("/gzip", ts.handleGzip)
	httpMux.HandleFunc("/stream/fixed", ts.handleStreamFixed)
	httpMux.HandleFunc("/stream/close", ts.handleStreamClose)

	ts.HTTPServer = &http.Server{
		Addr:    ":" + ts.HTTPPort,
		Handler: httpMux,
	}

	// HTTPS server
	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", ts.handleHTTPS)
	httpsMux.HandleFunc("/redirect/302", ts.handleRedirect302)
	httpsMux.HandleFunc("/redirect/target", ts.handleRedirectTarget)
	httpsMux.HandleFunc("/stream", ts.handleStreamChunked)         // backward-compatible chunked
	httpsMux.HandleFunc("/stream/chunked", ts.handleStreamChunked) // explicit chunked
	httpsMux.HandleFunc("/html", ts.handleHTML)
	httpsMux.HandleFunc("/gzip", ts.handleGzip)
	httpsMux.HandleFunc("/stream/fixed", ts.handleStreamFixed)
	httpsMux.HandleFunc("/stream/close", ts.handleStreamClose)

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

	// Wait for servers to start
	time.Sleep(time.Second)
	log.Info().Str("http", ts.HTTPPort).Str("https", ts.HTTPSPort).Msg("Test servers started")
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

// handleRedirect302 handles 302 redirect requests
func (ts *TestServer) handleRedirect302(w http.ResponseWriter, r *http.Request) {
	// Determine target URL based on protocol
	var targetURL string
	if r.TLS != nil {
		// HTTPS request
		targetURL = fmt.Sprintf("https://localhost:%s/redirect/target", ts.HTTPSPort)
	} else {
		// HTTP request
		targetURL = fmt.Sprintf("http://localhost:%s/redirect/target", ts.HTTPPort)
	}

	// Log the redirect request
	log.Info().
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Str("target", targetURL).
		Bool("tls", r.TLS != nil).
		Msg("302 redirect request received")

	// Send 302 redirect response
	w.Header().Set("Location", targetURL)
	w.Header().Set("X-Test-Type", "redirect-302")
	w.WriteHeader(http.StatusFound) // 302

	// Include response body for debugging
	response := map[string]interface{}{
		"status":    302,
		"method":    r.Method,
		"url":       r.URL.String(),
		"target":    targetURL,
		"timestamp": time.Now().Unix(),
		"protocol":  "http",
		"message":   "This is a 302 redirect response",
	}

	if r.TLS != nil {
		response["protocol"] = "https"
		response["tls"] = true
	}

	json.NewEncoder(w).Encode(response)
}

// handleRedirectTarget handles the target of redirect requests
func (ts *TestServer) handleRedirectTarget(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"method":     r.Method,
		"url":        r.URL.String(),
		"headers":    r.Header,
		"user_agent": r.Header.Get("User-Agent"),
		"timestamp":  time.Now().Unix(),
		"protocol":   "http",
		"message":    "This is the redirect target endpoint",
		"is_target":  true,
	}

	if r.TLS != nil {
		response["protocol"] = "https"
		response["tls"] = true
		response["tls_version"] = r.TLS.Version
		response["cipher_suite"] = r.TLS.CipherSuite
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Test-Type", "redirect-target")
	json.NewEncoder(w).Encode(response)
}

// handleHTML serves a simple HTML page for payload injection tests
func (ts *TestServer) handleHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>MaskTunnel Test</title></head><body><h1>HTML Test Page</h1><p>Injection point check.</p></body></html>`))
}

// handleGzip returns a gzipped response.
func (ts *TestServer) handleGzip(w http.ResponseWriter, r *http.Request) {
	originalContent := "this content was gzipped"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(originalContent)); err != nil {
		http.Error(w, "Failed to gzip content", http.StatusInternalServerError)
		return
	}
	gz.Close() // Important to close the writer to flush all data

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "text/plain")
	w.Write(buf.Bytes())
}

// handleStreamFixed returns a response with explicit Content-Length
func (ts *TestServer) handleStreamFixed(w http.ResponseWriter, r *http.Request) {
	numBytesStr := r.URL.Query().Get("numbytes")
	numBytes, _ := strconv.Atoi(numBytesStr)
	if numBytes <= 0 {
		numBytes = 5
	}
	payload := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		payload[i] = 'F'
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// handleStreamClose writes some data and then closes the connection (no chunked, no content-length)
func (ts *TestServer) handleStreamClose(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		log.Error().Err(err).Msg("Hijack failed")
		return
	}
	defer conn.Close()

	numBytesStr := r.URL.Query().Get("numbytes")
	numBytes, _ := strconv.Atoi(numBytesStr)
	if numBytes <= 0 {
		numBytes = 5
	}
	payload := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		payload[i] = 'C'
	}

	// Raw HTTP/1.1 response with Connection: close, no Content-Length
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n")
	if _, err := buf.WriteString(resp); err != nil {
		return
	}
	if _, err := buf.Write(payload); err != nil {
		return
	}
	_ = buf.Flush()
	// Close immediately; client should treat close as end-of-message
}

// handleStreamChunked simulates a slow streaming response
func (ts *TestServer) handleStreamChunked(w http.ResponseWriter, r *http.Request) {
	numBytesStr := r.URL.Query().Get("numbytes")
	durationStr := r.URL.Query().Get("duration")
	delayStr := r.URL.Query().Get("delay")

	numBytes, _ := strconv.Atoi(numBytesStr)
	if numBytes <= 0 {
		numBytes = 5
	}

	durationSec, _ := strconv.Atoi(durationStr)
	if durationSec <= 0 {
		durationSec = 3
	}

	delaySec, _ := strconv.Atoi(delayStr)
	if delaySec > 0 {
		time.Sleep(time.Duration(delaySec) * time.Second)
	}

	// Calculate the delay between each byte
	var sleepPerByte time.Duration
	if numBytes > 1 {
		sleepPerByte = time.Duration(durationSec) * time.Second / time.Duration(numBytes-1)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	for i := 0; i < numBytes; i++ {
		if _, err := w.Write([]byte("s")); err != nil {
			log.Error().Err(err).Msg("Error writing stream data")
			return
		}
		flusher.Flush()
		if i < numBytes-1 {
			time.Sleep(sleepPerByte)
		}
	}
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
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Do not follow 3xx automatically; let tests inspect 302 and Location
			return http.ErrUseLastResponse
		},
	}

	return client, nil
}

// CreateDirectClient creates a direct HTTP client (no proxy) with HTTP/2 support
func CreateDirectClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true, // Enable HTTP/2 support
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
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

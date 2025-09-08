package masktunnel

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Noooste/azuretls-client"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// handleMITM performs man-in-the-middle handling of HTTPS connections
func (s *Server) handleMITM(clientConn net.Conn, target string) {
	// Parse hostname from target (remove port if present) for certificate generation
	hostname := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		hostname = target[:idx]
	}

	// Log MITM setup with structured logging
	log.Debug().
		Str("type", "mitm_setup").
		Str("target", target).
		Str("hostname", hostname).
		Msg("Starting MITM")

	// Try to detect if this is HTTP by peeking at the first bytes
	bufferedConn := &BufferedMITMConn{
		Conn:   clientConn,
		Reader: bufio.NewReader(clientConn),
	}

	// Peek at the first few bytes to determine protocol
	firstBytes, err := bufferedConn.Reader.Peek(10)
	if err != nil {
		log.Error().Err(err).Msg("Failed to peek at connection for protocol detection")
		return
	}

	// Check if it starts with HTTP methods (indicating HTTP, not TLS)
	firstStr := string(firstBytes)
	isHTTPRequest := strings.HasPrefix(firstStr, "GET ") ||
		strings.HasPrefix(firstStr, "POST ") ||
		strings.HasPrefix(firstStr, "PUT ") ||
		strings.HasPrefix(firstStr, "HEAD ") ||
		strings.HasPrefix(firstStr, "OPTIONS ")

	if isHTTPRequest {
		log.Debug().Str("target", target).Msg("Detected HTTP request, handling as plain HTTP")
		s.handleHTTPConnection(bufferedConn, target)
		return
	}

	// This is likely HTTPS, proceed with TLS
	log.Debug().Str("target", target).Msg("Detected TLS, proceeding with HTTPS MITM")

	// Load or generate certificate for the target hostname
	cert, err := s.getCertificateForHost(hostname)
	if err != nil {
		log.Error().Err(err).Str("hostname", hostname).Msg("Failed to get certificate")
		return
	}

	// Create TLS config for client connection
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   hostname,
	}

	// Wrap client connection with TLS
	clientTLSConn := tls.Server(bufferedConn, tlsConfig)
	defer clientTLSConn.Close()

	// Perform TLS handshake with client
	if err := clientTLSConn.Handshake(); err != nil {
		log.Error().Err(err).Str("hostname", hostname).Msg("Client TLS handshake failed")
		return
	}

	log.Debug().Str("hostname", hostname).Msg("Client TLS handshake completed")

	// Handle HTTP requests over the TLS connection
	s.handleTLSConnection(clientTLSConn, target)
}

// handleTLSConnection handles HTTP requests over established TLS connection
func (s *Server) handleTLSConnection(clientTLSConn *tls.Conn, target string) {
	log.Debug().Str("target", target).Msg("Starting HTTP handler for TLS connection")

	reader := bufio.NewReader(clientTLSConn)
	var req fasthttp.Request

	for {
		if err := req.Read(reader); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") && err != fasthttp.ErrTimeout {
				log.Error().Err(err).Msg("Failed to read HTTP request")
			}
			break
		}

		ua := string(req.Header.Peek("User-Agent"))
		sess, err := s.sessionManager.GetSession(ua, s.config.UpstreamProxy)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get azuretls session")
			break
		}

		resp, streamed, err := s.processMITMRequest(&req, sess, target, clientTLSConn)
		if err != nil {
			log.Error().Err(err).Msg("Failed to process MITM request")
			break
		}

		if !streamed {
			if err := resp.Write(clientTLSConn); err != nil {
				log.Error().Err(err).Msg("Failed to write response")
				break
			}
		}

		if req.Header.ConnectionClose() {
			break
		}

		req.Reset()
	}

	log.Debug().Str("target", target).Msg("Closed TLS connection")
}

// processMITMRequest handles individual HTTP requests in MITM mode
func (s *Server) processMITMRequest(r *fasthttp.Request, sess *azuretls.Session, target string, clientConn net.Conn) (*http.Response, bool, error) {
	// Check if this is a WebSocket upgrade request
	if s.isWebSocketUpgradeRequest(r) {
		log.Debug().Str("target", target).Msg("Detected WebSocket upgrade request in MITM")
		return s.handleWebSocketUpgradeInMITM(r, sess, target, clientConn)
	}

	scheme := "https"
	fullURL := scheme + "://" + target + string(r.URI().Path())
	if query := r.URI().QueryString(); len(query) > 0 {
		fullURL += "?" + string(query)
	}

	method := string(r.Header.Method())
	logEvent := log.Info().
		Str("method", method).
		Str("url", fullURL).
		Str("target", target)

	if userAgent := string(r.Header.Peek("User-Agent")); userAgent != "" {
		if browserFp, err := GetBrowserFingerprint(userAgent); err == nil {
			logEvent = logEvent.
				Str("browser", browserFp.Browser).
				Str("tls_profile", browserFp.TLSProfile)
		}
	}

	logEvent.Msg("MITM HTTP request")

	azureReq := &azuretls.Request{
		Method:           method,
		Url:              fullURL,
		DisableRedirects: true,
		IgnoreBody:       true,
	}

	if headerCount := r.Header.Len(); headerCount > 0 {
		azureReq.OrderedHeaders = make(azuretls.OrderedHeaders, 0, headerCount)
		r.Header.AllInOrder()(func(key, value []byte) bool {
			azureReq.OrderedHeaders = append(azureReq.OrderedHeaders, []string{string(key), string(value)})
			return true
		})
	}

	if r.Header.ContentLength() == 0 {
		azureReq.Body = nil
	} else {
		azureReq.Body = bytes.NewReader(r.Body())
	}

	resp, err := sess.Do(azureReq)
	if err != nil {
		log.Error().Err(err).Msg("MITM request failed")
		return nil, false, err
	}

	contentType := resp.Header.Get("Content-Type")
	bodyStream := resp.RawBody

	if !s.payloadInjector.ShouldInject(contentType) {
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")

		var headerBuilder strings.Builder
		headerBuilder.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status))

		contentLength := resp.Header.Get("Content-Length")
		useChunked := contentLength == ""
		if useChunked {
			resp.Header.Set("Transfer-Encoding", "chunked")
			resp.Header.Del("Content-Length")
		}

		resp.Header.Write(&headerBuilder)
		headerBuilder.WriteString("\r\n")

		if _, err := io.WriteString(clientConn, headerBuilder.String()); err != nil {
			_ = bodyStream.Close()
			return nil, false, err
		}

		writer := NewChunkedWriter(clientConn, useChunked)
		if _, err := io.Copy(writer, bodyStream); err != nil {
			_ = bodyStream.Close()
			return nil, false, err
		}
		writer.Close()

		_ = bodyStream.Close()

		log.Debug().Str("type", "mitm_response").Int("status", resp.StatusCode).Msg("Directly streamed MITM response")
		return nil, true, nil
	}

	defer bodyStream.Close()
	bodyBytes, err := io.ReadAll(bodyStream)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response body for injection")
		return nil, false, err
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	processedBody, _, err := injectWithReencode(s.payloadInjector, bodyBytes, contentType, contentEncoding)
	if err != nil {
		log.Error().Err(err).Str("content_encoding", contentEncoding).Msg("Failed to re-encode body, sending original.")
		processedBody = bodyBytes
	} else {
		log.Debug().Str("content_type", contentType).Msg("Payload injected and body re-encoded")
	}

	httpReq, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create dummy http.Request for response context")
		return nil, false, err
	}

	httpResp := &http.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        fromFhttpHeader(resp.Header),
		Body:          io.NopCloser(bytes.NewReader(processedBody)),
		ContentLength: int64(len(processedBody)),
		Request:       httpReq,
	}
	httpResp.Header.Set("Content-Length", fmt.Sprintf("%d", len(processedBody)))
	httpResp.Header.Del("Transfer-Encoding")

	log.Debug().
		Str("type", "mitm_response").
		Int("status", resp.StatusCode).
		Int("size", len(processedBody)).
		Msg("MITM HTTP response with injected payload")

	return httpResp, false, nil
}

// fromFhttpHeader converts an fhttp.Header to a standard http.Header.
func fromFhttpHeader(fhttpHeader map[string][]string) http.Header {
	httpHeader := make(http.Header)
	for k, vv := range fhttpHeader {
		for _, v := range vv {
			httpHeader.Add(k, v)
		}
	}
	return httpHeader
}

// getCertificateForHost returns a certificate for the given host
func (s *Server) getCertificateForHost(host string) (tls.Certificate, error) {
	cert, err := s.certManager.GetCertificate(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	return *cert, nil
}

// ChunkedWriter is a helper to wrap a net.Conn to write in chunked encoding format.
type ChunkedWriter struct {
	conn       net.Conn
	useChunked bool
}

// NewChunkedWriter creates a new ChunkedWriter.
func NewChunkedWriter(conn net.Conn, useChunked bool) *ChunkedWriter {
	return &ChunkedWriter{conn: conn, useChunked: useChunked}
}

// Write implements io.Writer. It writes data in chunked format if useChunked is true.
func (cw *ChunkedWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	if cw.useChunked {
		// Write chunk size, then chunk data, then CRLF
		if _, err := fmt.Fprintf(cw.conn, "%x\r\n", len(p)); err != nil {
			return 0, err
		}
		if _, err := cw.conn.Write(p); err != nil {
			return 0, err
		}
		if _, err := io.WriteString(cw.conn, "\r\n"); err != nil {
			return 0, err
		}
	} else {
		// Not chunked, write data directly
		if _, err := cw.conn.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close finalizes the stream. For chunked encoding, it writes the final zero-length chunk.
// This is implicitly called by io.Copy when the source reader returns EOF.
func (cw *ChunkedWriter) Close() error {
	if cw.useChunked {
		log.Debug().Msg("Writing final zero-length chunk to close stream.")
		_, err := io.WriteString(cw.conn, "0\r\n\r\n")
		return err
	}
	return nil
}

// isWebSocketUpgradeRequest checks if the fasthttp request is a WebSocket upgrade request
func (s *Server) isWebSocketUpgradeRequest(r *fasthttp.Request) bool {
	upgrade := string(r.Header.Peek("Upgrade"))
	connection := string(r.Header.Peek("Connection"))
	wsKey := string(r.Header.Peek("Sec-WebSocket-Key"))

	isUpgrade := strings.ToLower(upgrade) == "websocket"
	hasConnection := strings.Contains(strings.ToLower(connection), "upgrade")
	hasWSKey := wsKey != ""

	log.Debug().
		Str("upgrade", upgrade).
		Str("connection", connection).
		Str("ws_key", wsKey).
		Bool("is_websocket", isUpgrade && hasConnection && hasWSKey).
		Msg("Checking WebSocket upgrade in MITM")

	return isUpgrade && hasConnection && hasWSKey
}

// handleWebSocketUpgradeInMITM handles WebSocket upgrade requests in MITM mode
func (s *Server) handleWebSocketUpgradeInMITM(r *fasthttp.Request, sess *azuretls.Session, target string, clientConn net.Conn) (*http.Response, bool, error) {
	// For WebSocket, we need to use HTTP/1.1 and establish a direct tunnel
	scheme := "wss"
	fullURL := scheme + "://" + target + string(r.URI().Path())
	if query := r.URI().QueryString(); len(query) > 0 {
		fullURL += "?" + string(query)
	}

	log.Debug().Str("url", fullURL).Msg("Handling WebSocket upgrade in MITM")

	// Use azuretls WebSocket functionality
	ws, err := sess.NewWebsocket(fullURL, 1024, 1024)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create WebSocket connection")
		// Return error response
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Status:     "502 Bad Gateway",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		return resp, false, nil
	}

	// Send successful upgrade response to client
	upgradeResponse := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + generateWebSocketAccept(string(r.Header.Peek("Sec-WebSocket-Key"))) + "\r\n\r\n"

	if _, err := clientConn.Write([]byte(upgradeResponse)); err != nil {
		log.Error().Err(err).Msg("Failed to write WebSocket upgrade response")
		ws.Close()
		return nil, true, err
	}

	log.Debug().Str("url", fullURL).Msg("WebSocket tunnel established in MITM")

	// Get the underlying TCP connection from azuretls WebSocket
	wsConn := ws.UnderlyingConn()

	// Start bidirectional copying between client and the underlying WebSocket TCP connection
	go func() {
		defer wsConn.Close()
		defer clientConn.Close()
		// Copy from client to WebSocket TCP connection (WebSocket frames as-is)
		io.Copy(wsConn, clientConn)
	}()

	// Copy from WebSocket TCP connection to client (WebSocket frames as-is)
	defer wsConn.Close()
	defer clientConn.Close()
	io.Copy(clientConn, wsConn)

	return nil, true, nil
}

// generateWebSocketAccept generates the Sec-WebSocket-Accept header value
func generateWebSocketAccept(key string) string {
	const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// BufferedMITMConn wraps a connection with a buffered reader for protocol detection
type BufferedMITMConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (bc *BufferedMITMConn) Read(p []byte) (int, error) {
	return bc.Reader.Read(p)
}

// handleHTTPConnection handles plain HTTP requests (including HTTP WebSocket)
func (s *Server) handleHTTPConnection(clientConn *BufferedMITMConn, target string) {
	log.Debug().Str("target", target).Msg("Starting HTTP handler for plain connection")

	reader := clientConn.Reader
	var req fasthttp.Request

	for {
		if err := req.Read(reader); err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") && err != fasthttp.ErrTimeout {
				log.Error().Err(err).Msg("Failed to read HTTP request")
			}
			break
		}

		// Check if this is a WebSocket upgrade request
		if s.isWebSocketUpgradeRequest(&req) {
			log.Debug().Str("target", target).Msg("Detected HTTP WebSocket upgrade request")
			s.handleHTTPWebSocketUpgrade(&req, clientConn, target)
			return
		}

		// Handle regular HTTP request through transparent proxy
		log.Debug().Str("method", string(req.Header.Method())).Str("path", string(req.URI().Path())).Msg("Handling HTTP request")
		s.handleHTTPRequest(&req, clientConn, target)

		if req.Header.ConnectionClose() {
			break
		}

		req.Reset()
	}

	log.Debug().Str("target", target).Msg("Closed HTTP connection")
}

// handleHTTPWebSocketUpgrade handles WebSocket upgrade for plain HTTP
func (s *Server) handleHTTPWebSocketUpgrade(req *fasthttp.Request, clientConn *BufferedMITMConn, target string) {
	// Connect to upstream server
	upstreamConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Error().Err(err).Str("target", target).Msg("Failed to connect to upstream for HTTP WebSocket")
		return
	}
	defer upstreamConn.Close()

	// Log the request we're about to send
	log.Debug().
		Str("method", string(req.Header.Method())).
		Str("path", string(req.URI().Path())).
		Str("host", string(req.Host())).
		Str("upgrade", string(req.Header.Peek("Upgrade"))).
		Str("connection", string(req.Header.Peek("Connection"))).
		Str("ws_version", string(req.Header.Peek("Sec-WebSocket-Version"))).
		Str("ws_key", string(req.Header.Peek("Sec-WebSocket-Key"))).
		Msg("Sending WebSocket upgrade request to upstream")

	// Manually build and send the HTTP request to avoid fasthttp/fhttp compatibility issues
	upstreamWriter := bufio.NewWriter(upstreamConn)

	// Build the HTTP request manually
	requestLine := fmt.Sprintf("GET %s HTTP/1.1\r\n", string(req.URI().Path()))
	_, err = upstreamWriter.WriteString(requestLine)
	if err != nil {
		log.Error().Err(err).Msg("Failed to write request line")
		return
	}

	// Write essential headers
	headers := map[string]string{
		"Host":                  string(req.Host()),
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Key":     string(req.Header.Peek("Sec-WebSocket-Key")),
		"Sec-WebSocket-Version": "13",
		"User-Agent":            string(req.Header.Peek("User-Agent")),
	}

	for key, value := range headers {
		if value != "" {
			headerLine := fmt.Sprintf("%s: %s\r\n", key, value)
			_, err = upstreamWriter.WriteString(headerLine)
			if err != nil {
				log.Error().Err(err).Str("header", key).Msg("Failed to write header")
				return
			}
		}
	}

	// End headers
	_, err = upstreamWriter.WriteString("\r\n")
	if err != nil {
		log.Error().Err(err).Msg("Failed to write header terminator")
		return
	}

	if err := upstreamWriter.Flush(); err != nil {
		log.Error().Err(err).Msg("Failed to flush WebSocket upgrade request")
		return
	}

	log.Debug().Msg("WebSocket upgrade request sent, waiting for response")

	// Read and forward the WebSocket upgrade response
	upstreamReader := bufio.NewReader(upstreamConn)
	var resp fasthttp.Response
	if err := resp.Read(upstreamReader); err != nil {
		log.Error().Err(err).Msg("Failed to read WebSocket upgrade response")

		// Try to read raw response for debugging
		upstreamConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		rawResp := make([]byte, 1024)
		if n, readErr := upstreamConn.Read(rawResp); readErr == nil && n > 0 {
			log.Debug().Str("raw_response", string(rawResp[:n])).Msg("Raw response from upstream")
		}
		return
	}

	// Write the response back to client
	clientWriter := bufio.NewWriter(clientConn)
	if err := resp.Write(clientWriter); err != nil {
		log.Error().Err(err).Msg("Failed to write WebSocket upgrade response to client")
		return
	}
	if err := clientWriter.Flush(); err != nil {
		log.Error().Err(err).Msg("Failed to flush WebSocket upgrade response")
		return
	}

	log.Debug().Str("target", target).Int("status", resp.StatusCode()).Msg("WebSocket upgrade response forwarded")

	// Only proceed with tunnel if upgrade was successful
	if resp.StatusCode() != 101 {
		log.Error().Int("status", resp.StatusCode()).Msg("WebSocket upgrade failed")
		return
	}

	log.Debug().Str("target", target).Msg("HTTP WebSocket tunnel established")

	// Start bidirectional copying for WebSocket frames
	go func() {
		defer upstreamConn.Close()
		// Copy remaining client data to upstream
		io.Copy(upstreamConn, clientConn.Reader)
	}()

	// Copy upstream data to client
	defer upstreamConn.Close()
	io.Copy(clientConn, upstreamReader)
}

// handleHTTPRequest handles regular HTTP requests
func (s *Server) handleHTTPRequest(req *fasthttp.Request, clientConn *BufferedMITMConn, target string) {
	// For now, just establish a plain tunnel for regular HTTP requests
	// In a full implementation, you'd want to proxy the HTTP request properly
	upstreamConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Error().Err(err).Str("target", target).Msg("Failed to connect to upstream for HTTP")
		return
	}
	defer upstreamConn.Close()

	// Forward the request
	upstreamWriter := bufio.NewWriter(upstreamConn)
	if err := req.Write(upstreamWriter); err != nil {
		log.Error().Err(err).Msg("Failed to write HTTP request to upstream")
		return
	}
	if err := upstreamWriter.Flush(); err != nil {
		log.Error().Err(err).Msg("Failed to flush HTTP request")
		return
	}

	// Start bidirectional copying
	go func() {
		defer clientConn.Close()
		defer upstreamConn.Close()
		io.Copy(upstreamConn, clientConn.Reader)
	}()

	defer clientConn.Close()
	defer upstreamConn.Close()
	io.Copy(clientConn, upstreamConn)
}

// We need to implement io.Closer for the writer passed to io.Copy to be closed correctly.
// Since io.Copy checks for io.WriteCloser to call Close, we add the Close method.
var _ io.WriteCloser = (*ChunkedWriter)(nil)

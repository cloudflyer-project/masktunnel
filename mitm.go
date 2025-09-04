package masktunnel

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/Noooste/azuretls-client"
	"github.com/rs/zerolog/log"
)

// handleMITM performs man-in-the-middle handling of HTTPS connections
func (s *Server) handleMITM(clientConn net.Conn, target, userAgent string) {
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
	clientTLSConn := tls.Server(clientConn, tlsConfig)
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

	// Create HTTP request reader once outside the loop to maintain buffer state
	reader := bufio.NewReader(clientTLSConn)

	// Read and process HTTP requests directly
	for {
		// Use the same reader to maintain buffer state across requests
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Error().Err(err).Msg("Failed to read HTTP request")
			}
			break
		}

		// Select/obtain session per inner request based on its User-Agent
		ua := req.Header.Get("User-Agent")
		sess, err := s.sessionManager.GetSession(ua, s.config.UpstreamProxy)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get azuretls session")
			break
		}

		// Process the request - azuretls will handle TLS connection with fingerprinting
		resp, streamed, err := s.processMITMRequest(req, sess, target, clientTLSConn)
		if err != nil {
			log.Error().Err(err).Msg("Failed to process MITM request")
			break
		}

		// In direct streaming mode, response has already been written
		if !streamed {
			// Write response back to client
			if err := resp.Write(clientTLSConn); err != nil {
				log.Error().Err(err).Msg("Failed to write response")
				break
			}
		}

		// Close connection for HTTP/1.0 or if Connection: close
		if req.ProtoMajor < 2 && (req.Close || req.Header.Get("Connection") == "close") {
			break
		}
	}

	log.Debug().Str("target", target).Msg("Closed TLS connection")
}

// processMITMRequest handles individual HTTP requests in MITM mode
func (s *Server) processMITMRequest(r *http.Request, sess *azuretls.Session, target string, clientConn net.Conn) (*http.Response, bool, error) {
	// Construct full URL for the request
	scheme := "https"
	if r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}

	fullURL := scheme + "://" + target + r.URL.Path
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}

	// Log MITM HTTP request with structured logging including browser info
	logEvent := log.Info().
		Str("method", r.Method).
		Str("url", fullURL).
		Str("target", target)

	// Add browser fingerprint info if available
	if userAgent := r.Header.Get("User-Agent"); userAgent != "" {
		if browserFp, err := GetBrowserFingerprint(userAgent); err == nil {
			logEvent = logEvent.
				Str("browser", browserFp.Browser).
				Str("tls_profile", browserFp.TLSProfile)
		}
	}

	logEvent.Msg("MITM HTTP request")

	// Create azuretls request
	azureReq := &azuretls.Request{
		Method:           r.Method,
		Url:              fullURL,
		Body:             r.Body,
		DisableRedirects: true,
		IgnoreBody:       true, // Enable response body streaming
	}

	// Convert client headers to OrderedHeaders
	if len(r.Header) > 0 {
		azureReq.OrderedHeaders = make(azuretls.OrderedHeaders, 0, len(r.Header))
		for name, values := range r.Header {
			for _, value := range values {
				azureReq.OrderedHeaders = append(azureReq.OrderedHeaders, []string{name, value})
			}
		}
	}

	// Crucial fix for HTTP/2 fingerprinting: ensure nil body for requests without content.
	if r.ContentLength == 0 {
		azureReq.Body = nil
	} else {
		azureReq.Body = r.Body
	}

	// Send request using azuretls with fingerprinting
	resp, err := sess.Do(azureReq)
	if err != nil {
		log.Error().Err(err).Msg("MITM request failed")
		return nil, false, err
	}

	// Decide whether to inject payload based on Content-Type
	contentType := resp.Header.Get("Content-Type")
	bodyStream := resp.RawBody

	// --- PATH 1: Stream-through (No Injection) ---
	if !s.payloadInjector.ShouldInject(contentType) {
		// The upstream client (azuretls) decodes the body automatically.
		// We must remove compression-related headers before forwarding.
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")

		// Write the status line and headers as received from upstream
		var headerBuilder strings.Builder
		headerBuilder.WriteString(fmt.Sprintf("HTTP/1.1 %s\r\n", resp.Status))

		// The upstream client (azuretls) decodes chunked encoding automatically and removes the
		// Transfer-Encoding header. We must re-chunk the response if Content-Length is missing
		// to signal the end of the stream to the downstream client.
		contentLength := resp.Header.Get("Content-Length")
		useChunked := contentLength == ""
		if useChunked {
			resp.Header.Set("Transfer-Encoding", "chunked")
			// We are re-chunking, so Content-Length from upstream (if any) is no longer valid.
			resp.Header.Del("Content-Length")
		}

		resp.Header.Write(&headerBuilder)
		headerBuilder.WriteString("\r\n")

		if _, err := io.WriteString(clientConn, headerBuilder.String()); err != nil {
			_ = bodyStream.Close()
			return nil, false, err
		}

		// Use a custom writer that re-chunks the data if necessary.
		writer := NewChunkedWriter(clientConn, useChunked)
		if _, err := io.Copy(writer, bodyStream); err != nil {
			_ = bodyStream.Close()
			return nil, false, err
		}
		// Finalize the stream (writes the 0-length chunk if needed)
		writer.Close()

		_ = bodyStream.Close()

		log.Debug().Str("type", "mitm_response").Int("status", resp.StatusCode).Msg("Directly streamed MITM response")
		return nil, true, nil // Return true to indicate it was streamed
	}

	// --- PATH 2: Buffer and Inject ---
	defer bodyStream.Close()
	bodyBytes, err := io.ReadAll(bodyStream)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response body for injection")
		return nil, false, err
	}

	// Decode, inject payload, and re-encode
	contentEncoding := resp.Header.Get("Content-Encoding")
	processedBody, _, err := injectWithReencode(s.payloadInjector, bodyBytes, contentType, contentEncoding)
	if err != nil {
		log.Error().Err(err).Str("content_encoding", contentEncoding).Msg("Failed to re-encode body, sending original.")
		processedBody = bodyBytes // Fallback to original body on error
	} else {
		log.Info().Str("content_type", contentType).Msg("Payload injected and body re-encoded")
	}

	// Create a new standard library http.Response to send back to the client.
	httpResp := &http.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        fromFhttpHeader(resp.Header), // Convert fhttp.Header to http.Header
		Body:          io.NopCloser(bytes.NewReader(processedBody)),
		ContentLength: int64(len(processedBody)),
		Request:       r,
	}
	// We are now sending a buffered response, so we must manage framing.
	// Set Content-Length and remove Transfer-Encoding.
	httpResp.Header.Set("Content-Length", fmt.Sprintf("%d", len(processedBody)))
	httpResp.Header.Del("Transfer-Encoding")

	log.Debug().
		Str("type", "mitm_response").
		Int("status", resp.StatusCode).
		Int("size", len(processedBody)).
		Msg("MITM HTTP response with injected payload")

	return httpResp, false, nil // Return false to indicate it's a buffered response object
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

// We need to implement io.Closer for the writer passed to io.Copy to be closed correctly.
// Since io.Copy checks for io.WriteCloser to call Close, we add the Close method.
var _ io.WriteCloser = (*ChunkedWriter)(nil)

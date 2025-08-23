package masktunnel

import (
	"bufio"
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
	// Parse host from target (remove port if present)
	host := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		host = target[:idx]
	}

	// Log MITM setup with structured logging
	log.Debug().
		Str("type", "mitm_setup").
		Str("target", target).
		Str("host", host).
		Msg("Starting MITM")

	// Load or generate certificate for the target host
	cert, err := s.getCertificateForHost(host)
	if err != nil {
		log.Error().Err(err).Str("host", host).Msg("Failed to get certificate")
		return
	}

	// Create TLS config for client connection
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   host,
	}

	// Wrap client connection with TLS
	clientTLSConn := tls.Server(clientConn, tlsConfig)
	defer clientTLSConn.Close()

	// Perform TLS handshake with client
	if err := clientTLSConn.Handshake(); err != nil {
		log.Error().Err(err).Str("host", host).Msg("Client TLS handshake failed")
		return
	}

	log.Debug().Str("host", host).Msg("Client TLS handshake completed")

	// Get azuretls session for server connection with fingerprinting
	sess, err := s.sessionManager.GetSession(userAgent, s.config.UpstreamProxy)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get azuretls session")
		return
	}

	// Log detailed fingerprint information
	if browserFp, err := GetBrowserFingerprint(userAgent); err == nil {
		log.Info().
			Str("browser", browserFp.Browser).
			Str("tls_profile", browserFp.TLSProfile).
			Str("http2_fingerprint", browserFp.HTTP2Fingerprint).
			Msg("Session configured with fingerprints")
	}

	// Handle HTTP requests over the TLS connection
	s.handleTLSConnection(clientTLSConn, sess, host)
}

// handleTLSConnection handles HTTP requests over established TLS connection
func (s *Server) handleTLSConnection(clientTLSConn *tls.Conn, sess *azuretls.Session, host string) {
	log.Debug().Str("host", host).Msg("Starting HTTP handler for TLS connection")

	// Read and process HTTP requests directly
	for {
		// Create HTTP request reader
		req, err := http.ReadRequest(bufio.NewReader(clientTLSConn))
		if err != nil {
			if err != io.EOF {
				log.Error().Err(err).Msg("Failed to read HTTP request")
			}
			break
		}

		// Process the request - azuretls will handle TLS connection with fingerprinting
		resp, err := s.processMITMRequest(req, sess, host)
		if err != nil {
			log.Error().Err(err).Msg("Failed to process MITM request")
			break
		}

		// Write response back to client
		if err := resp.Write(clientTLSConn); err != nil {
			log.Error().Err(err).Msg("Failed to write response")
			break
		}

		// Close connection for HTTP/1.0 or if Connection: close
		if req.ProtoMajor < 2 && (req.Close || req.Header.Get("Connection") == "close") {
			break
		}
	}

	log.Debug().Str("host", host).Msg("Closed TLS connection")
}

// processMITMRequest handles individual HTTP requests in MITM mode
func (s *Server) processMITMRequest(r *http.Request, sess *azuretls.Session, host string) (*http.Response, error) {
	// Construct full URL for the request
	scheme := "https"
	if r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}

	fullURL := scheme + "://" + host + r.URL.Path
	if r.URL.RawQuery != "" {
		fullURL += "?" + r.URL.RawQuery
	}

	// Log MITM HTTP request with structured logging
	log.Info().
		Str("type", "mitm_request").
		Str("method", r.Method).
		Str("url", r.URL.String()).
		Str("host", host).
		Str("full_url", fullURL).
		Msg("MITM HTTP request - azuretls will apply ClientHello fingerprint")

	// Create azuretls request using OrderedHeaders (Header is ignored by azuretls-client)
	azureReq := &azuretls.Request{
		Method: r.Method,
		Url:    fullURL,
	}

	// Convert client headers to OrderedHeaders
	if len(r.Header) > 0 {
		azureReq.OrderedHeaders = azuretls.OrderedHeaders{}

		// Add headers from client request
		// Note: Go's http.Request.Header is a map so original order is lost,
		// but at least the headers will be forwarded rather than ignored
		for name, values := range r.Header {
			for _, value := range values {
				azureReq.OrderedHeaders = append(azureReq.OrderedHeaders, []string{name, value})
			}
		}
	}

	// Crucial fix for HTTP/2 fingerprinting:
	// For requests without a body (like GET), Go's http.Request has a non-nil Body (http.NoBody).
	// We must explicitly set Body to nil so that azuretls-client sends the HEADERS frame
	// with the EndStream flag set, which is critical for a correct fingerprint hash.
	if r.ContentLength == 0 {
		azureReq.Body = nil
	} else {
		azureReq.Body = r.Body
	}

	// Send request using azuretls with fingerprinting
	resp, err := sess.Do(azureReq)
	if err != nil {
		log.Error().Err(err).Msg("MITM request failed")
		return nil, err
	}

	// Process response body with payload injection
	body := resp.Body
	contentType := resp.Header.Get("Content-Type")

	if s.payloadInjector.ShouldInject(contentType) {
		body = s.payloadInjector.InjectIntoResponse(body, contentType)
		log.Info().Str("content_type", contentType).Msg("Payload injected")
	}

	// Create http response
	httpResp := &http.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
		Request:       r,
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			httpResp.Header.Add(key, value)
		}
	}

	// Update Content-Length if body was modified
	if len(body) != len(resp.Body) {
		httpResp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		httpResp.ContentLength = int64(len(body))
	}

	log.Debug().
		Str("type", "mitm_response").
		Int("status", resp.StatusCode).
		Int("size", len(body)).
		Msg("MITM HTTP response")

	return httpResp, nil
}

// getCertificateForHost returns a certificate for the given host
func (s *Server) getCertificateForHost(host string) (tls.Certificate, error) {
	cert, err := s.certManager.GetCertificate(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	return *cert, nil
}

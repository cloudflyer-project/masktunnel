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
		IgnoreBody:       true, // Enable streaming by default
	}

	// Convert client headers to OrderedHeaders
	if len(r.Header) > 0 {
		azureReq.OrderedHeaders = azuretls.OrderedHeaders{}

		// Add headers from client request
		// Note: Go's http.Request.Header is a map so original order is lost
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
		return nil, false, err
	}

	// By default, we stream the response. If we need to inject payload,
	// we'll read the body into memory.
	bodyStream := resp.RawBody
	contentType := resp.Header.Get("Content-Type")

	// If no payload injection is needed, directly stream upstream response preserving framing
	if !s.payloadInjector.ShouldInject(contentType) {
		var sb strings.Builder
		sb.WriteString("HTTP/1.1 ")
		if resp.Status != "" {
			sb.WriteString(resp.Status)
		} else {
			sb.WriteString(fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)))
		}
		sb.WriteString("\r\n")

		// Preserve headers but manage Connection/length semantics ourselves
		hasCL := false
		hasTE := false
		for key, values := range resp.Header {
			lk := strings.ToLower(key)
			if lk == "connection" {
				continue
			}
			if lk == "content-length" {
				hasCL = true
			}
			if lk == "transfer-encoding" {
				hasTE = true
			}
			for _, value := range values {
				sb.WriteString(key)
				sb.WriteString(": ")
				sb.WriteString(value)
				sb.WriteString("\r\n")
			}
		}

		// If neither Content-Length nor Transfer-Encoding: enforce close-delimited by adding Connection: close
		if !hasCL && !hasTE {
			sb.WriteString("Connection: close\r\n")
		}

		sb.WriteString("\r\n")

		if _, err := io.WriteString(clientConn, sb.String()); err != nil {
			_ = bodyStream.Close()
			return nil, false, err
		}

		if _, err := io.Copy(clientConn, bodyStream); err != nil {
			_ = bodyStream.Close()
			return nil, false, err
		}
		_ = bodyStream.Close()

		// Mirror/Enforce close-delimited semantics when required
		if !hasCL && !hasTE {
			_ = clientConn.Close()
		} else if strings.EqualFold(resp.Header.Get("Connection"), "close") {
			_ = clientConn.Close()
		}

		log.Debug().Str("type", "mitm_response").Int("status", resp.StatusCode).Msg("Directly streamed MITM response")
		return nil, true, nil
	}

	// Payload injection path: buffer, inject, and return a normal response object
	bodyBytes, err := io.ReadAll(bodyStream)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response body for injection")
		_ = bodyStream.Close()
		return nil, false, err
	}
	_ = bodyStream.Close()

	injectedBody := s.payloadInjector.InjectIntoResponse(bodyBytes, contentType)
	log.Info().Str("content_type", contentType).Msg("Payload injected")

	httpResp := &http.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(injectedBody)),
		ContentLength: int64(len(injectedBody)),
		Request:       r,
	}
	for key, values := range resp.Header {
		lk := strings.ToLower(key)
		if lk == "transfer-encoding" {
			continue
		}
		for _, value := range values {
			httpResp.Header.Add(key, value)
		}
	}
	httpResp.Header.Set("Content-Length", fmt.Sprintf("%d", len(injectedBody)))

	log.Debug().
		Str("type", "mitm_response").
		Int("status", resp.StatusCode).
		Int("size", len(injectedBody)).
		Msg("MITM HTTP response with payload")

	return httpResp, false, nil
}

// getCertificateForHost returns a certificate for the given host
func (s *Server) getCertificateForHost(host string) (tls.Certificate, error) {
	cert, err := s.certManager.GetCertificate(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	return *cert, nil
}

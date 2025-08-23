package masktunnel

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// BasicAuth handles HTTP Basic Authentication for proxy
type BasicAuth struct {
	username string
	password string
	enabled  bool
}

// NewBasicAuth creates a new basic auth handler
func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		username: username,
		password: password,
		enabled:  username != "" || password != "",
	}
}

// IsEnabled returns true if authentication is enabled
func (ba *BasicAuth) IsEnabled() bool {
	return ba.enabled
}

// Validate validates the proxy authentication from request
func (ba *BasicAuth) Validate(req *http.Request) bool {
	if !ba.enabled {
		return true
	}

	authHeader := req.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		return false
	}

	if !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}

	encoded := authHeader[6:] // Remove "Basic " prefix
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return false
	}

	return parts[0] == ba.username && parts[1] == ba.password
}

// GetAuthRequiredResponse returns HTTP 407 response for auth required
func (ba *BasicAuth) GetAuthRequiredResponse() *http.Response {
	resp := &http.Response{
		StatusCode:    http.StatusProxyAuthRequired,
		Status:        "407 Proxy Authentication Required",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          http.NoBody,
		ContentLength: 0,
	}

	resp.Header.Set("Proxy-Authenticate", "Basic realm=\"MaskTunnel Proxy\"")
	resp.Header.Set("Content-Type", "text/plain")

	return resp
}

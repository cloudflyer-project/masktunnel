package masktunnel

import "github.com/rs/zerolog"

// Config holds the proxy server configuration
type Config struct {
	Addr          string
	Port          string
	UserAgent     string
	Payload       string
	UpstreamProxy string
	Username      string
	Password      string
	CertFile      string
	KeyFile       string
	Verbose       int
	Logger        *zerolog.Logger // Custom logger for Python bindings
}

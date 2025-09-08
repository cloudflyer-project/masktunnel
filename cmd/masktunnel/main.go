package main

import (
	"fmt"
	"os"
	"time"

	"github.com/cloudflyer-project/masktunnel"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
)

// getLogLevel maps verbosity count to zerolog level.
// default (0) is Warn, -v is Info, -vv is Debug, -vvv is Trace.
func getLogLevel(count int) zerolog.Level {
	switch {
	case count >= 3:
		return zerolog.TraceLevel
	case count == 2:
		return zerolog.DebugLevel
	case count == 1:
		return zerolog.InfoLevel
	default: // 0 or less
		return zerolog.WarnLevel
	}
}

func main() {
	var config masktunnel.Config

	// Command line flags
	pflag.StringVarP(&config.Addr, "addr", "a", "", "Proxy listen address")
	pflag.StringVarP(&config.Port, "port", "p", "8080", "Proxy listen port")
	pflag.StringVarP(&config.UserAgent, "user-agent", "U", "", "Override the User-Agent header. Optional.")
	pflag.StringVarP(&config.Payload, "payload", "P", "", "Payload to inject into responses. Optional.")
	pflag.StringVarP(&config.UpstreamProxy, "upstream-proxy", "X", "", "Forward requests to an upstream proxy. Optional.")
	pflag.StringVar(&config.Username, "username", "", "Username for proxy authentication. Optional.")
	pflag.StringVar(&config.Password, "password", "", "Password for proxy authentication. Optional.")
	pflag.StringVarP(&config.CertFile, "cert", "c", "cert.pem", "TLS CA certificate (auto-generated if not present)")
	pflag.StringVarP(&config.KeyFile, "key", "k", "key.pem", "TLS CA key (auto-generated if not present)")
	pflag.CountVarP(&config.Verbose, "verbose", "v", "Enable verbose logging (-v for info, -vv for debug, -vvv for trace)")
	pflag.Parse()

	// Setup zerolog
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	output.FormatMessage = func(i interface{}) string {
		return i.(string)
	}
	log.Logger = zerolog.New(output).With().Timestamp().Logger()

	// Set log level based on verbose flag count
	zerolog.SetGlobalLevel(getLogLevel(config.Verbose))

	// Start proxy server
	server := masktunnel.NewServer(&config)

	addr := fmt.Sprintf("%s:%s", config.Addr, config.Port)
	log.Warn().Str("address", addr).Msg("MaskTunnel proxy server starting")

	if err := server.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}

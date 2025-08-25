package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/cloudflyer-project/masktunnel"
)

func main() {
	var config masktunnel.Config

	// Command line flags
	flag.StringVar(&config.Addr, "addr", "", "Proxy listen address")
	flag.StringVar(&config.Port, "port", "8080", "Proxy listen port")
	flag.StringVar(&config.UserAgent, "user-agent", "", "Override the User-Agent header for incoming requests. Optional.")
	flag.StringVar(&config.Payload, "payload", "", "Payload to inject into responses. Optional.")
	flag.StringVar(&config.UpstreamProxy, "upstream-proxy", "", "Forward requests to an upstream proxy. Optional.")
	flag.StringVar(&config.Username, "username", "", "Username for proxy authentication. Optional.")
	flag.StringVar(&config.Password, "password", "", "Password for proxy authentication. Optional.")
	flag.StringVar(&config.CertFile, "cert", "cert.pem", "TLS CA certificate (generated automatically if not present)")
	flag.StringVar(&config.KeyFile, "key", "key.pem", "TLS CA key (generated automatically if not present)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	// Setup zerolog
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	output.FormatMessage = func(i interface{}) string {
		return i.(string)
	}
	log.Logger = zerolog.New(output).With().Timestamp().Logger()

	// Set log level based on verbose flag
	if config.Verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Start proxy server
	server := masktunnel.NewServer(&config)

	addr := fmt.Sprintf("%s:%s", config.Addr, config.Port)
	log.Info().Str("address", addr).Msg("MaskTunnel proxy server starting")

	if err := server.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}

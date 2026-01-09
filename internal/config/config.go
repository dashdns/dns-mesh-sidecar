package config

import (
	"encoding/base64"
	"flag"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type Config struct {
	ListenAddr            string
	UpstreamDNS           string
	Verbose               bool
	Blocklist             []string
	DryRun                bool
	ControllerURL         string
	FetchInterval         time.Duration
	MetricsAddr           string
	HTTPSModeEnabled      bool
	HTTPSUpstream         string
	TLSCACert             string
	TLSClientCert         string
	TLSClientKey          string
	TLSInsecureSkipVerify bool

	// Runtime TLS data fetched from controller (decoded from base64)
	tlsClientCertData []byte
	tlsClientKeyData  []byte
	tlsCACertData     []byte
	tlsMutex          sync.RWMutex
}

func Load() *Config {
	cfg := &Config{}
	fetchIntervalSec := 0

	flag.StringVar(&cfg.ListenAddr, "listen", ":53", "Address to listen on (default :53)")
	flag.StringVar(&cfg.UpstreamDNS, "upstream", "1.1.1.1:53", "Upstream DNS server (default 1.1.1.1:53)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&cfg.ControllerURL, "controller", "", "Controller URL to fetch policies from")
	flag.IntVar(&fetchIntervalSec, "fetch-interval", 30, "Policy fetch interval in seconds (default 30)")
	flag.StringVar(&cfg.MetricsAddr, "metrics", ":9090", "Metrics HTTP server address (default :9090)")
	flag.BoolVar(&cfg.HTTPSModeEnabled, "https-mode", false, "Enable DNS-over-HTTPS mode")
	flag.StringVar(&cfg.HTTPSUpstream, "https-upstream", "https://1.1.1.1/dns-query", "DNS-over-HTTPS upstream server (default Cloudflare)")
	flag.StringVar(&cfg.TLSCACert, "tls-ca-cert", "", "Path to CA certificate for verifying DoH server")
	flag.StringVar(&cfg.TLSClientCert, "tls-client-cert", "", "Path to client certificate for mTLS")
	flag.StringVar(&cfg.TLSClientKey, "tls-client-key", "", "Path to client private key for mTLS")
	flag.BoolVar(&cfg.TLSInsecureSkipVerify, "tls-insecure-skip-verify", false, "Skip TLS certificate verification (insecure, for testing only)")
	flag.Parse()

	cfg.FetchInterval = time.Duration(fetchIntervalSec) * time.Second

	return cfg
}

// UpdateTLSData updates the TLS certificate and key data from base64-encoded strings
func (c *Config) UpdateTLSData(certBase64, keyBase64, caCertBase64 string) error {
	c.tlsMutex.Lock()
	defer c.tlsMutex.Unlock()

	if certBase64 != "" {
		certData, err := base64.StdEncoding.DecodeString(certBase64)
		if err != nil {
			log.Err(err).Msg("Failed to decode TLS certificate from base64")
			return err
		}
		c.tlsClientCertData = certData
		if c.Verbose {
			log.Info().Msg("TLS client certificate updated from controller")
		}
	}

	if keyBase64 != "" {
		keyData, err := base64.StdEncoding.DecodeString(keyBase64)
		if err != nil {
			log.Err(err).Msg("Failed to decode TLS private key from base64")
			return err
		}
		c.tlsClientKeyData = keyData
		if c.Verbose {
			log.Info().Msg("TLS client private key updated from controller")
		}
	}

	if caCertBase64 != "" {
		caCertData, err := base64.StdEncoding.DecodeString(caCertBase64)
		if err != nil {
			log.Err(err).Msg("Failed to decode CA certificate from base64")
			return err
		}
		c.tlsCACertData = caCertData
		if c.Verbose {
			log.Info().Msg("CA certificate updated from controller")
		}
	}

	return nil
}

// GetTLSClientCertData returns the decoded TLS client certificate data
func (c *Config) GetTLSClientCertData() []byte {
	c.tlsMutex.RLock()
	defer c.tlsMutex.RUnlock()
	return c.tlsClientCertData
}

// GetTLSClientKeyData returns the decoded TLS client private key data
func (c *Config) GetTLSClientKeyData() []byte {
	c.tlsMutex.RLock()
	defer c.tlsMutex.RUnlock()
	return c.tlsClientKeyData
}

// GetTLSCACertData returns the decoded CA certificate data
func (c *Config) GetTLSCACertData() []byte {
	c.tlsMutex.RLock()
	defer c.tlsMutex.RUnlock()
	return c.tlsCACertData
}

// SetHTTPSMode dynamically enables or disables HTTPS mode
func (c *Config) SetHTTPSMode(enabled bool) {
	c.tlsMutex.Lock()
	defer c.tlsMutex.Unlock()
	c.HTTPSModeEnabled = enabled
	if c.Verbose {
		if enabled {
			log.Info().Msg("DoH (DNS-over-HTTPS) mode enabled by controller")
		} else {
			log.Info().Msg("DoH (DNS-over-HTTPS) mode disabled by controller")
		}
	}
}

// IsHTTPSModeEnabled returns whether HTTPS mode is currently enabled
func (c *Config) IsHTTPSModeEnabled() bool {
	c.tlsMutex.RLock()
	defer c.tlsMutex.RUnlock()
	return c.HTTPSModeEnabled
}

package doh

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

// DoHClient represents a DNS over HTTPS client
type DoHClient struct {
	ServerURL  string
	HTTPClient *http.Client
}

// DoHConfig holds configuration for the DoH client
type DoHConfig struct {
	ServerURL          string
	TLSConfig          *tls.Config
	Timeout            time.Duration
	CACertPath         string
	ClientCertPath     string
	ClientKeyPath      string
	// In-memory certificate data (takes precedence over file paths)
	CACertData         []byte
	ClientCertData     []byte
	ClientKeyData      []byte
	InsecureSkipVerify bool
}

// NewDoHClient creates a new DoH client with the given configuration
func NewDoHClient(config DoHConfig) *DoHClient {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	// Load TLS certificates if provided
	tlsConfig, err := loadTLSConfig(config)
	if err != nil {
		log.Err(err).Msg("Failed to load TLS configuration, using defaults")
		tlsConfig = config.TLSConfig
	}

	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return &DoHClient{
		ServerURL:  config.ServerURL,
		HTTPClient: httpClient,
	}
}

// loadTLSConfig loads TLS certificates and creates a TLS configuration
func loadTLSConfig(config DoHConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	// Load CA certificate if provided
	// Prefer in-memory data over file path
	if len(config.CACertData) > 0 {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(config.CACertData) {
			return nil, fmt.Errorf("failed to parse CA certificate from memory")
		}

		tlsConfig.RootCAs = caCertPool
		log.Info().Msg("Loaded CA certificate from in-memory data")
	} else if config.CACertPath != "" {
		caCert, err := os.ReadFile(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
		log.Info().Msgf("Loaded CA certificate from %s", config.CACertPath)
	}

	// Load client certificate and key if provided (for mTLS)
	// Prefer in-memory data over file paths
	if len(config.ClientCertData) > 0 && len(config.ClientKeyData) > 0 {
		clientCert, err := tls.X509KeyPair(config.ClientCertData, config.ClientKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client certificate from memory: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{clientCert}
		log.Info().Msg("Loaded client certificate from in-memory data")
	} else if config.ClientCertPath != "" && config.ClientKeyPath != "" {
		clientCert, err := tls.LoadX509KeyPair(config.ClientCertPath, config.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{clientCert}
		log.Info().Msgf("Loaded client certificate from %s", config.ClientCertPath)
	}

	if config.InsecureSkipVerify {
		log.Warn().Msg("TLS certificate verification is disabled (insecure)")
	}

	return tlsConfig, nil
}

// Query sends a DNS query to the DoH server and returns the response
// The query should be in DNS wire format
func (c *DoHClient) Query(dnsQuery []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", c.ServerURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "application/dns-message" {
		return nil, fmt.Errorf("unexpected content type: %s", contentType)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}

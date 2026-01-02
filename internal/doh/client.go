package doh

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DoHClient represents a DNS over HTTPS client
type DoHClient struct {
	ServerURL  string
	HTTPClient *http.Client
}

// DoHConfig holds configuration for the DoH client
type DoHConfig struct {
	ServerURL string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// NewDoHClient creates a new DoH client with the given configuration
func NewDoHClient(config DoHConfig) *DoHClient {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	if config.TLSConfig == nil {
		config.TLSConfig = &tls.Config{}
	}

	transport := &http.Transport{
		TLSClientConfig:   config.TLSConfig,
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

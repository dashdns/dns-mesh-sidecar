package dns

import (
	"crypto/tls"
	"errors"
	"lktr/internal/doh"
	"lktr/internal/metrics"
	"lktr/pkg/matcher"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	INVALID_QUERY_LENGTH_MSG = "QueryLenghtTooLongException"
)

type Handler struct {
	UpstreamDNS           string
	Verbose               bool
	DryRun                bool
	Matcher               *matcher.Matcher
	HTTPSModeEnabled      bool
	HTTPSUpstream         string
	DoHClient             *doh.DoHClient
	dnsMeshDohTimeout     int
	tlsCACert             string
	tlsInsecureSkipVerify bool
	getTLSCertData        func() ([]byte, []byte, []byte) // function to get current TLS cert/key/CA data
	mu                    sync.RWMutex
}

func NewHandler(upstreamDNS string, verbose bool, m *matcher.Matcher, httpsModeEnabled bool, httpsUpstream string, dnsMeshDohTimeout int, tlsCACert string, tlsClientCert string, tlsClientKey string, tlsInsecureSkipVerify bool, getTLSCertData func() ([]byte, []byte, []byte)) *Handler {
	handler := &Handler{
		UpstreamDNS:           upstreamDNS,
		Verbose:               verbose,
		Matcher:               m,
		HTTPSModeEnabled:      httpsModeEnabled,
		HTTPSUpstream:         httpsUpstream,
		dnsMeshDohTimeout:     dnsMeshDohTimeout,
		tlsCACert:             tlsCACert,
		tlsInsecureSkipVerify: tlsInsecureSkipVerify,
		getTLSCertData:        getTLSCertData,
	}

	// Initialize DoH client if HTTPS mode is enabled
	if httpsModeEnabled {
		handler.initDoHClient(tlsClientCert, tlsClientKey)

		if verbose {
			log.Info().Msgf("DNS-over-HTTPS mode enabled with upstream: %s", httpsUpstream)
			if tlsCACert != "" {
				log.Info().Msgf("Using custom CA certificate: %s", tlsCACert)
			}
			if tlsClientCert != "" && tlsClientKey != "" {
				log.Info().Msgf("Using client certificate for mTLS: %s", tlsClientCert)
			}
			if tlsInsecureSkipVerify {
				log.Warn().Msg("TLS certificate verification is disabled")
			}
		}
	}

	return handler
}

// initDoHClient initializes or reinitializes the DoH client with current TLS configuration
func (h *Handler) initDoHClient(tlsClientCert, tlsClientKey string) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	dohConfig := doh.DoHConfig{
		ServerURL:          h.HTTPSUpstream,
		TLSConfig:          tlsConfig,
		Timeout:            time.Duration(h.dnsMeshDohTimeout) * time.Second,
		CACertPath:         h.tlsCACert,
		ClientCertPath:     tlsClientCert,
		ClientKeyPath:      tlsClientKey,
		InsecureSkipVerify: h.tlsInsecureSkipVerify,
	}

	// Get in-memory TLS data if available
	if h.getTLSCertData != nil {
		certData, keyData, caCertData := h.getTLSCertData()
		if len(certData) > 0 && len(keyData) > 0 {
			dohConfig.ClientCertData = certData
			dohConfig.ClientKeyData = keyData
		}
		if len(caCertData) > 0 {
			dohConfig.CACertData = caCertData
		}
	}

	h.DoHClient = doh.NewDoHClient(dohConfig)
}

// UpdateTLSConfig updates the DoH client with new TLS certificate data
func (h *Handler) UpdateTLSConfig() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.HTTPSModeEnabled {
		return
	}

	if h.Verbose {
		log.Info().Msg("Updating DoH client with new TLS configuration")
	}

	h.initDoHClient("", "")
}

// SetHTTPSMode dynamically enables or disables HTTPS mode
func (h *Handler) SetHTTPSMode(enabled bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.HTTPSModeEnabled = enabled

	if enabled {
		// Initialize DoH client when enabling
		if h.DoHClient == nil {
			h.initDoHClient("", "")
		}
		if h.Verbose {
			log.Info().Msg("DNS-over-HTTPS mode enabled")
		}
	} else {
		if h.Verbose {
			log.Info().Msg("DNS-over-HTTPS mode disabled")
		}
	}
}

// isHTTPSModeEnabled returns whether HTTPS mode is currently enabled (thread-safe)
func (h *Handler) isHTTPSModeEnabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.HTTPSModeEnabled
}

func (h *Handler) UpdateMatcher(m *matcher.Matcher) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Matcher = m
	if h.Verbose {
		log.Printf("Matcher updated successfully")
	}
}

func (h *Handler) getMatcher() *matcher.Matcher {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.Matcher
}

// HandleHTTPS sends a DNS query over HTTPS and returns the response
func (h *Handler) HandleHTTPS(query []byte, protocol string) ([]byte, error) {
	if h.DoHClient == nil {
		return nil, errors.New("DoH client not initialized")
	}

	if h.Verbose {
		log.Info().Msgf("[%s] Sending query via DNS-over-HTTPS to %s", protocol, h.HTTPSUpstream)
	}

	// Send query via DoH
	response, err := h.DoHClient.Query(query)
	if err != nil {
		log.Err(err).Msgf("Failed to query via DNS-over-HTTPS")
		return nil, err
	}

	if h.Verbose {
		log.Info().Msgf("[%s] Received %d bytes from DoH server", protocol, len(response))
	}

	return response, nil
}

func (h *Handler) HandleUDP(serverConn *net.UDPConn, clientAddr *net.UDPAddr, query []byte) {
	start := time.Now()
	protocol := "udp"
	// Increment total queries
	metrics.QueriesTotal.WithLabelValues(protocol).Inc()
	domain, qtype := ParseQuery(query)
	// Track parse errors (when domain is empty and query is long enough)
	if domain == "" && len(query) >= 12 {
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeParse, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	if domain != "" {
		log.Info().Msgf("[UDP] %s -> %s (%s)\n", clientAddr, domain, qtype)
	}

	m := h.getMatcher()
	if m != nil {
		result := m.Match(domain)
		if h.Verbose {
			log.Info().Msgf("Domain: %s, Matched: %v", domain, result.Matched)
		}

		if result.Matched {

			if !h.DryRun {

				log.Info().Msgf("[UDP] Blocking %s - returning NXDOMAIN\n", domain)

				// Increment blocked counter
				metrics.QueriesBlocked.WithLabelValues(protocol).Inc()

				nxdomainResponse := CreateNXDomainResponse(query)
				_, err := serverConn.WriteToUDP(nxdomainResponse, clientAddr)
				if err != nil {
					log.Err(err).Msg("Failed to send NXDOMAIN response to client:")
					metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeClientWrite, protocol).Inc()
				}

				metrics.QueryDuration.WithLabelValues(protocol, "blocked").Observe(time.Since(start).Seconds())
				return
			} else {
				log.Info().Msgf("DryRun Mode enabled not blocking [UDP] %s - returning NXDOMAIN\n", domain)
			}
		}
	}

	var responseBuffer []byte
	var n int

	// Check if HTTPS mode is enabled
	if h.isHTTPSModeEnabled() {
		// Use DNS-over-HTTPS
		protocol = "https"
		response, err := h.HandleHTTPS(query, protocol)
		if err != nil {
			log.Err(err).Msg("Failed to query via DNS-over-HTTPS:")
			metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamRead, protocol).Inc()
			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}
		responseBuffer = response
		n = len(response)
	} else {
		// Use regular UDP forwarding
		upstreamAddr, err := net.ResolveUDPAddr("udp", h.UpstreamDNS)
		if err != nil {
			log.Err(err).Msg("Failed to resolve upstream DNS:")
			metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamDial, protocol).Inc()
			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}

		upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
		if err != nil {
			log.Err(err).Msg("Failed to connect to upstream DNS:")
			metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamDial, protocol).Inc()
			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}
		defer upstreamConn.Close()

		upstreamConn.SetDeadline(time.Now().Add(5 * time.Second))

		_, err = upstreamConn.Write(query)
		if err != nil {
			log.Err(err).Msg("Failed to send query to upstream:")
			metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamWrite, protocol).Inc()
			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}

		if h.Verbose {
			log.Info().Msgf("Forwarded query to %s", h.UpstreamDNS)
		}

		buffer := make([]byte, 512)
		n, err = upstreamConn.Read(buffer)
		if err != nil {
			log.Err(err).Msg("Failed to read response from upstream:")

			// Check if it's a timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamTimeout, protocol).Inc()
			} else {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamRead, protocol).Inc()
			}

			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}
		responseBuffer = buffer

		if h.Verbose {
			log.Info().Msgf("Received %d bytes from upstream", n)
		}
	}

	_, err := serverConn.WriteToUDP(responseBuffer[:n], clientAddr)
	if err != nil {
		log.Err(err).Msg("Failed to send response to client:")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeClientWrite, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	if h.Verbose {
		log.Printf("Sent response to %s", clientAddr)
	}

	// Successfully allowed and forwarded
	metrics.QueriesAllowed.WithLabelValues(protocol).Inc()
	metrics.QueryDuration.WithLabelValues(protocol, "allowed").Observe(time.Since(start).Seconds())
}

func (h *Handler) HandleTCP(clientConn net.Conn) {
	defer clientConn.Close()
	start := time.Now()
	protocol := "tcp"
	var n int

	// Increment total queries
	metrics.QueriesTotal.WithLabelValues(protocol).Inc()

	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	lengthBuf := make([]byte, 2)
	_, err := clientConn.Read(lengthBuf)
	if err != nil {
		log.Err(err).Msg("Failed to read TCP length prefix:")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeParse, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	queryLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	if queryLen > 65535 {
		err = errors.New(INVALID_QUERY_LENGTH_MSG)
		log.Err(err).Msgf("Invalid query length: %d", queryLen)
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeParse, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	query := make([]byte, queryLen)
	n, err = clientConn.Read(query)
	if err != nil {
		log.Err(err).Msg("Failed to read TCP query:")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeParse, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	if n != queryLen {
		err = errors.New(INVALID_QUERY_LENGTH_MSG)
		log.Err(err).Msgf("Expected %d bytes but got %d", queryLen, n)
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeParse, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	domain, qtype := ParseQuery(query)

	// Track parse errors when domain is empty and query is long enough
	if domain == "" && len(query) >= 12 {
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeParse, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	if domain != "" {
		log.Info().Msgf("[TCP] %s -> %s (%s)\n", clientConn.RemoteAddr(), domain, qtype)
	}

	if h.Verbose {
		log.Info().Msgf("Processing TCP query from %s", clientConn.RemoteAddr())
	}

	m := h.getMatcher()
	if m != nil {
		result := m.Match(domain)
		if h.Verbose {
			log.Info().Msgf("Domain: %s, Matched: %v", domain, result.Matched)
		}

		if result.Matched {
			log.Info().Msgf("[TCP] Blocking %s - returning NXDOMAIN\n", domain)

			// Increment blocked counter
			metrics.QueriesBlocked.WithLabelValues(protocol).Inc()

			nxdomainResponse := CreateNXDomainResponse(query)
			responseLen := len(nxdomainResponse)
			lengthPrefix := []byte{byte(responseLen >> 8), byte(responseLen & 0xFF)}
			_, err := clientConn.Write(lengthPrefix)
			if err != nil {
				log.Err(err).Msg("Failed to send NXDOMAIN length to client:")
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeClientWrite, protocol).Inc()
				metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
				return
			}
			_, err = clientConn.Write(nxdomainResponse)
			if err != nil {
				log.Err(err).Msg("Failed to send NXDOMAIN response to client:")
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeClientWrite, protocol).Inc()
			}

			metrics.QueryDuration.WithLabelValues(protocol, "blocked").Observe(time.Since(start).Seconds())
			return
		}
	}

	var response []byte

	// Check if HTTPS mode is enabled
	if h.isHTTPSModeEnabled() {
		// Use DNS-over-HTTPS
		dohResponse, err := h.HandleHTTPS(query, protocol)
		if err != nil {
			log.Err(err).Msg("Failed to query via DNS-over-HTTPS:")
			metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamRead, protocol).Inc()
			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}
		response = dohResponse
		n = len(dohResponse)
	} else {
		// Use regular TCP forwarding
		upstreamConn, err := net.DialTimeout("tcp", h.UpstreamDNS, 5*time.Second)
		if err != nil {
			log.Err(err).Msg("Failed to connect to upstream DNS via TCP:")

			// Check if it's a timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamTimeout, protocol).Inc()
			} else {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamDial, protocol).Inc()
			}

			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}
		defer upstreamConn.Close()

		upstreamConn.SetDeadline(time.Now().Add(5 * time.Second))

		_, err = upstreamConn.Write(lengthBuf)
		if err != nil {
			log.Err(err).Msg("Failed to send length prefix to upstream:")
			metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamWrite, protocol).Inc()
			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}

		_, err = upstreamConn.Write(query)
		if err != nil {
			log.Err(err).Msg("Failed to send query to upstream:")
			metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamWrite, protocol).Inc()
			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}

		if h.Verbose {
			log.Info().Msgf("Forwarded TCP query to %s", h.UpstreamDNS)
		}

		responseLengthBuf := make([]byte, 2)
		_, err = upstreamConn.Read(responseLengthBuf)
		if err != nil {
			log.Err(err).Msg("Failed to read response length from upstream:")

			// Check if it's a timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamTimeout, protocol).Inc()
			} else {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamRead, protocol).Inc()
			}

			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}

		responseLen := int(responseLengthBuf[0])<<8 | int(responseLengthBuf[1])

		response = make([]byte, responseLen)
		n, err = upstreamConn.Read(response)
		if err != nil {
			log.Err(err).Msg("Failed to read response from upstream:")

			// Check if it's a timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamTimeout, protocol).Inc()
			} else {
				metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeUpstreamRead, protocol).Inc()
			}

			metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
			return
		}

		if h.Verbose {
			log.Info().Msgf("Received %d bytes from upstream via TCP", n)
		}
	}

	// Send response to client with TCP length prefix
	responseLen := len(response[:n])
	lengthPrefix := []byte{byte(responseLen >> 8), byte(responseLen & 0xFF)}
	_, err = clientConn.Write(lengthPrefix)
	if err != nil {
		log.Err(err).Msg("Failed to send response length to client:")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeClientWrite, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	_, err = clientConn.Write(response[:n])
	if err != nil {
		log.Err(err).Msg("Failed to send response to client:")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypeClientWrite, protocol).Inc()
		metrics.QueryDuration.WithLabelValues(protocol, "error").Observe(time.Since(start).Seconds())
		return
	}

	if h.Verbose {
		log.Info().Msgf("Sent TCP response to %s", clientConn.RemoteAddr())
	}
	metrics.QueriesAllowed.WithLabelValues(protocol).Inc()
	metrics.QueryDuration.WithLabelValues(protocol, "allowed").Observe(time.Since(start).Seconds())
}

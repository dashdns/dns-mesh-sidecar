package main

import (
	"lktr/internal/client"
	"lktr/internal/config"
	"lktr/internal/dns"
	"lktr/internal/metrics"
	"lktr/internal/server"
	"lktr/pkg/matcher"
	"os"
	"strconv"

	"github.com/rs/zerolog/log"
)

func main() {
	cfg := config.Load()

	log.Info().Msg("DNS Proxy v0.0.3-rc (Sidecar Mode)\n")
	log.Info().Msgf("Listening on: %s\n", cfg.ListenAddr)
	log.Info().Msgf("Upstream DNS: %s\n", cfg.UpstreamDNS)
	if cfg.HTTPSModeEnabled {
		log.Info().Msgf("DNS-over-HTTPS mode: ENABLED\n")
		log.Info().Msgf("HTTPS Upstream: %s\n", cfg.HTTPSUpstream)
		if cfg.TLSCACert != "" {
			log.Info().Msgf("TLS CA Certificate: %s\n", cfg.TLSCACert)
		}
		if cfg.TLSClientCert != "" && cfg.TLSClientKey != "" {
			log.Info().Msgf("TLS Client Certificate: %s\n", cfg.TLSClientCert)
		}
		if cfg.TLSInsecureSkipVerify {
			log.Warn().Msg("TLS certificate verification: DISABLED (insecure)\n")
		}
	}
	if cfg.ControllerURL != "" {
		log.Info().Msgf("Controller URL: %s\n", cfg.ControllerURL)
		log.Info().Msgf("Fetch Interval: %v\n", cfg.FetchInterval)
	}
	log.Info().Msgf("Metrics endpoint: http://%s/metrics\n", cfg.MetricsAddr)
	log.Info().Msg("Starting DNS proxy...")

	// Start metrics server in background
	go func() {
		if err := metrics.StartMetricsServer(cfg.MetricsAddr); err != nil {
			log.Err(err).Msg("Metrics server error:")
		}
	}()

	blocklist := []string{}

	m := matcher.BuildMatcher(blocklist)
	dnsMeshDohTimeout, err := strconv.Atoi(os.Getenv("DNS_MESH_DOH_TIMEOUT"))
	if err != nil {
		dnsMeshDohTimeout = 10
	}

	// Create a function to get TLS cert data from config
	getTLSCertData := func() ([]byte, []byte, []byte) {
		return cfg.GetTLSClientCertData(), cfg.GetTLSClientKeyData(), cfg.GetTLSCACertData()
	}
	dnsHandler := dns.NewHandler(cfg.UpstreamDNS, cfg.Verbose, m, cfg.HTTPSModeEnabled, cfg.HTTPSUpstream, dnsMeshDohTimeout, cfg.TLSCACert, cfg.TLSClientCert, cfg.TLSClientKey, cfg.TLSInsecureSkipVerify, getTLSCertData)

	updateChannel := make(chan []string, 10)

	go func() {
		for newBlocklist := range updateChannel {
			if cfg.Verbose {
				log.Info().Msgf("Received blocklist update with %d entries", len(newBlocklist))
			}
			newMatcher := matcher.BuildMatcher(newBlocklist)
			dnsHandler.DryRun = cfg.DryRun
			dnsHandler.UpdateMatcher(newMatcher)

			if cfg.Verbose {
				log.Info().Msgf("Blocklist updated successfully with %d entries\n", len(newBlocklist))
			}
		}
	}()

	operationalMode := os.Getenv("DNS_MESH_OPERATIONAL_MODE")
	if cfg.ControllerURL != "" {
		// Create DoH callback to update DoH mode when controller changes it
		dohCallback := func(enabled bool) {
			// Update config DoH status
			cfg.SetHTTPSMode(enabled)
			// Update DNS handler DoH status
			dnsHandler.SetHTTPSMode(enabled)
			if cfg.Verbose {
				if enabled {
					log.Info().Msg("DoH mode dynamically enabled by controller")
				} else {
					log.Info().Msg("DoH mode dynamically disabled by controller")
				}
			}
		}

		// Create TLS data callback to update config when controller provides new TLS data
		tlsCallback := func(tlsData *client.TLSData) {
			if err := cfg.UpdateTLSData(tlsData.Certificate, tlsData.PrivateKey, tlsData.CACertificate); err != nil {
				log.Err(err).Msg("Failed to update TLS data from controller")
				return
			}

			// Update DoH client with new TLS configuration if DoH is enabled
			if cfg.IsHTTPSModeEnabled() {
				dnsHandler.UpdateTLSConfig()
				if cfg.Verbose {
					log.Info().Msg("DoH client updated with new TLS credentials from controller")
				}
			}
		}

		fetcher := client.NewFetcher(cfg.ControllerURL, &cfg.FetchInterval, cfg.Verbose, updateChannel, &cfg.DryRun, operationalMode, tlsCallback, dohCallback)
		go fetcher.Start()
	} else {
		log.Info().Msgf("Warning: No controller URL specified, running without policy updates")
	}

	udpServer := server.NewUDPServer(cfg.ListenAddr, dnsHandler, cfg.Verbose)
	tcpServer := server.NewTCPServer(cfg.ListenAddr, dnsHandler, cfg.Verbose)

	go func() {
		if err := udpServer.Start(); err != nil {
			log.Err(err).Msg("UDP server error:")
		}
	}()

	if err := tcpServer.Start(); err != nil {
		log.Err(err).Msg("TCP server error:")
	}
}

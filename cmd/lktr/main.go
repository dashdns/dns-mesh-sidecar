package main

import (
	"lktr/internal/client"
	"lktr/internal/config"
	"lktr/internal/dns"
	"lktr/internal/metrics"
	"lktr/internal/server"
	"lktr/pkg/matcher"

	"github.com/rs/zerolog/log"
)

func main() {
	cfg := config.Load()

	log.Info().Msg("DNS Proxy v1.0.0 (Sidecar Mode)\n")
	log.Info().Msgf("Listening on: %s\n", cfg.ListenAddr)
	log.Info().Msgf("Upstream DNS: %s\n", cfg.UpstreamDNS)
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

	dnsHandler := dns.NewHandler(cfg.UpstreamDNS, cfg.Verbose, m)

	updateChannel := make(chan []string, 10)

	go func() {
		for newBlocklist := range updateChannel {
			if cfg.Verbose {
				log.Info().Msgf("Received blocklist update with %d entries", len(newBlocklist))
			}
			newMatcher := matcher.BuildMatcher(newBlocklist)
			dnsHandler.DryRun = cfg.DryRun
			dnsHandler.UpdateMatcher(newMatcher)

			log.Info().Msgf("Blocklist updated successfully with %d entries\n", len(newBlocklist))
		}
	}()

	if cfg.ControllerURL != "" {
		fetcher := client.NewFetcher(cfg.ControllerURL, cfg.FetchInterval, cfg.Verbose, updateChannel, &cfg.DryRun)
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

package main

import (
	"log"

	"lktr/internal/client"
	"lktr/internal/config"
	"lktr/internal/dns"
	"lktr/internal/metrics"
	"lktr/internal/server"
	"lktr/pkg/matcher"
)

func main() {
	cfg := config.Load()

	log.Printf("DNS Proxy v1.0.0 (Sidecar Mode)\n")
	log.Printf("Listening on: %s\n", cfg.ListenAddr)
	log.Printf("Upstream DNS: %s\n", cfg.UpstreamDNS)
	if cfg.ControllerURL != "" {
		log.Printf("Controller URL: %s\n", cfg.ControllerURL)
		log.Printf("Fetch Interval: %v\n", cfg.FetchInterval)
	}
	log.Printf("Metrics endpoint: http://%s/metrics\n", cfg.MetricsAddr)
	log.Printf("Starting DNS proxy...")

	// Start metrics server in background
	go func() {
		if err := metrics.StartMetricsServer(cfg.MetricsAddr); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	blocklist := []string{}

	m := matcher.BuildMatcher(blocklist)

	dnsHandler := dns.NewHandler(cfg.UpstreamDNS, cfg.Verbose, m)

	updateChannel := make(chan []string, 10)

	go func() {
		for newBlocklist := range updateChannel {
			if cfg.Verbose {
				log.Printf("Received blocklist update with %d entries", len(newBlocklist))
			}

			newMatcher := matcher.BuildMatcher(newBlocklist)
			dnsHandler.UpdateMatcher(newMatcher)

			log.Printf("Blocklist updated successfully with %d entries\n", len(newBlocklist))
		}
	}()

	if cfg.ControllerURL != "" {
		fetcher := client.NewFetcher(cfg.ControllerURL, cfg.FetchInterval, cfg.Verbose, updateChannel)
		go fetcher.Start()
	} else {
		log.Println("Warning: No controller URL specified, running without policy updates")
	}

	udpServer := server.NewUDPServer(cfg.ListenAddr, dnsHandler, cfg.Verbose)
	tcpServer := server.NewTCPServer(cfg.ListenAddr, dnsHandler, cfg.Verbose)

	go func() {
		if err := udpServer.Start(); err != nil {
			log.Fatalf("UDP server error: %v", err)
		}
	}()

	if err := tcpServer.Start(); err != nil {
		log.Fatalf("TCP server error: %v", err)
	}
}

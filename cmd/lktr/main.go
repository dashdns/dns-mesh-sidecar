package main

import (
	"fmt"
	"log"

	"lktr/internal/api"
	"lktr/internal/config"
	"lktr/internal/dns"
	"lktr/internal/server"
	"lktr/pkg/matcher"
)

func main() {
	cfg := config.Load()

	fmt.Printf("DNS Proxy v1.0.0\n")
	fmt.Printf("Listening on: %s\n", cfg.ListenAddr)
	fmt.Printf("Upstream DNS: %s\n", cfg.UpstreamDNS)
	fmt.Printf("API Server on: %s\n", cfg.APIPort)
	fmt.Println("Starting DNS proxy...")

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

			fmt.Printf("Blocklist updated successfully with %d entries\n", len(newBlocklist))
		}
	}()

	apiServer := api.NewServer(cfg.APIPort, cfg.Verbose, updateChannel)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("API server error: %v", err)
		}
	}()

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

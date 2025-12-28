package config

import (
	"flag"
	"time"
)

type Config struct {
	ListenAddr    string
	UpstreamDNS   string
	Verbose       bool
	Blocklist     []string
	DryRun        bool
	ControllerURL string
	FetchInterval time.Duration
	MetricsAddr   string
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
	flag.Parse()

	cfg.FetchInterval = time.Duration(fetchIntervalSec) * time.Second

	return cfg
}

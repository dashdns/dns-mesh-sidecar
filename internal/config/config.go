package config

import (
	"flag"
)

type Config struct {
	ListenAddr  string
	UpstreamDNS string
	Verbose     bool
	Blocklist   []string
	APIPort     string
}

func Load() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", ":53", "Address to listen on (default :53)")
	flag.StringVar(&cfg.UpstreamDNS, "upstream", "1.1.1.1:53", "Upstream DNS server (default 1.1.1.1:53)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.StringVar(&cfg.APIPort, "api-port", ":9090", "API server port (default :9090)")
	flag.Parse()

	return cfg
}

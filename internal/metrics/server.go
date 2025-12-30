package metrics

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// StartMetricsServer starts the HTTP server for Prometheus metrics
func StartMetricsServer(addr string) error {
	http.Handle("/metrics", promhttp.Handler())

	log.Printf("Metrics server listening on %s", addr)
	log.Printf("pprof endpoints available at http://%s/debug/pprof/", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		return fmt.Errorf("metrics server failed: %w", err)
	}
	return nil
}

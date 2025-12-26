package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// QueriesTotal counts total DNS queries received
	QueriesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_queries_total",
			Help: "Total number of DNS queries received",
		},
		[]string{"protocol"},
	)

	// QueriesBlocked counts DNS queries that were blocked
	QueriesBlocked = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_queries_blocked_total",
			Help: "Total number of DNS queries blocked",
		},
		[]string{"protocol"},
	)

	// QueriesAllowed counts DNS queries that were allowed and forwarded
	QueriesAllowed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_queries_allowed_total",
			Help: "Total number of DNS queries allowed and forwarded",
		},
		[]string{"protocol"},
	)

	// ErrorsTotal counts DNS errors by type
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_errors_total",
			Help: "Total number of DNS errors by type",
		},
		[]string{"type", "protocol"},
	)

	// QueryDuration tracks DNS query processing duration
	QueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_query_duration_seconds",
			Help:    "DNS query processing duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"protocol", "status"},
	)
)

// Error type constants
const (
	ErrorTypeParse           = "parse"
	ErrorTypeUpstreamDial    = "upstream_dial"
	ErrorTypeUpstreamWrite   = "upstream_write"
	ErrorTypeUpstreamRead    = "upstream_read"
	ErrorTypeUpstreamTimeout = "upstream_timeout"
	ErrorTypeClientWrite     = "client_write"
	ErrorTypePolicyFetch     = "policy_fetch"
)

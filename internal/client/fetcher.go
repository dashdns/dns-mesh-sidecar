package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"lktr/internal/metrics"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DnsPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DnsPolicySpec   `json:"spec,omitempty"`
	Status DnsPolicyStatus `json:"status,omitempty"`
}

type DnsPolicySpec struct {
	TargetSelector map[string]string `json:"targetSelector,omitempty"`
	AllowList      []string          `json:"allowList,omitempty"`
	BlockList      []string          `json:"blockList,omitempty"`
	DryRun         bool              `json:"dryrun,omitempty"`
	Interval       int               `json:"interval,omitempty"`
}

type DnsPolicyStatus struct {
	SelectorHash       string             `json:"selectorHash,omitempty"`
	SpecHash           string             `json:"specHash,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

type Fetcher struct {
	controllerURL string
	fetchInterval *time.Duration
	verbose       bool
	dryRun        *bool
	updateChannel chan []string
	httpClient    *http.Client
}

func NewFetcher(controllerURL string, fetchInterval *time.Duration, verbose bool, updateChannel chan []string, dryRun *bool) *Fetcher {
	return &Fetcher{
		controllerURL: controllerURL,
		fetchInterval: fetchInterval,
		verbose:       verbose,
		dryRun:        dryRun,
		updateChannel: updateChannel,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (f *Fetcher) Start() {
	if f.verbose {
		log.Info().Msgf("Starting policy fetcher, controller: %s, interval: %v", f.controllerURL, f.fetchInterval)
	}

	configHash := os.Getenv("DNS_MESH_CONFIG_HASH")
	if len(configHash) == 0 {
		err := errors.New("MISSING_ENVIRONMENT_VARIABLE")
		log.Err(err).Msg("The config hash cannot be blank")
	}

	ticker := time.NewTicker(*f.fetchInterval)
	defer ticker.Stop()

	// Fetch immediately on start
	f.fetchPolicies(configHash)

	for range ticker.C {
		f.fetchPolicies(configHash)
	}
}

func (f *Fetcher) fetchPolicies(configHash string) {
	if f.verbose {
		log.Info().Msgf("Fetching policies from controller: %s", f.controllerURL)
	}

	url := fmt.Sprintf("%s/api/policies?hash=%s", f.controllerURL, configHash)
	resp, err := f.httpClient.Get(url)
	if err != nil {
		log.Err(err).Msg("Error fetching policies:")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypePolicyFetch, "policy_upstream").Inc()
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := errors.New("HTTP status error")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypePolicyFetch, "policy_upstream_http_err").Inc()
		log.Err(err).Msgf("Unexpected status code from controller: %d", resp.StatusCode)
		return
	}

	var policyResp DnsPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policyResp); err != nil {
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypePolicyFetch, "policy_upstream_decode_err").Inc()
		log.Err(err).Msg("Error decoding policy response:")
		return
	}

	policyCount := len(policyResp.Spec.BlockList)
	if f.verbose {
		log.Info().Msgf("Fetched %d policy entries from controller", policyCount)
	}

	f.updateChannel <- policyResp.Spec.BlockList
	*f.dryRun = policyResp.Spec.DryRun
	*f.fetchInterval = time.Duration(policyResp.Spec.Interval)
	metrics.InfoTotal.WithLabelValues(metrics.InformalMetric, "number_of_policies").Set(float64(policyCount))

	if f.verbose {
		log.Info().Msgf("Policies fetched successfully: %d entries\n", policyCount)
	}
}

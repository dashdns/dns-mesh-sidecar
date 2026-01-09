package client

import (
	"errors"
	"fmt"
	"lktr/internal/metrics"
	"net/http"
	"os"
	"time"

	json "github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
)

func NewFetcher(controllerURL string, fetchInterval *time.Duration, verbose bool, updateChannel chan []string, dryRun *bool, operationalMode string, tlsDataCallback func(*TLSData), dohCallback func(bool)) *Fetcher {
	return &Fetcher{
		controllerURL:   controllerURL,
		fetchInterval:   fetchInterval,
		verbose:         verbose,
		dryRun:          dryRun,
		operationalMode: operationalMode,
		updateChannel:   updateChannel,
		tlsDataCallback: tlsDataCallback,
		dohCallback:     dohCallback,
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
		log.Info().Msgf("The operational mode is %s error while fetching policies", f.operationalMode)
		switch f.operationalMode {
		case "strict":
			f.updateChannel <- []string{"*"}
		case "balance":
			*f.dryRun = true
		}
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypePolicyFetch, "policy_upstream").Inc()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := errors.New("HTTP status error")
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypePolicyFetch, "policy_upstream_http_err").Inc()
		log.Info().Msgf("The operational mode is %s error on HTTP Status", f.operationalMode)
		switch f.operationalMode {
		case "strict":
			f.updateChannel <- []string{"*"}
		case "balance":
			*f.dryRun = true
		}
		log.Err(err).Msgf("Unexpected status code from controller: %d", resp.StatusCode)
		log.Info().Msg("THE END")
		return
	}
	var controllerResp ControllerResponse
	if err := json.NewDecoder(resp.Body).Decode(&controllerResp); err != nil {
		metrics.ErrorsTotal.WithLabelValues(metrics.ErrorTypePolicyFetch, "policy_upstream_decode_err").Inc()
		log.Info().Msgf("The operational mode is %s error on decoding", f.operationalMode)
		switch f.operationalMode {
		case "strict":
			f.updateChannel <- []string{"*"}
		case "balance":
			*f.dryRun = true
		}
		log.Err(err).Msg("Error decoding policy response:")
		return
	}

	// Handle DoH status update
	if f.dohCallback != nil {
		if f.verbose {
			fmt.Println("The DOH status is ", controllerResp.Policy.Spec.Doh)
			log.Info().Msgf("DoH status from controller: %v", controllerResp.Policy.Spec.Doh)
		}
		f.dohCallback(controllerResp.Policy.Spec.Doh)
	}

	// Handle TLS data if DoH is enabled and TLS data is present
	if controllerResp.Policy.Spec.Doh && controllerResp.TLSData != nil && f.tlsDataCallback != nil {
		if f.verbose {
			log.Info().Msg("TLS data received from controller, updating configuration")
		}
		f.tlsDataCallback(controllerResp.TLSData)
	} else if !controllerResp.Policy.Spec.Doh && f.verbose {
		log.Info().Msg("DoH disabled, skipping TLS data processing")
	}

	policyCount := len(controllerResp.Policy.Spec.BlockList)
	if f.verbose {
		log.Info().Msgf("Fetched %d policy entries from controller", policyCount)
	}
	f.updateChannel <- controllerResp.Policy.Spec.BlockList
	*f.dryRun = controllerResp.Policy.Spec.DryRun
	*f.fetchInterval = time.Duration(controllerResp.Policy.Spec.Interval)
	metrics.InfoTotal.WithLabelValues(metrics.InformalMetric, "number_of_policies").Set(float64(policyCount))

	if f.verbose {
		log.Info().Msgf("Policies fetched successfully: %d entries\n", policyCount)
	}
}

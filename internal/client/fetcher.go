package client

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

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
}

type DnsPolicyStatus struct {
	SelectorHash       string             `json:"selectorHash,omitempty"`
	SpecHash           string             `json:"specHash,omitempty"`
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

type Fetcher struct {
	controllerURL string
	fetchInterval time.Duration
	verbose       bool
	updateChannel chan []string
	httpClient    *http.Client
}

func NewFetcher(controllerURL string, fetchInterval time.Duration, verbose bool, updateChannel chan []string) *Fetcher {
	return &Fetcher{
		controllerURL: controllerURL,
		fetchInterval: fetchInterval,
		verbose:       verbose,
		updateChannel: updateChannel,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (f *Fetcher) Start() {
	if f.verbose {
		log.Printf("Starting policy fetcher, controller: %s, interval: %v", f.controllerURL, f.fetchInterval)
	}

	configHash := os.Getenv("DNS_MESH_CONFIG_HASH")
	if len(configHash) == 0 {
		log.Fatal("The config hash cannot be blank")
	}

	ticker := time.NewTicker(f.fetchInterval)
	defer ticker.Stop()

	// Fetch immediately on start
	f.fetchPolicies(configHash)

	for range ticker.C {
		f.fetchPolicies(configHash)
	}
}

func (f *Fetcher) fetchPolicies(configHash string) {
	if f.verbose {
		log.Printf("Fetching policies from controller: %s", f.controllerURL)
	}

	url := fmt.Sprintf("%s/api/policies?hash=%s", f.controllerURL, configHash)
	resp, err := f.httpClient.Get(url)
	if err != nil {
		log.Printf("Error fetching policies: %v", err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Unexpected status code from controller: %d", resp.StatusCode)
		return
	}

	var policyResp DnsPolicy
	if err := json.NewDecoder(resp.Body).Decode(&policyResp); err != nil {
		log.Printf("Error decoding policy response: %v", err)
		return
	}

	if f.verbose {
		log.Printf("Fetched %d policy entries from controller", len(policyResp.Spec.BlockList))
	}

	f.updateChannel <- policyResp.Spec.BlockList

	log.Printf("Policies fetched successfully: %d entries\n", len(policyResp.Spec.BlockList))
}

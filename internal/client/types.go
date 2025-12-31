package client

import (
	"net/http"
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
	controllerURL   string
	fetchInterval   *time.Duration
	verbose         bool
	dryRun          *bool
	operationalMode string
	updateChannel   chan []string
	httpClient      *http.Client
}

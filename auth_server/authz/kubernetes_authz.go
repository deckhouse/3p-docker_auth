/*
   Copyright 2026 Flant

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authz

import (
	"fmt"

	"github.com/cesanta/glog"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/k8s"
)

var (
	k8sAuthzRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_auth_k8s_authz_requests_total",
			Help: "Total number of Kubernetes SelfSubjectRulesReview calls.",
		},
		[]string{"code"},
	)
	k8sAuthzRequestLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "registry_auth_k8s_authz_request_latency_seconds",
			Help:    "Latency of Kubernetes SelfSubjectRulesReview calls in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"code"},
	)
)

func init() {
	prometheus.MustRegister(k8sAuthzRequestsTotal)
	prometheus.MustRegister(k8sAuthzRequestLatencySeconds)
}

type kubernetesAuthz struct {
	cfg          *k8s.AuthConfig
	rulesFetcher k8s.RulesFetcher
}

// NewKubernetesAuthz creates a new Kubernetes RBAC authorizer using SelfSubjectRulesReview.
func NewKubernetesAuthz(config *k8s.AuthConfig) (api.Authorizer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	rc, err := config.BuildRestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes REST config: %w", err)
	}

	fetcherMetrics := &k8s.RulesFetcherMetrics{
		RequestsTotal:  k8sAuthzRequestsTotal,
		RequestLatency: k8sAuthzRequestLatencySeconds,
	}

	fetcher, err := k8s.NewRulesFetcher(config.Limits.RequestTimeout, rc, fetcherMetrics)
	if err != nil {
		return nil, fmt.Errorf("failed to create rules fetcher: %w", err)
	}
	cachedFetcher := k8s.NewCachedRulesFetcher(fetcher, config.Cache.SuccessTTL, config.Cache.FailureTTL)

	glog.V(1).Infof(
		"Kubernetes authz configured (group=%s, resource=%s, cache_ttl=%s/%s)",
		config.Authz.APIGroup, config.Authz.Resource, config.Cache.SuccessTTL, config.Cache.FailureTTL,
	)

	return &kubernetesAuthz{cfg: config, rulesFetcher: cachedFetcher}, nil
}

func (ka *kubernetesAuthz) Authorize(req *api.AuthRequestInfo) ([]string, error) {
	if len(req.Actions) == 0 {
		return nil, api.NoMatch
	}

	if req.Account != ka.cfg.UserName {
		return nil, api.NoMatch
	}

	userInfo := k8s.UserInfoFromLabels(req.Labels)
	if userInfo.Name == "" {
		return nil, api.NoMatch
	}

	ns, repoPath := k8s.SplitNamespaceAndPath(req.Name)
	if repoPath == "" {
		return nil, api.NoMatch
	}

	rules, err := ka.rulesFetcher.GetRules(userInfo, ns)
	if err != nil {
		glog.Errorf("Failed to get rules (SSRR): %v", err)
		return nil, err
	}

	allowed := []string{}
	for _, action := range req.Actions {
		verb, ok := k8s.GetK8sVerb(action)
		if !ok {
			glog.Warningf("Unknown action %q, ignoring", action)
			continue
		}

		if ka.cfg.Authz.IsActionAllowed(rules, verb, repoPath) {
			allowed = append(allowed, action)
		}
	}

	if len(allowed) == 0 {
		return nil, api.NoMatch
	}

	return allowed, nil
}

func (ka *kubernetesAuthz) Stop() {}

func (ka *kubernetesAuthz) Name() string {
	return "Kubernetes RBAC (SSRR)"
}

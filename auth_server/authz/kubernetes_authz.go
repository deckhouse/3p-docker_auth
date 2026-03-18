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
	"context"
	"fmt"

	"github.com/cesanta/glog"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/k8s"
)

var (
	k8sAuthzRulesRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_auth_k8s_authz_rules_requests_total",
			Help: "Total number of Kubernetes SelfSubjectRulesReview calls.",
		},
		[]string{"code"},
	)
	k8sAuthzRulesRequestDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "registry_auth_k8s_authz_rules_request_duration_seconds",
			Help:    "Duration of Kubernetes SelfSubjectRulesReview calls in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"code"},
	)
)

func init() {
	prometheus.MustRegister(k8sAuthzRulesRequestsTotal)
	prometheus.MustRegister(k8sAuthzRulesRequestDurationSeconds)
}

type kubernetesAuthz struct {
	cfg              *k8s.AuthConfig
	namespaceChecker k8s.NamespaceChecker
	rulesFetcher     k8s.RulesFetcher
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
		RequestsTotal:  k8sAuthzRulesRequestsTotal,
		RequestLatency: k8sAuthzRulesRequestDurationSeconds,
	}

	fetcher, err := k8s.NewRulesFetcher(config.Limits.RequestTimeout, rc, fetcherMetrics, config.Authz.FilterRules)
	if err != nil {
		return nil, fmt.Errorf("failed to create rules fetcher: %w", err)
	}

	cachedFetcher := k8s.NewCachedRulesFetcher(fetcher, config.Cache.SuccessTTL, config.Cache.FailureTTL)

	namespaceChecker, err := k8s.NewNamespaceChecker(config.Limits.RequestTimeout, rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create namespace checker: %w", err)
	}
	cachedNamespaceChecker := k8s.NewCachedNamespaceChecker(namespaceChecker, config.Cache.SuccessTTL, config.Cache.FailureTTL)

	glog.V(1).Infof(
		"Kubernetes authz configured (group=%s, resource=%s, cache_ttl=%s/%s)",
		config.Authz.APIGroup, config.Authz.Resource, config.Cache.SuccessTTL, config.Cache.FailureTTL,
	)

	return &kubernetesAuthz{
		cfg:              config,
		namespaceChecker: cachedNamespaceChecker,
		rulesFetcher:     cachedFetcher,
	}, nil
}

func (ka *kubernetesAuthz) Authorize(req *api.AuthRequestInfo) ([]string, error) {
	if len(req.Actions) == 0 {
		return nil, api.NoMatch
	}

	if req.Account != ka.cfg.UserName {
		return nil, api.NoMatch
	}

	userInfo, ok := req.AuthenticatorData.(k8s.UserInfo)
	if !ok || !userInfo.IsValid() {
		glog.Warning("Invalid userInfo, skipping authorization")
		return nil, api.NoMatch
	}

	ns, repoPath := k8s.SplitNamespaceAndPath(req.Name)
	if repoPath == "" {
		return nil, api.NoMatch
	}

	if ka.cfg.Authz.NeedsNamespaceCheck(req.Actions) {
		exists, err := ka.namespaceChecker.Exists(context.Background(), ns)
		if err != nil {
			glog.Errorf("Failed to check namespace %q: %v", ns, err)
			return nil, err
		}

		if !exists {
			glog.Warningf("Access denied: namespace %q does not exist (user=%s, repository=%s)", ns, userInfo.Name, req.Name)
			return nil, api.NoMatch
		}
	}

	rules, err := ka.rulesFetcher.GetRules(userInfo, ns)
	if err != nil {
		glog.Errorf("Failed to get rules (SSRR): %v", err)
		return nil, err
	}
	glog.V(2).Infof("Rules (SSRR) for user=%s ns=%s: %+v", userInfo.Name, ns, rules)

	allowed := []string{}
	for _, action := range req.Actions {
		verb, ok := k8s.GetK8sVerb(action)
		if !ok {
			glog.Warningf("Unknown action %q, ignoring", action)
			continue
		}

		if rules.IsActionAllowed(verb, repoPath) {
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

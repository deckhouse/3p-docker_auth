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
	"slices"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/cesanta/glog"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/k8s"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type kubernetesAuthz struct {
	cfg        *k8s.AuthConfig
	restConfig *rest.Config
	cache      *cache.LRUExpireCache
}

// Docker action to Kubernetes verb mapping (standard for Docker Registry).
var defaultVerbs = map[string]string{
	"pull":   "get",
	"push":   "create",
	"delete": "delete",
}

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

// NewKubernetesAuthz creates a new Kubernetes RBAC authorizer using SelfSubjectRulesReview.
func NewKubernetesAuthz(config *k8s.AuthConfig) (api.Authorizer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	rc, err := config.BuildRestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes REST config: %w", err)
	}

	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go#L130
	authzCache := cache.NewLRUExpireCache(8192)

	glog.V(1).Infof(
		"Kubernetes authz configured (group=%s, resource=%s, cache_ttl=%s/%s)",
		config.Authz.APIGroup, config.Authz.Resource, config.Cache.SuccessTTL, config.Cache.FailureTTL,
	)

	return &kubernetesAuthz{cfg: config, restConfig: rc, cache: authzCache}, nil
}

func (ka *kubernetesAuthz) Authorize(req *api.AuthRequestInfo) ([]string, error) {
	if req.Account != "token" {
		return nil, api.NoMatch
	}

	userInfo := k8s.UserInfoFromLabels(req.Labels)
	if userInfo.Name == "" {
		return nil, api.NoMatch
	}

	ns, repoPath := ka.splitNamespaceAndPath(req.Name)

	rules, err := ka.getRules(userInfo, ns)
	if err != nil {
		glog.Errorf("Failed to get rules (SSRR): %v", err)
		return nil, err
	}

	if len(req.Actions) == 0 {
		return []string{}, nil
	}

	allowed := []string{}

	for _, action := range req.Actions {
		verb, ok := defaultVerbs[action]
		if !ok {
			glog.Warningf("Unknown action %q, ignoring", action)
			continue
		}

		if ka.isActionAllowed(rules, verb, repoPath) {
			allowed = append(allowed, action)
		}
	}

	return allowed, nil
}

func (ka *kubernetesAuthz) getRules(userInfo *k8s.UserInfo, ns string) ([]authorizationv1.ResourceRule, error) {
	key, err := k8s.ComputeHash(userInfo, ns)
	if err != nil {
		return nil, fmt.Errorf("failed to compute cache key: %w", err)
	}

	if val, ok := ka.cache.Get(key); ok {
		return val.([]authorizationv1.ResourceRule), nil
	}

	rules, err := ka.getRulesFromK8s(userInfo, ns)
	if err != nil {
		if ka.cfg.Cache.FailureTTL > 0 {
			ka.cache.Add(key, []authorizationv1.ResourceRule(nil), ka.cfg.Cache.FailureTTL)
		}
		return nil, err
	}

	if ka.cfg.Cache.SuccessTTL > 0 {
		ka.cache.Add(key, rules, ka.cfg.Cache.SuccessTTL)
	}

	return rules, nil
}

// getRulesFromK8s fetches resource rules from Kubernetes using SelfSubjectRulesReview with retry logic and metrics.
func (ka *kubernetesAuthz) getRulesFromK8s(userInfo *k8s.UserInfo, ns string) ([]authorizationv1.ResourceRule, error) {
	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/pkg/util/webhook/webhook.go#L42
	backoff := webhook.DefaultRetryBackoffWithInitialDelay(500 * time.Millisecond)

	timeout := ka.cfg.Limits.RequestTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	impersonatedConfig := rest.CopyConfig(ka.restConfig)
	impersonatedConfig.Impersonate = userInfo.ToImpersonationConfig()

	client, err := kubernetes.NewForConfig(impersonatedConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create impersonated client: %w", err)
	}

	ssrr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: ns},
	}

	var rules []authorizationv1.ResourceRule

	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go#L235
	err = webhook.WithExponentialBackoff(ctx, backoff, func() error {
		start := time.Now()

		res, ssrrErr := client.
			AuthorizationV1().
			SelfSubjectRulesReviews().
			Create(ctx, ssrr, metav1.CreateOptions{})

		duration := time.Since(start).Seconds()

		code := "ok"
		if ssrrErr != nil {
			code = "error"
		}

		k8sAuthzRequestsTotal.WithLabelValues(code).Inc()
		k8sAuthzRequestLatencySeconds.WithLabelValues(code).Observe(duration)

		if ssrrErr != nil {
			return ssrrErr
		}

		rules = res.Status.ResourceRules

		return nil
	}, webhook.DefaultShouldRetry)

	if err != nil {
		return nil, err
	}

	return rules, nil
}

// splitNamespaceAndPath splits a repository name into namespace and relative path.
// The format is "namespace/path" where namespace is required and path is optional.
func (ka *kubernetesAuthz) splitNamespaceAndPath(name string) (string, string) {
	var relativePath string

	parts := strings.SplitN(name, "/", 2)

	ns := parts[0]
	if len(parts) == 2 {
		relativePath = parts[1]
	}

	return ns, relativePath
}

// isActionAllowed checks if the verb is allowed for the resource path using doublestar matching.
// Pattern matching uses github.com/bmatcuk/doublestar/v4 for recursive glob support (**).
func (ka *kubernetesAuthz) isActionAllowed(rules []authorizationv1.ResourceRule, verb string, resourcePath string) bool {
	for _, rule := range rules {
		if !slices.Contains(rule.Verbs, verb) && !slices.Contains(rule.Verbs, "*") {
			continue
		}

		if !slices.Contains(rule.APIGroups, ka.cfg.Authz.APIGroup) && !slices.Contains(rule.APIGroups, "*") {
			continue
		}

		if !slices.Contains(rule.Resources, ka.cfg.Authz.Resource) && !slices.Contains(rule.Resources, "*") {
			continue
		}

		if len(rule.ResourceNames) == 0 {
			return true
		}

		for _, pattern := range rule.ResourceNames {
			if matched, _ := doublestar.Match(pattern, resourcePath); matched {
				return true
			}
		}
	}

	return false
}

func (ka *kubernetesAuthz) Stop() {}

func (ka *kubernetesAuthz) Name() string {
	return "Kubernetes RBAC (SSRR)"
}

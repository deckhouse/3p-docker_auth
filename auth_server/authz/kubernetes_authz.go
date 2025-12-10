/*
   Copyright 2025 Flant

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
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/cesanta/glog"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cesanta/docker_auth/auth_server/api"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/util/webhook"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesAuthzConfig defines configuration for Kubernetes RBAC authorization via SSRR.
type KubernetesAuthzConfig struct {
	Kubeconfig string `yaml:"kubeconfig,omitempty"`

	Limits struct {
		QPS            float32       `yaml:"qps,omitempty"`
		Burst          int           `yaml:"burst,omitempty"`
		RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
	} `yaml:"limits,omitempty"`

	Cache struct {
		SuccessTTL time.Duration `yaml:"success_ttl,omitempty"`
		FailureTTL time.Duration `yaml:"failure_ttl,omitempty"`
	} `yaml:"cache,omitempty"`

	Review struct {
		APIGroup  string `yaml:"api_group,omitempty"`
		Resource  string `yaml:"resource,omitempty"`
		UserLabel string `yaml:"user_label,omitempty"`
	} `yaml:"review,omitempty"`
}

type kubernetesAuthz struct {
	cfg        *KubernetesAuthzConfig
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

func (c *KubernetesAuthzConfig) Validate(configKey string) error {
	if c == nil {
		return fmt.Errorf("%s is nil", configKey)
	}
	if c.Review.APIGroup == "" || c.Review.Resource == "" {
		return fmt.Errorf("%s.review.{api_group,resource} are required", configKey)
	}
	if c.Review.UserLabel == "" {
		c.Review.UserLabel = "k8s_username"
	}
	return nil
}

func buildRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		if _, statErr := os.Stat(kubeconfig); statErr != nil {
			return nil, fmt.Errorf("kubeconfig not accessible: %w", statErr)
		}
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

// NewKubernetesAuthz creates a new Kubernetes RBAC authorizer using SelfSubjectRulesReview.
func NewKubernetesAuthz(c *KubernetesAuthzConfig) (api.Authorizer, error) {
	if err := c.Validate("kubernetes_authz"); err != nil {
		return nil, err
	}

	rc, err := buildRestConfig(c.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes REST config: %w", err)
	}

	if c.Limits.QPS > 0 {
		rc.QPS = c.Limits.QPS
	}
	if c.Limits.Burst > 0 {
		rc.Burst = c.Limits.Burst
	}

	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go#L130
	authzCache := cache.NewLRUExpireCache(8192)

	glog.V(1).Infof("Kubernetes authz configured (group=%s, resource=%s, cache_ttl=%s/%s)",
		c.Review.APIGroup, c.Review.Resource, c.Cache.SuccessTTL, c.Cache.FailureTTL)
	return &kubernetesAuthz{cfg: c, restConfig: rc, cache: authzCache}, nil
}

func (ka *kubernetesAuthz) Authorize(ai *api.AuthRequestInfo) ([]string, error) {
	if ai.Account != "token" {
		return nil, api.NoMatch
	}

	username := ""
	if vals, ok := ai.Labels[ka.cfg.Review.UserLabel]; ok && len(vals) > 0 {
		username = vals[0]
	}
	if username == "" {
		return nil, api.NoMatch
	}

	groups := ai.Labels["groups"]
	extra := map[string][]string{}
	for k, vs := range ai.Labels {
		if k == "k8s_username" || k == "groups" {
			continue
		}
		extra[k] = vs
	}

	ns := strings.SplitN(ai.Name, "/", 2)[0]

	rules, err := ka.getRules(username, groups, extra, ns)
	if err != nil {
		glog.Errorf("Failed to get rules (SSRR): %v", err)
		return nil, err
	}

	if len(ai.Actions) == 0 {
		return []string{}, nil
	}

	relativePath := ka.derivePath(ai.Name)
	allowed := []string{}

	for _, action := range ai.Actions {
		verb, ok := defaultVerbs[action]
		if !ok {
			glog.Warningf("Unknown action %q, ignoring", action)
			continue
		}
		if ka.isActionAllowed(rules, verb, relativePath) {
			allowed = append(allowed, action)
		}
	}

	return allowed, nil
}

func (ka *kubernetesAuthz) getRules(username string, groups []string, extra map[string][]string, ns string) ([]authorizationv1.ResourceRule, error) {
	key := ka.computeCacheKey(username, groups, extra, ns)

	if val, ok := ka.cache.Get(key); ok {
		return val.([]authorizationv1.ResourceRule), nil
	}

	var rules []authorizationv1.ResourceRule

	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/pkg/util/webhook/webhook.go#L42
	backoff := webhook.DefaultRetryBackoffWithInitialDelay(500 * time.Millisecond)

	timeout := ka.cfg.Limits.RequestTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	impersonatedConfig := *ka.restConfig
	impersonatedConfig.Impersonate = rest.ImpersonationConfig{
		UserName: username,
		Groups:   groups,
		Extra:    extra,
	}

	client, err := kubernetes.NewForConfig(&impersonatedConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create impersonated client: %w", err)
	}

	ssrr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: ns},
	}

	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go#L235
	err = webhook.WithExponentialBackoff(ctx, backoff, func() error {
		start := time.Now()
		res, ssrrErr := client.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, ssrr, metav1.CreateOptions{})
		duration := time.Since(start).Seconds()

		code := "200"
		if ssrrErr != nil {
			code = "<error>"
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

func (ka *kubernetesAuthz) computeCacheKey(username string, groups []string, extra map[string][]string, ns string) string {
	gCopy := make([]string, len(groups))
	copy(gCopy, groups)
	sort.Strings(gCopy)

	eKeys := make([]string, 0, len(extra))
	for k := range extra {
		eKeys = append(eKeys, k)
	}
	sort.Strings(eKeys)

	var eb strings.Builder
	for _, k := range eKeys {
		vals := make([]string, len(extra[k]))
		copy(vals, extra[k])
		sort.Strings(vals)
		eb.WriteString(k)
		eb.WriteString(":")
		eb.WriteString(strings.Join(vals, ","))
		eb.WriteString(";")
	}

	return fmt.Sprintf("%s|%s|%s|%s", username, strings.Join(gCopy, ","), eb.String(), ns)
}

// isActionAllowed checks if the verb is allowed for the resource path using doublestar matching.
// Pattern matching uses github.com/bmatcuk/doublestar/v4 for recursive glob support (**).
func (ka *kubernetesAuthz) isActionAllowed(rules []authorizationv1.ResourceRule, verb string, resourcePath string) bool {
	for _, rule := range rules {
		if !slices.Contains(rule.Verbs, verb) && !slices.Contains(rule.Verbs, "*") {
			continue
		}
		if !slices.Contains(rule.APIGroups, ka.cfg.Review.APIGroup) && !slices.Contains(rule.APIGroups, "*") {
			continue
		}
		if !slices.Contains(rule.Resources, ka.cfg.Review.Resource) && !slices.Contains(rule.Resources, "*") {
			continue
		}
		if len(rule.ResourceNames) == 0 {
			continue
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

func (ka *kubernetesAuthz) derivePath(fullRepoName string) string {
	parts := strings.SplitN(fullRepoName, "/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return fullRepoName
}

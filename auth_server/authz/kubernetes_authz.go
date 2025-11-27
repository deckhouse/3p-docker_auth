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
	"path"
	"strings"
	"time"

	"github.com/cesanta/glog"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cesanta/docker_auth/auth_server/api"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesAuthzConfig struct {
	Kubeconfig string `yaml:"kubeconfig,omitempty"`

	Limits struct {
		QPS            float32       `yaml:"qps,omitempty"`
		Burst          int           `yaml:"burst,omitempty"`
		RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
	} `yaml:"limits,omitempty"`

	Cache struct {
		AllowTTL time.Duration `yaml:"allow_ttl,omitempty"`
		DenyTTL  time.Duration `yaml:"deny_ttl,omitempty"`
	} `yaml:"cache,omitempty"`

	Review struct {
		APIGroup      string            `yaml:"api_group,omitempty"`
		Resource      string            `yaml:"resource,omitempty"`
		UserLabel     string            `yaml:"user_label,omitempty"`
		NameTransform string            `yaml:"name_transform,omitempty"`
		Verbs         map[string]string `yaml:"verbs,omitempty"`
	} `yaml:"review,omitempty"`
}

type kubernetesAuthz struct {
	cfg        *KubernetesAuthzConfig
	restConfig *rest.Config
}

var (
	k8sAuthzRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_auth_k8s_authz_requests_total",
			Help: "Total number of Kubernetes SelfSubjectRulesReview calls performed by registry authorization, labeled by HTTP status code or <error>.",
		},
		[]string{"code"},
	)
	k8sAuthzRequestLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "registry_auth_k8s_authz_request_latency_seconds",
			Help:    "Latency of Kubernetes SelfSubjectRulesReview calls performed by registry authorization, in seconds, labeled by HTTP status code or <error>.",
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

	if c.Review.NameTransform == "" {
		c.Review.NameTransform = "base32"
	}

	if c.Review.Verbs == nil {
		c.Review.Verbs = map[string]string{"pull": "get", "push": "create"}
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

	glog.V(1).Infof("Kubernetes authz configured (kubeconfig=%t, group=%s, resource=%s, rest_qps_burst=%v/%d, cache_ttl=%s/%s)", c.Kubeconfig != "", c.Review.APIGroup, c.Review.Resource, c.Limits.QPS, c.Limits.Burst, c.Cache.AllowTTL, c.Cache.DenyTTL)
	return &kubernetesAuthz{cfg: c, restConfig: rc}, nil
}

func (ka *kubernetesAuthz) Authorize(ai *api.AuthRequestInfo) ([]string, error) {
	if ai.Account != "token" {
		return nil, api.NoMatch
	}

	// Extract subject from labels
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

	timeout := ka.cfg.Limits.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Derive namespace and relative path from the requested repository name
	ns, relativePath := ka.deriveNSAndPath(ai)

	// Prepare impersonation config
	// Create a shallow copy of the config to avoid race conditions if we were to modify it in place
	// (though we are creating a new client, passing modified config is safer)
	impersonatedConfig := *ka.restConfig
	impersonatedConfig.Impersonate = rest.ImpersonationConfig{
		UserName: username,
		Groups:   groups,
		Extra:    extra,
	}

	client, err := kubernetes.NewForConfig(&impersonatedConfig)
	if err != nil {
		glog.Errorf("Failed to create impersonated client: %v", err)
		return nil, err
	}

	allowed := []string{}
	ssrr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{
			Namespace: ns,
		},
	}

	// We only need to do SSRR once per request, as it returns ALL rules for the user in the namespace.
	// Optimization: Check if we have at least one action to check before making the call.
	if len(ai.Actions) == 0 {
		return allowed, nil
	}

	start := time.Now()
	res, err := client.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, ssrr, metav1.CreateOptions{})
	duration := time.Since(start).Seconds()

	code := "200"
	if err != nil {
		code = "<error>"
		glog.Errorf("Kubernetes SSRR error: %v", err)
	}

	k8sAuthzRequestsTotal.WithLabelValues(code).Inc()
	k8sAuthzRequestLatencySeconds.WithLabelValues(code).Observe(duration)

	if err != nil {
		return nil, err
	}

	// Check rules for each requested action
	for _, action := range ai.Actions {
		verb, ok := ka.cfg.Review.Verbs[action]
		if !ok {
			continue
		}

		if ka.isActionAllowed(res.Status.ResourceRules, verb, relativePath) {
			allowed = append(allowed, action)
		}
	}

	if len(allowed) == 0 {
		return []string{}, nil
	}
	return allowed, nil
}

// Recursive wildcard matching helper
// path.Match does not support recursive wildcards ("**")
// This implementation treats any "*" as a recursive match for path segments if it's at the end?
// No, standard path.Match is simple shell glob.
// For "backend/*" matching "backend/v2/api", path.Match fails because "*" does not match separator.
// We need prefix matching logic if pattern ends with "*" or proper glob support.
func matchPattern(pattern, name string) (bool, error) {
	// Optimization for common "prefix/*" case
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(name, prefix) {
			return true, nil
		}
	}
	// Fallback to standard glob
	return path.Match(pattern, name)
}

func (ka *kubernetesAuthz) isActionAllowed(rules []authorizationv1.ResourceRule, verb string, resourcePath string) bool {
	for _, rule := range rules {
		// Check verb
		if !sliceContains(rule.Verbs, verb) && !sliceContains(rule.Verbs, "*") {
			continue
		}

		// Check API Group
		if !sliceContains(rule.APIGroups, ka.cfg.Review.APIGroup) && !sliceContains(rule.APIGroups, "*") {
			continue
		}

		// Check Resource
		if !sliceContains(rule.Resources, ka.cfg.Review.Resource) && !sliceContains(rule.Resources, "*") {
			continue
		}

		// Check ResourceNames (This is our custom path matching logic)
		// If ResourceNames is empty, it means "all resources" -> ALLOW
		if len(rule.ResourceNames) == 0 {
			return true
		}

		// If ResourceNames is not empty, we check if our path matches any of the patterns
		for _, pattern := range rule.ResourceNames {
			matched, err := matchPattern(pattern, resourcePath)
			if err == nil && matched {
				return true
			}
		}
	}
	return false
}

func sliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (ka *kubernetesAuthz) Stop() {
}

func (ka *kubernetesAuthz) Name() string {
	return "Kubernetes RBAC (SSRR)"
}

func (ka *kubernetesAuthz) deriveNSAndPath(ai *api.AuthRequestInfo) (string, string) {
	ns := ""
	// Expect repo name like "namespace/image/subpath"
	parts := strings.SplitN(ai.Name, "/", 2)
	if len(parts) == 2 {
		ns = parts[0]
		// Return the namespace and the REST of the path (e.g. "image/subpath")
		// This "rest" is what we match against resourceNames in RBAC
		return ns, parts[1]
	}
	glog.V(2).Infof("Kubernetes authz: repository name lacks namespace: %q", ai.Name)
	return "", ai.Name
}

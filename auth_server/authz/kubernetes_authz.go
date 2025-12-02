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

	Review struct {
		APIGroup  string            `yaml:"api_group,omitempty"`
		Resource  string            `yaml:"resource,omitempty"`
		UserLabel string            `yaml:"user_label,omitempty"`
		Verbs     map[string]string `yaml:"verbs,omitempty"`
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

	if c.Review.Verbs == nil {
		c.Review.Verbs = map[string]string{
			"pull":   "get",
			"push":   "create",
			"delete": "delete",
		}
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

	// We don't create a Clientset here because we need to create a new one
	// for each request with impersonation configuration.
	// We store the rest.Config to clone it later.

	glog.V(1).Infof("Kubernetes authz configured (kubeconfig=%t, group=%s, resource=%s, rest_qps_burst=%v/%d)", c.Kubeconfig != "", c.Review.APIGroup, c.Review.Resource, c.Limits.QPS, c.Limits.Burst)
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

	// Derive relative path from the requested repository name
	relativePath := ka.derivePath(ai.Name)

	// Prepare impersonation config
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

	// SSRR must be performed in the namespace derived from the repo path.
	// According to Deckhouse logic, the first segment of the repo path is the Namespace.
	ns := strings.SplitN(ai.Name, "/", 2)[0]

	ssrr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{
			Namespace: ns,
		},
	}

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
			glog.Warningf("Kubernetes authz: unknown action %q (not mapped to any K8s verb), ignoring", action)
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

// matchPattern checks if the resource name matches the RBAC pattern.
// Supports standard path matching, recursive wildcard suffix "/*", and global wildcard "*".
func matchPattern(pattern, name string) (bool, error) {
	// Global wildcard matches everything
	if pattern == "*" {
		return true, nil
	}
	// Optimization for common "prefix/*" case (recursive match)
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(name, prefix) {
			return true, nil
		}
	}
	// Fallback to standard glob (non-recursive)
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
		// If ResourceNames is empty, it acts as a DENY.
		// To allow all resources, explicit "*" must be used in resourceNames.
		if len(rule.ResourceNames) == 0 {
			continue
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

func (ka *kubernetesAuthz) derivePath(fullRepoName string) string {
	// Expect repo name like "namespace/image/subpath"
	parts := strings.SplitN(fullRepoName, "/", 2)
	if len(parts) == 2 {
		// Return the REST of the path (e.g. "image/subpath")
		// This "rest" is what we match against resourceNames in RBAC
		return parts[1]
	}
	glog.V(2).Infof("Kubernetes authz: repository name lacks namespace: %q", fullRepoName)
	return fullRepoName
}

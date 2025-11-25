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
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cesanta/glog"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cesanta/docker_auth/auth_server/api"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesAuthzConfig struct {
	Kubeconfig string `yaml:"kubeconfig,omitempty"`

	Review struct {
		APIGroup      string            `yaml:"api_group,omitempty"`
		Resource      string            `yaml:"resource,omitempty"`
		UserLabel     string            `yaml:"user_label,omitempty"`
		NameTransform string            `yaml:"name_transform,omitempty"`
		Verbs         map[string]string `yaml:"verbs,omitempty"`
	} `yaml:"review,omitempty"`

	Limits struct {
		QPS            float32       `yaml:"qps,omitempty"`
		Burst          int           `yaml:"burst,omitempty"`
		RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
	} `yaml:"limits,omitempty"`

	Cache struct {
		AllowTTL time.Duration `yaml:"allow_ttl,omitempty"`
		DenyTTL  time.Duration `yaml:"deny_ttl,omitempty"`
	} `yaml:"cache,omitempty"`
}

type kubernetesAuthz struct {
	cfg   *KubernetesAuthzConfig
	authz authorizer.Authorizer
}

var (
	k8sAuthzRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_auth_k8s_authz_requests_total",
			Help: "Total number of Kubernetes SubjectAccessReview calls performed by registry authorization, labeled by HTTP status code or <error>.",
		},
		[]string{"code"},
	)
	k8sAuthzRequestLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "registry_auth_k8s_authz_request_latency_seconds",
			Help:    "Latency of Kubernetes SubjectAccessReview calls performed by registry authorization, in seconds, labeled by HTTP status code or <error>.",
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
	var (
		cfg *rest.Config
		err error
	)

	if kubeconfig != "" {
		if _, statErr := os.Stat(kubeconfig); statErr != nil {
			return nil, fmt.Errorf("kubeconfig not accessible: %w", statErr)
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes REST config (in_cluster=%t): %w", kubeconfig == "", err)
	}

	return cfg, nil
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

	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	// authorizerfactory.DelegatingAuthorizerConfig does not apply defaults for zero TTLs.
	// If c.Cache.AllowTTL/DenyTTL are 0, caching is disabled.
	authzConfig := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: cs.AuthorizationV1(),
		AllowCacheTTL:             c.Cache.AllowTTL,
		DenyCacheTTL:              c.Cache.DenyTTL,
		WebhookRetryBackoff:       options.DefaultAuthWebhookRetryBackoff(),
	}

	k8sAuthz, err := authzConfig.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s authorizer: %w", err)
	}

	glog.V(1).Infof("Kubernetes authz configured (kubeconfig=%t, group=%s, resource=%s, rest_qps_burst=%v/%d, cache_ttl=%s/%s)", c.Kubeconfig != "", c.Review.APIGroup, c.Review.Resource, c.Limits.QPS, c.Limits.Burst, c.Cache.AllowTTL, c.Cache.DenyTTL)
	return &kubernetesAuthz{cfg: c, authz: k8sAuthz}, nil
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

	allowed := []string{}
	for _, action := range ai.Actions {
		verb, ok := ka.cfg.Review.Verbs[action]
		if !ok {
			continue
		}

		ns, name := ka.deriveNSAndName(ai)
		if verb == "create" {
			// For create, Name is typically empty in SAR
			name = ""
		}

		attrs := authorizer.AttributesRecord{
			User: &user.DefaultInfo{
				Name:   username,
				Groups: groups,
				Extra:  extra,
			},
			Verb:            verb,
			Namespace:       ns,
			APIGroup:        ka.cfg.Review.APIGroup,
			Resource:        ka.cfg.Review.Resource,
			Name:            name,
			ResourceRequest: true,
		}

		start := time.Now()
		decision, _, err := ka.authz.Authorize(ctx, attrs)
		duration := time.Since(start).Seconds()

		code := "200"
		if err != nil {
			code = "<error>"
			glog.Errorf("Kubernetes Authorize error: %v", err)
		} else if decision != authorizer.DecisionAllow {
			code = "403"
		}

		k8sAuthzRequestsTotal.WithLabelValues(code).Inc()
		k8sAuthzRequestLatencySeconds.WithLabelValues(code).Observe(duration)

		if err != nil {
			return nil, err
		}
		if decision == authorizer.DecisionAllow {
			allowed = append(allowed, action)
		}
	}

	if len(allowed) == 0 {
		return []string{}, nil
	}
	return allowed, nil
}

func (ka *kubernetesAuthz) Stop() {
}

func (ka *kubernetesAuthz) Name() string {
	return "Kubernetes RBAC"
}

func (ka *kubernetesAuthz) deriveNSAndName(ai *api.AuthRequestInfo) (string, string) {
	ns := ""
	// Expect repo name like "namespace/image" — take the left part
	parts := strings.SplitN(ai.Name, "/", 2)
	if len(parts) == 2 {
		ns = parts[0]
	} else {
		glog.V(2).Infof("Kubernetes authz: repository name lacks namespace: %q", ai.Name)
	}

	name := ai.Name
	if ka.cfg.Review.NameTransform == "base32" {
		enc := base32.StdEncoding.WithPadding(base32.NoPadding)
		name = strings.ToLower(enc.EncodeToString([]byte(ai.Name)))
	}
	return ns, name
}

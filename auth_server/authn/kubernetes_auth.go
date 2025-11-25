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

package authn

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cesanta/glog"

	"github.com/cesanta/docker_auth/auth_server/api"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	apiauthn "k8s.io/apiserver/pkg/authentication/authenticator"
	tokencache "k8s.io/apiserver/pkg/authentication/token/cache"
	webhookauthn "k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
)

type KubernetesAuthConfig struct {
	Kubeconfig string `yaml:"kubeconfig,omitempty"`

	Labels struct {
		IncludeGroups bool `yaml:"include_groups,omitempty"`
		IncludeExtra  bool `yaml:"include_extra,omitempty"`
	} `yaml:"labels,omitempty"`

	Limits struct {
		QPS            float32       `yaml:"qps,omitempty"`
		Burst          int           `yaml:"burst,omitempty"`
		RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
	} `yaml:"limits,omitempty"`

	Cache struct {
		SuccessTTL time.Duration `yaml:"success_ttl,omitempty"`
		FailureTTL time.Duration `yaml:"failure_ttl,omitempty"`
	} `yaml:"cache,omitempty"`
}

type KubernetesAuth struct {
	cfg                *KubernetesAuthConfig
	client             *kubernetes.Clientset
	tokenAuthenticator apiauthn.Token
}

var (
	k8sAuthnRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_auth_k8s_authn_requests_total",
			Help: "Total number of Kubernetes TokenReview calls performed by registry authentication, labeled by HTTP status code or <error>.",
		},
		[]string{"code"},
	)
	k8sAuthnRequestLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "registry_auth_k8s_authn_request_latency_seconds",
			Help:    "Latency of Kubernetes TokenReview calls performed by registry authentication, in seconds, labeled by HTTP status code or <error>.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"code"},
	)
)

func init() {
	prometheus.MustRegister(k8sAuthnRequestsTotal)
	prometheus.MustRegister(k8sAuthnRequestLatencySeconds)
}

func (c *KubernetesAuthConfig) Validate(configKey string) error {
	if c == nil {
		return fmt.Errorf("%s is nil", configKey)
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

func NewKubernetesAuth(c *KubernetesAuthConfig) (*KubernetesAuth, error) {
	if err := c.Validate("kubernetes_auth"); err != nil {
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

	tokenAuth, err := webhookauthn.NewFromInterface(
		cs.AuthenticationV1(),
		[]string{},
		*webhookauthn.DefaultRetryBackoff(),
		c.Limits.RequestTimeout,
		webhookauthn.AuthenticatorMetrics{
			RecordRequestTotal: func(ctx context.Context, code string) {
				k8sAuthnRequestsTotal.WithLabelValues(code).Inc()
			},
			RecordRequestLatency: func(ctx context.Context, code string, latency float64) {
				k8sAuthnRequestLatencySeconds.WithLabelValues(code).Observe(latency)
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook token authenticator: %w", err)
	}

	cachingAuth := tokencache.New(tokenAuth, false, c.Cache.SuccessTTL, c.Cache.FailureTTL)

	glog.V(1).Infof("Kubernetes auth configured (kubeconfig=%t, rest_qps_burst=%v/%d, cache_ttl=%s/%s)", c.Kubeconfig != "", c.Limits.QPS, c.Limits.Burst, c.Cache.SuccessTTL, c.Cache.FailureTTL)
	return &KubernetesAuth{cfg: c, client: cs, tokenAuthenticator: cachingAuth}, nil
}

func (ka *KubernetesAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	if user != "token" || password == "" {
		return false, nil, api.NoMatch
	}

	ctx, cancel := context.WithTimeout(context.Background(), ka.cfg.Limits.RequestTimeout)
	defer cancel()

	authResp, ok, err := ka.tokenAuthenticator.AuthenticateToken(ctx, string(password))
	if err != nil {
		glog.Errorf("k8s token authenticator error: %v", err)
		return false, nil, err
	}

	if !ok || authResp == nil || authResp.User == nil {
		glog.V(2).Infof("Kubernetes authn failed for user=%q", user)
		return false, nil, nil
	}

	labels := api.Labels{}

	// Added for k8s-authz support: preserve username in labels
	if username := authResp.User.GetName(); username != "" {
		labels["k8s_username"] = []string{username}
	}

	if ka.cfg.Labels.IncludeGroups {
		if groups := authResp.User.GetGroups(); len(groups) > 0 {
			labels["groups"] = append([]string(nil), groups...)
		}
	}

	if ka.cfg.Labels.IncludeExtra {
		if extra := authResp.User.GetExtra(); extra != nil {
			for k, v := range extra {
				if len(v) > 0 {
					labels[k] = append([]string(nil), v...)
				}
			}
		}
	}

	glog.V(1).Infof("Kubernetes authn success: %s", authResp.User.GetName())
	return true, labels, nil
}

func (ka *KubernetesAuth) Stop() {
}

func (ka *KubernetesAuth) Name() string {
	return "Kubernetes"
}

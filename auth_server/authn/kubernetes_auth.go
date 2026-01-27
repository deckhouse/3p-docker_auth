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

package authn

import (
	"context"
	"fmt"

	"github.com/cesanta/glog"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/k8s"

	"k8s.io/client-go/kubernetes"

	apiauthn "k8s.io/apiserver/pkg/authentication/authenticator"
	tokencache "k8s.io/apiserver/pkg/authentication/token/cache"
	webhookauthn "k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
)

type KubernetesAuth struct {
	cfg                *k8s.AuthConfig
	client             *kubernetes.Clientset
	tokenAuthenticator apiauthn.Token
}

var (
	k8sAuthnRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "registry_auth_k8s_authn_requests_total",
			Help: "Total number of Kubernetes TokenReview calls.",
		},
		[]string{"code"},
	)
	k8sAuthnRequestLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "registry_auth_k8s_authn_request_latency_seconds",
			Help:    "Latency of Kubernetes TokenReview calls in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"code"},
	)
)

func init() {
	prometheus.MustRegister(k8sAuthnRequestsTotal)
	prometheus.MustRegister(k8sAuthnRequestLatencySeconds)
}

// NewKubernetesAuth creates a new Kubernetes authenticator using TokenReview API.
func NewKubernetesAuth(config *k8s.AuthConfig) (*KubernetesAuth, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	rc, err := config.BuildRestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build Kubernetes REST config: %w", err)
	}

	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/webhook/webhook.go
	tokenAuth, err := webhookauthn.NewFromInterface(
		cs.AuthenticationV1(),
		[]string{},
		*webhookauthn.DefaultRetryBackoff(),
		config.Limits.RequestTimeout,
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

	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/pkg/authentication/token/cache/cached_token_authenticator.go
	cachingAuth := tokencache.New(
		tokenAuth,
		false,
		config.Cache.SuccessTTL,
		config.Cache.FailureTTL,
	)

	glog.V(1).Infof(
		"Kubernetes auth configured (cache_ttl=%s/%s)",
		config.Cache.SuccessTTL, config.Cache.FailureTTL,
	)
	return &KubernetesAuth{cfg: config, client: cs, tokenAuthenticator: cachingAuth}, nil
}

func (ka *KubernetesAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	if user != ka.cfg.UserName || password == "" {
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
		return false, nil, nil
	}

	userInfo := k8s.UserInfoFromUser(authResp.User)
	labels := userInfo.ToLabels()

	// Set standard "groups" label like other auth methods
	if len(userInfo.Groups) > 0 {
		labels["groups"] = userInfo.Groups
	}

	glog.V(1).Infof("Kubernetes authn success: %s", userInfo.Name)
	return true, labels, nil
}

func (ka *KubernetesAuth) Stop() {}

func (ka *KubernetesAuth) Name() string {
	return "Kubernetes"
}

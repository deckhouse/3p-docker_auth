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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/apimachinery/pkg/util/wait"
	apiauthn "k8s.io/apiserver/pkg/authentication/authenticator"
	tokencache "k8s.io/apiserver/pkg/authentication/token/cache"
	webhookauthn "k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
)

// KubernetesAuthConfig configures the Kubernetes authenticator.
type KubernetesAuthConfig struct {
	Kubeconfig string `yaml:"kubeconfig,omitempty"`
	Labels     struct {
		IncludeGroups bool `yaml:"include_groups,omitempty"`
		IncludeExtra  bool `yaml:"include_extra,omitempty"`
	} `yaml:"labels,omitempty"`
	RateLimit struct {
		QPS   float32 `yaml:"qps,omitempty"`
		Burst int     `yaml:"burst,omitempty"`
	} `yaml:"rate_limit,omitempty"`
	Webhook struct {
		RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
		Cache          struct {
			SuccessTTL time.Duration `yaml:"success_ttl,omitempty"`
			FailureTTL time.Duration `yaml:"failure_ttl,omitempty"`
		} `yaml:"cache,omitempty"`
	} `yaml:"webhook,omitempty"`
}

type KubernetesAuth struct {
	cfg                *KubernetesAuthConfig
	client             *kubernetes.Clientset
	tokenAuthenticator apiauthn.Token
}

func (c *KubernetesAuthConfig) Validate(configKey string) error {
	if c == nil {
		return fmt.Errorf("%s is nil", configKey)
	}
	// Defaults for webhook timeout and cache TTLs
	if c.Webhook.RequestTimeout <= 0 {
		c.Webhook.RequestTimeout = 5 * time.Second
	}
	if c.Webhook.Cache.SuccessTTL <= 0 {
		c.Webhook.Cache.SuccessTTL = 2 * time.Minute
	}
	if c.Webhook.Cache.FailureTTL <= 0 {
		c.Webhook.Cache.FailureTTL = 2 * time.Minute
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

	if c.RateLimit.QPS > 0 {
		rc.QPS = c.RateLimit.QPS
	}
	if c.RateLimit.Burst > 0 {
		rc.Burst = c.RateLimit.Burst
	}

	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	rb := wait.Backoff{Duration: 500 * time.Millisecond, Factor: 1.2, Steps: 10}
	tokenAuth, err := webhookauthn.NewFromInterface(
		cs.AuthenticationV1(),
		[]string{},
		rb,
		c.Webhook.RequestTimeout,
		webhookauthn.AuthenticatorMetrics{
			RecordRequestTotal:   func(ctx context.Context, code string) {},
			RecordRequestLatency: func(ctx context.Context, code string, latency float64) {},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create webhook token authenticator: %w", err)
	}
	cachingAuth := tokencache.New(tokenAuth, false, c.Webhook.Cache.SuccessTTL, c.Webhook.Cache.FailureTTL)

	glog.V(1).Infof("Kubernetes auth configured (kubeconfig=%t, rest_qps_burst=%v/%d, cache_ttl=%s/%s)", c.Kubeconfig != "", c.RateLimit.QPS, c.RateLimit.Burst, c.Webhook.Cache.SuccessTTL, c.Webhook.Cache.FailureTTL)
	return &KubernetesAuth{cfg: c, client: cs, tokenAuthenticator: cachingAuth}, nil
}

func (ka *KubernetesAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	if user != "token" || password == "" {
		return false, nil, api.NoMatch
	}

	ctx, cancel := context.WithTimeout(context.Background(), ka.cfg.Webhook.RequestTimeout)
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

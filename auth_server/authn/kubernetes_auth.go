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

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authnclientv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	apiauthn "k8s.io/apiserver/pkg/authentication/authenticator"
	tokencache "k8s.io/apiserver/pkg/authentication/token/cache"
	apiuser "k8s.io/apiserver/pkg/authentication/user"
)

// KubernetesAuthConfig configures the Kubernetes authenticator.
type KubernetesAuthConfig struct {
	Kubeconfig     string        `yaml:"kubeconfig,omitempty"`
	RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
	Labels         struct {
		IncludeGroups bool `yaml:"include_groups,omitempty"`
		IncludeExtra  bool `yaml:"include_extra,omitempty"`
	} `yaml:"labels,omitempty"`
	RateLimit struct {
		QPS   float32 `yaml:"qps,omitempty"`
		Burst int     `yaml:"burst,omitempty"`
	} `yaml:"rate_limit,omitempty"`
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

func (c *KubernetesAuthConfig) Validate(configKey string) error {
	if c == nil {
		return fmt.Errorf("%s is nil", configKey)
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 5 * time.Second
	}
	if c.Cache.SuccessTTL <= 0 {
		c.Cache.SuccessTTL = 2 * time.Minute
	}
	if c.Cache.FailureTTL <= 0 {
		c.Cache.FailureTTL = 2 * time.Minute
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
	baseAuth := &tokenReviewerAuthenticator{client: cs.AuthenticationV1(), timeout: c.RequestTimeout}
	cachingAuth := tokencache.New(baseAuth, false, c.Cache.SuccessTTL, c.Cache.FailureTTL)

	glog.V(1).Infof("Kubernetes auth configured (kubeconfig=%t, rest_qps_burst=%v/%d, cache_ttl=%s/%s)", c.Kubeconfig != "", c.RateLimit.QPS, c.RateLimit.Burst, c.Cache.SuccessTTL, c.Cache.FailureTTL)
	return &KubernetesAuth{cfg: c, client: cs, tokenAuthenticator: cachingAuth}, nil
}

func (ka *KubernetesAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	if user != "token" || password == "" {
		return false, nil, api.NoMatch
	}

	ctx, cancel := context.WithTimeout(context.Background(), ka.cfg.RequestTimeout)
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

type tokenReviewerAuthenticator struct {
	client  authnclientv1.AuthenticationV1Interface
	timeout time.Duration
}

func (t *tokenReviewerAuthenticator) AuthenticateToken(parent context.Context, token string) (*apiauthn.Response, bool, error) {
	ctx := parent
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, t.timeout)
		defer cancel()
	}
	glog.V(3).Infof("TokenReview API call")
	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}
	res, err := t.client.TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return nil, false, err
	}
	if res == nil || !res.Status.Authenticated {
		return nil, false, nil
	}
	u := &apiuser.DefaultInfo{Name: res.Status.User.Username, UID: string(res.UID)}
	if len(res.Status.User.Groups) > 0 {
		u.Groups = append([]string(nil), res.Status.User.Groups...)
	}
	if res.Status.User.Extra != nil {
		extra := map[string][]string{}
		for k, v := range res.Status.User.Extra {
			if len(v) > 0 {
				extra[k] = append([]string(nil), v...)
			}
		}
		u.Extra = extra
	}
	return &apiauthn.Response{User: u}, true, nil
}

func (ka *KubernetesAuth) Stop() {
}

func (ka *KubernetesAuth) Name() string {
	return "Kubernetes"
}

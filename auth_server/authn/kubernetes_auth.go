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
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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
}

type KubernetesAuth struct {
	cfg    *KubernetesAuthConfig
	client *kubernetes.Clientset
}

func (c *KubernetesAuthConfig) Validate(configKey string) error {
	if c == nil {
		return fmt.Errorf("%s is nil", configKey)
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 5 * time.Second
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

	glog.V(1).Infof("Kubernetes auth configured (kubeconfig=%t, rest_qps_burst=%v/%d)", c.Kubeconfig != "", c.RateLimit.QPS, c.RateLimit.Burst)
	return &KubernetesAuth{cfg: c, client: cs}, nil
}

func (ka *KubernetesAuth) Authenticate(user string, password api.PasswordString) (bool, api.Labels, error) {
	if user != "token" || password == "" {
		return false, nil, api.NoMatch
	}

	ctx, cancel := context.WithTimeout(context.Background(), ka.cfg.RequestTimeout)
	defer cancel()

	tr := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token: string(password),
		},
	}

	res, err := ka.client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		glog.Errorf("k8s TokenReview error: %v", err)
		return false, nil, err
	}
	if res == nil || !res.Status.Authenticated {
		glog.V(2).Infof("Kubernetes authn failed for user=%q", user)
		return false, nil, nil
	}

	labels := api.Labels{}
	if res.Status.User.Username != "" {
		labels["k8s_username"] = []string{res.Status.User.Username}
	}
	if ka.cfg.Labels.IncludeGroups && len(res.Status.User.Groups) > 0 {
		labels["groups"] = append([]string(nil), res.Status.User.Groups...)
	}
	if ka.cfg.Labels.IncludeExtra && res.Status.User.Extra != nil {
		for k, v := range res.Status.User.Extra {
			// v is ExtraValue ([]string)
			if len(v) > 0 {
				labels[k] = append([]string(nil), v...)
			}
		}
	}

	glog.V(1).Infof("Kubernetes authn success: %s", res.Status.User.Username)
	return true, labels, nil
}

func (ka *KubernetesAuth) Stop() {
}

func (ka *KubernetesAuth) Name() string {
	return "Kubernetes"
}

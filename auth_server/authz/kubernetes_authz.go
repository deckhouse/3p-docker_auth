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
	"strings"
	"time"

	"github.com/cesanta/glog"

	"github.com/cesanta/docker_auth/auth_server/api"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesAuthzConfig struct {
	Kubeconfig     string        `yaml:"kubeconfig,omitempty"`
	RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`

	APIGroup string `yaml:"api_group,omitempty"`
	Resource string `yaml:"resource,omitempty"`

	// UserLabel is the label key to read Kubernetes username from AuthN labels
	// Defaults to "k8s_username".
	UserLabel string `yaml:"user_label,omitempty"`

	RateLimit struct {
		RPS   float64 `yaml:"rps,omitempty"`
		Burst int     `yaml:"burst,omitempty"`
	} `yaml:"rate_limit,omitempty"`

	NameTransform string `yaml:"name_transform,omitempty"` // base32 | raw

	Verbs map[string]string `yaml:"verbs,omitempty"` // map docker action -> k8s verb
}

type kubernetesAuthz struct {
	cfg    *KubernetesAuthzConfig
	client *kubernetes.Clientset
}

func (c *KubernetesAuthzConfig) Validate(configKey string) error {
	if c == nil {
		return fmt.Errorf("%s is nil", configKey)
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 5 * time.Second
	}
	if c.APIGroup == "" || c.Resource == "" {
		return fmt.Errorf("%s.api_group and %s.resource are required", configKey, configKey)
	}
	if c.UserLabel == "" {
		c.UserLabel = "k8s_username"
	}
	if c.NameTransform == "" {
		c.NameTransform = "base32"
	}
	if c.Verbs == nil {
		c.Verbs = map[string]string{"pull": "get", "push": "create"}
	}
	return nil
}

func buildRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
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
		return nil, fmt.Errorf("failed to build k8s rest config: %w", err)
	}
	// Apply rate limits to the REST client if explicitly configured; otherwise use client-go defaults
	if c.RateLimit.RPS > 0 && c.RateLimit.Burst > 0 {
		rc.QPS = float32(c.RateLimit.RPS)
		rc.Burst = c.RateLimit.Burst
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	glog.V(1).Infof("Kubernetes authz configured (kubeconfig=%t, group=%s, resource=%s, rest_qps_burst=%v/%d)", c.Kubeconfig != "", c.APIGroup, c.Resource, c.RateLimit.RPS, c.RateLimit.Burst)
	return &kubernetesAuthz{cfg: c, client: cs}, nil
}

func (ka *kubernetesAuthz) Stop() {}

func (ka *kubernetesAuthz) Name() string { return "Kubernetes RBAC" }

func (ka *kubernetesAuthz) Authorize(ai *api.AuthRequestInfo) ([]string, error) {
	if ai.Account != "token" {
		return nil, api.NoMatch
	}
	// Extract subject from labels
	user := ""
	if vals, ok := ai.Labels[ka.cfg.UserLabel]; ok && len(vals) > 0 {
		user = vals[0]
	}
	if user == "" {
		return nil, api.NoMatch
	}
	groups := ai.Labels["groups"]
	extra := map[string]authzv1.ExtraValue{}
	for k, vs := range ai.Labels {
		if k == "k8s_username" || k == "groups" {
			continue
		}
		extra[k] = authzv1.ExtraValue(vs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ka.cfg.RequestTimeout)
	defer cancel()

	allowed := []string{}
	for _, action := range ai.Actions {
		verb, ok := ka.cfg.Verbs[action]
		if !ok {
			continue
		}
		ns, name := ka.deriveNSAndName(ai)
		if verb == "create" {
			// For create, Name is typically empty in SAR
			name = ""
		}
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:   user,
				Groups: groups,
				Extra:  extra,
				ResourceAttributes: &authzv1.ResourceAttributes{
					Group:     ka.cfg.APIGroup,
					Resource:  ka.cfg.Resource,
					Verb:      verb,
					Namespace: ns,
					Name:      name,
				},
			},
		}
		res, err := ka.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
		if err != nil {
			glog.Errorf("Kubernetes SAR error: %v", err)
			return nil, err
		}
		if res.Status.Allowed {
			allowed = append(allowed, action)
		}
	}
	if len(allowed) == 0 {
		return []string{}, nil
	}
	return allowed, nil
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
	if ka.cfg.NameTransform == "base32" {
		enc := base32.StdEncoding.WithPadding(base32.NoPadding)
		name = strings.ToLower(enc.EncodeToString([]byte(ai.Name)))
	}
	return ns, name
}

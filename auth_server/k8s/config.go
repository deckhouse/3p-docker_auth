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

package k8s

import (
	"fmt"
	"os"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	UserLabel        = "k8s-username"
	GroupsLabel      = "k8s-groups"
	ExtraLabelPrefix = "k8s-extra-"
)

// AuthConfig defines configuration for Kubernetes TokenReview authentication.
type AuthConfig struct {
	Kubeconfig string `yaml:"kubeconfig,omitempty"`

	Limits struct {
		QPS            float32       `yaml:"qps,omitempty"`
		Burst          int           `yaml:"burst,omitempty"`
		RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
	} `yaml:"limits,omitempty"`

	// Cache defines TTL (Time To Live) settings for caching authentication and authorization results.
	// If TTL is negative, caching will be disabled for that result type.
	Cache struct {
		// SuccessTTL is the duration to cache successful authentication/authorization results.
		SuccessTTL time.Duration `yaml:"success_ttl,omitempty"`
		// FailureTTL is the duration to cache failed authentication/authorization results.
		FailureTTL time.Duration `yaml:"failure_ttl,omitempty"`
	} `yaml:"cache,omitempty"`

	Authz *AuthzConfig `yaml:"authz,omitempty"`
}

type AuthzConfig struct {
	APIGroup string `yaml:"api_group,omitempty"`
	Resource string `yaml:"resource,omitempty"`
}

func (c AuthzConfig) Validate(configKey string) error {
	err := validation.ValidateStruct(&c,
		validation.Field(&c.APIGroup, validation.Required),
		validation.Field(&c.Resource, validation.Required),
	)

	if err != nil {
		return fmt.Errorf("%v validation error: %w", configKey, err)
	}

	return nil
}

func (c *AuthConfig) Validate(configKey string) error {
	if c.Cache.SuccessTTL == 0 {
		c.Cache.SuccessTTL = 5 * time.Minute
	}
	if c.Cache.FailureTTL == 0 {
		c.Cache.FailureTTL = 30 * time.Second
	}

	return validation.ValidateStruct(c,
		validation.Field(&c.Authz),
	)
}

func (c AuthConfig) BuildRestConfig() (*rest.Config, error) {
	rc, err := c.initRestConfig()
	if err != nil {
		return nil, fmt.Errorf("cannot initialize: %w", err)
	}

	if c.Limits.QPS > 0 {
		rc.QPS = c.Limits.QPS
	}
	if c.Limits.Burst > 0 {
		rc.Burst = c.Limits.Burst
	}

	return rc, nil
}

func (c AuthConfig) initRestConfig() (*rest.Config, error) {
	if c.Kubeconfig != "" {
		if _, statErr := os.Stat(c.Kubeconfig); statErr != nil {
			return nil, fmt.Errorf("kubeconfig not accessible: %w", statErr)
		}
		return clientcmd.BuildConfigFromFlags("", c.Kubeconfig)
	}
	return rest.InClusterConfig()
}

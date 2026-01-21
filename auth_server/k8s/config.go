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

func (c AuthConfig) Validate(configKey string) error {
	return validation.ValidateStruct(&c,
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

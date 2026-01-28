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
	"slices"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/cesanta/glog"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	defaultSuccessTTL    = 5 * time.Minute
	defaultFailureTTL    = 30 * time.Second
	defaultUserName      = "token"
	defaultRequestTimeout = 10 * time.Second
)

// AuthConfig defines configuration for Kubernetes TokenReview authentication.
// The password from `docker login` is treated as a Bearer token and validated
// using Kubernetes TokenReview API. Results can be cached to reduce load on the API server.
type AuthConfig struct {
	// Kubeconfig is the optional path to a kubeconfig file for connecting to the Kubernetes API.
	// If empty or not specified, in-cluster configuration is used (service account token and
	// CA certificate mounted in the pod).
	Kubeconfig string `yaml:"kubeconfig,omitempty"`

	// UserName is the username that must be used for Kubernetes token authentication.
	// Defaults to "token" if not specified.
	// When using Kubernetes auth, the docker login username must match this value,
	// and the password must be a valid Kubernetes bearer token.
	UserName string `yaml:"user_name,omitempty"`

	// Limits defines rate limiting and timeout settings for outgoing Kubernetes API requests.
	Limits struct {
		// QPS is the maximum queries per second for Kubernetes API client throttling.
		// If zero, DefaultQPS: 5 is used.
		// If negative, throttling is disabled.
		// See: https://github.com/kubernetes/client-go/blob/v0.31.14/rest/config.go#L353-L363
		QPS float32 `yaml:"qps,omitempty"`
		// Burst is the maximum burst size for Kubernetes API client throttling.
		// If zero, DefaultBurst: 10 is used.
		// Only relevant when QPS > 0. If QPS < 0, throttling is disabled and Burst is ignored.
		// See: https://github.com/kubernetes/client-go/blob/v0.31.14/rest/config.go#L353-L363
		Burst int `yaml:"burst,omitempty"`
		// RequestTimeout is the timeout duration for individual Kubernetes API requests
		// (e.g., TokenReview, SelfSubjectRulesReview).
		// Defaults to 10 seconds if not specified, zero, or negative.
		RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
	} `yaml:"limits,omitempty"`

	// Cache defines TTL (Time To Live) settings for caching authentication and authorization results.
	// If TTL is 0 or negative, caching will be disabled for that result type.
	Cache struct {
		// SuccessTTL is the duration to cache successful authentication/authorization results.
		// Defaults to 5 minutes if not specified.
		// Setting to 0 disables caching for successful results.
		SuccessTTL time.Duration `yaml:"success_ttl,omitempty"`
		// FailureTTL is the duration to cache failed authentication/authorization results.
		// Defaults to 30 seconds if not specified.
		// Setting to 0 disables caching for failed results.
		FailureTTL time.Duration `yaml:"failure_ttl,omitempty"`
	} `yaml:"cache,omitempty"`

	// Authz is an optional configuration for Kubernetes authorization (RBAC via SelfSubjectRulesReview).
	// When provided, enables authorization checks that map Docker actions (pull/push/delete)
	// to Kubernetes verbs for a custom resource in the specified API group.
	// Supports recursive globbing (e.g., "images/**") in RBAC resourceNames.
	// If nil, Kubernetes authorization will not be enabled.
	Authz *AuthzConfig `yaml:"authz,omitempty"`
}

// AuthzConfig defines configuration for Kubernetes authorization using SelfSubjectRulesReview.
// It specifies the API group and resource name to check when authorizing Docker registry actions.
// The authorization process maps Docker actions (pull->get, push->create, delete->delete) to
// Kubernetes verbs and checks if the authenticated user has the required permissions for the
// specified API group and resource.
type AuthzConfig struct {
	// APIGroup is the Kubernetes API group for the custom resource used in authorization checks.
	// This is used to filter ResourceRules when checking permissions via SelfSubjectRulesReview.
	// Examples: "registry.example.com", "apps", "extensions".
	// Required field.
	APIGroup string `yaml:"api_group,omitempty"`
	// Resource is the Kubernetes resource name (plural form) used in authorization checks.
	// This is used to filter ResourceRules when checking permissions via SelfSubjectRulesReview.
	// The resource name should match the resource defined in your Kubernetes RBAC rules.
	// Examples: "registries", "deployments", "pods".
	// Required field.
	Resource string `yaml:"resource,omitempty"`
}

// Validate validates the AuthzConfig fields to ensure required values are set.
// It checks that the following fields are non-empty:
//   - APIGroup: Kubernetes API group for the custom resource
//   - Resource: Kubernetes resource name (plural form)
//
// Returns an error if validation fails, with the error message prefixed by configKey.
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

// matchRule checks if a single ResourceRule matches the verb, API group, resource, and resource path.
// It performs case-insensitive matching for API groups and resources.
func (c *AuthzConfig) matchRule(rule authorizationv1.ResourceRule, verb string, resourcePath string) bool {
	if !slices.Contains(rule.Verbs, verb) && !slices.Contains(rule.Verbs, "*") {
		return false
	}

	apiGroupMatch := false
	for _, apiGroup := range rule.APIGroups {
		if apiGroup == "*" || strings.EqualFold(apiGroup, c.APIGroup) {
			apiGroupMatch = true
			break
		}
	}

	if !apiGroupMatch {
		return false
	}

	resourceMatch := false
	for _, resource := range rule.Resources {
		if resource == "*" || strings.EqualFold(resource, c.Resource) {
			resourceMatch = true
			break
		}
	}

	if !resourceMatch {
		return false
	}

	if len(rule.ResourceNames) == 0 {
		return true
	}

	for _, pattern := range rule.ResourceNames {
		lp := strings.ToLower(pattern)
		if matched, err := doublestar.Match(lp, resourcePath); matched {
			return true
		} else if err != nil {
			glog.Warningf("Error matching pattern %q for path %q: %v", pattern, resourcePath, err)
		}
	}

	return false
}

// IsActionAllowed checks if the verb is allowed for the resource path using doublestar matching.
// Pattern matching uses github.com/bmatcuk/doublestar/v4 for recursive glob support (**).
func (c *AuthzConfig) IsActionAllowed(rules []authorizationv1.ResourceRule, verb string, resourcePath string) bool {
	if resourcePath == "" {
		return false
	}

	for _, rule := range rules {
		if c.matchRule(rule, verb, strings.ToLower(resourcePath)) {
			return true
		}
	}

	return false
}

// Validate validates the AuthConfig and sets default values for optional fields.
// Default values are set if not specified:
//   - Cache.SuccessTTL: 5 minutes
//   - Cache.FailureTTL: 30 seconds
//   - UserName: "token"
//   - Limits.RequestTimeout: 10 seconds
//
// Also validates the nested Authz configuration if present.
func (c *AuthConfig) Validate(configKey string) error {
	if c.Cache.SuccessTTL == 0 {
		c.Cache.SuccessTTL = defaultSuccessTTL
	}

	if c.Cache.FailureTTL == 0 {
		c.Cache.FailureTTL = defaultFailureTTL
	}

	if c.UserName == "" {
		c.UserName = defaultUserName
	}

	if c.Limits.RequestTimeout <= 0 {
		c.Limits.RequestTimeout = defaultRequestTimeout
	}

	return validation.ValidateStruct(c,
		validation.Field(&c.Authz),
	)
}

// BuildRestConfig creates and configures a Kubernetes REST client configuration.
// It initializes the config from kubeconfig file (if specified) or in-cluster configuration,
// and applies QPS and Burst rate limiting settings from the AuthConfig.
// Returns the configured rest.Config or an error if initialization fails.
func (c AuthConfig) BuildRestConfig() (*rest.Config, error) {
	rc, err := c.initRestConfig()
	if err != nil {
		return nil, fmt.Errorf("cannot initialize: %w", err)
	}

	rc.QPS = c.Limits.QPS
	rc.Burst = c.Limits.Burst

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

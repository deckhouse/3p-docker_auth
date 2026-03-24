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
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	defaultSuccessTTL     = 1 * time.Minute
	defaultFailureTTL     = 30 * time.Second
	defaultUserName       = "token"
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
	UserName string `yaml:"username,omitempty"`

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
		// Defaults to 1 minute if not specified.
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
	// NamespaceCheckVerbs are Docker actions (e.g. "push", "delete") for which namespace existence is checked before authorization.
	// If empty or nil, namespace existence is not checked. When non-empty, the check runs only when the request includes at least one of these actions.
	NamespaceCheckVerbs []string `yaml:"namespace_check_verbs,omitempty"`
}

// NeedsNamespaceCheck returns true when namespace existence should be checked for the given Docker actions.
// This is the case when NamespaceCheckVerbs is non-empty and at least one of actions is in that list.
func (c *AuthzConfig) NeedsNamespaceCheck(actions []string) bool {
	if len(c.NamespaceCheckVerbs) == 0 {
		return false
	}

	for _, a := range actions {
		if slices.Contains(c.NamespaceCheckVerbs, a) {
			return true
		}
	}

	return false
}

// Validate validates the AuthzConfig fields to ensure required values are set.
// It checks that the following fields are non-empty:
//   - APIGroup: Kubernetes API group for the custom resource
//   - Resource: Kubernetes resource name (plural form)
//
// Returns an error if validation fails, with the error message prefixed by configKey.
func (c AuthzConfig) Validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.APIGroup, validation.Required),
		validation.Field(&c.Resource, validation.Required),
	)
}

// FilterRules returns rules that match the given API group and resource.
// It performs case-insensitive matching for API groups and resources.
func (c *AuthzConfig) FilterRules(rules Rules) Rules {
	var out Rules
	for _, rule := range rules {
		apiGroupMatch := false
		for _, apiGroup := range rule.APIGroups {
			if apiGroup == "*" || strings.EqualFold(apiGroup, c.APIGroup) {
				apiGroupMatch = true
				break
			}
		}
		if !apiGroupMatch {
			continue
		}

		resourceMatch := false
		for _, resource := range rule.Resources {
			if resource == "*" || strings.EqualFold(resource, c.Resource) {
				resourceMatch = true
				break
			}
		}
		if !resourceMatch {
			continue
		}

		out = append(out, rule)
	}
	return out
}

// ApplyDefaults sets default values for optional AuthConfig fields in place.
// Defaults applied:
//   - Cache.SuccessTTL: 1 minute
//   - Cache.FailureTTL: 30 seconds
//   - UserName: "token"
//   - Limits.RequestTimeout: 10 seconds
func ApplyDefaults(c *AuthConfig) {
	if c == nil {
		return
	}

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
}

// Validate validates the AuthConfig and the nested Authz configuration if present.
func (c AuthConfig) Validate(configKey string) error {
	err := validation.ValidateStruct(&c,
		validation.Field(&c.Authz),
	)

	var vErr validation.Errors

	if err != nil {
		if errors.As(err, &vErr) {
			rErr := make(validation.Errors)

			for name, err := range vErr {
				name = configKey + "." + name
				rErr[name] = err
			}

			return rErr
		}

		return fmt.Errorf("%v validation error: %w", configKey, err)
	}

	return nil
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

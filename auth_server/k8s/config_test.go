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
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestAuthzConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AuthzConfig
		wantErr bool
	}{
		{
			name: "valid",
			cfg: AuthzConfig{
				APIGroup: "registry.example.com",
				Resource: "repositories",
			},
			wantErr: false,
		},
		{
			name: "missing APIGroup",
			cfg: AuthzConfig{
				APIGroup: "",
				Resource: "repositories",
			},
			wantErr: true,
		},
		{
			name: "missing Resource",
			cfg: AuthzConfig{
				APIGroup: "registry.example.com",
				Resource: "",
			},
			wantErr: true,
		},
		{
			name:    "both missing",
			cfg:     AuthzConfig{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate("authz")
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthzConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthzConfig_NeedsNamespaceCheck(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *AuthzConfig
		actions []string
		want    bool
	}{
		{
			name: "empty NamespaceCheckVerbs",
			cfg: &AuthzConfig{
				NamespaceCheckVerbs: []string{},
			},
			actions: []string{"push", "delete"},
			want:    false,
		},
		{
			name: "nil NamespaceCheckVerbs",
			cfg: &AuthzConfig{
				NamespaceCheckVerbs: nil,
			},
			actions: []string{"push"},
			want:    false,
		},
		{
			name: "action in list",
			cfg: &AuthzConfig{
				NamespaceCheckVerbs: []string{"push", "delete"},
			},
			actions: []string{"pull", "push"},
			want:    true,
		},
		{
			name: "action not in list",
			cfg: &AuthzConfig{
				NamespaceCheckVerbs: []string{"push", "delete"},
			},
			actions: []string{"pull"},
			want:    false,
		},
		{
			name: "empty actions",
			cfg: &AuthzConfig{
				NamespaceCheckVerbs: []string{"push"},
			},
			actions: []string{},
			want:    false,
		},
		{
			name: "single verb match",
			cfg: &AuthzConfig{
				NamespaceCheckVerbs: []string{"delete"},
			},
			actions: []string{"delete"},
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.NeedsNamespaceCheck(tt.actions)
			if got != tt.want {
				t.Errorf("NeedsNamespaceCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthzConfig_FilterRules(t *testing.T) {
	ruleRegistryRepos := authorizationv1.ResourceRule{
		Verbs:         []string{"get"},
		APIGroups:     []string{"registry.example.com"},
		Resources:     []string{"repositories"},
		ResourceNames: []string{},
	}
	ruleOtherGroup := authorizationv1.ResourceRule{
		Verbs:         []string{"get"},
		APIGroups:     []string{"other.example.com"},
		Resources:     []string{"repositories"},
		ResourceNames: []string{},
	}
	ruleOtherResource := authorizationv1.ResourceRule{
		Verbs:         []string{"get"},
		APIGroups:     []string{"registry.example.com"},
		Resources:     []string{"images"},
		ResourceNames: []string{},
	}
	ruleWildcardGroup := authorizationv1.ResourceRule{
		Verbs:         []string{"get"},
		APIGroups:     []string{"*"},
		Resources:     []string{"repositories"},
		ResourceNames: []string{},
	}
	ruleWildcardResource := authorizationv1.ResourceRule{
		Verbs:         []string{"get"},
		APIGroups:     []string{"registry.example.com"},
		Resources:     []string{"*"},
		ResourceNames: []string{},
	}
	ruleMultipleVerbs := authorizationv1.ResourceRule{
		Verbs:         []string{"get", "create", "delete"},
		APIGroups:     []string{"registry.example.com"},
		Resources:     []string{"repositories"},
		ResourceNames: []string{},
	}

	tests := []struct {
		name     string
		cfg      *AuthzConfig
		rules    Rules
		wantLen  int
		wantAPIG string
	}{
		{
			name:     "match API group and resource",
			cfg:      &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules:    Rules{ruleRegistryRepos},
			wantLen:  1,
			wantAPIG: "registry.example.com",
		},
		{
			name:    "filter out different API group",
			cfg:     &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules:   Rules{ruleOtherGroup},
			wantLen: 0,
		},
		{
			name:    "filter out different resource",
			cfg:     &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules:   Rules{ruleOtherResource},
			wantLen: 0,
		},
		{
			name:     "wildcard API group matches",
			cfg:      &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules:    Rules{ruleWildcardGroup},
			wantLen:  1,
			wantAPIG: "*",
		},
		{
			name:     "wildcard resource matches",
			cfg:      &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules:    Rules{ruleWildcardResource},
			wantLen:  1,
		},
		{
			name: "case-insensitive API group in config",
			cfg:  &AuthzConfig{APIGroup: "REGISTRY.EXAMPLE.COM", Resource: "repositories"},
			rules: Rules{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"registry.example.com"},
					Resources: []string{"repositories"},
				},
			},
			wantLen:  1,
			wantAPIG: "registry.example.com",
		},
		{
			name: "case-insensitive resource in config",
			cfg:  &AuthzConfig{APIGroup: "registry.example.com", Resource: "REPOSITORIES"},
			rules: Rules{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{"registry.example.com"},
					Resources: []string{"repositories"},
				},
			},
			wantLen: 1,
		},
		{
			name: "multiple rules - only matching kept",
			cfg:  &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules: Rules{ruleOtherGroup, ruleRegistryRepos, ruleOtherResource},
			wantLen: 1,
		},
		{
			name:    "empty rules",
			cfg:     &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules:   Rules{},
			wantLen: 0,
		},
		{
			name:     "rule with multiple verbs - kept when group and resource match",
			cfg:      &AuthzConfig{APIGroup: "registry.example.com", Resource: "repositories"},
			rules:    Rules{ruleMultipleVerbs},
			wantLen:  1,
			wantAPIG: "registry.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.FilterRules(tt.rules)
			if len(got) != tt.wantLen {
				t.Errorf("FilterRules() len = %v, want %v", len(got), tt.wantLen)
			}
			if tt.wantAPIG != "" && len(got) > 0 {
				if len(got[0].APIGroups) == 0 || got[0].APIGroups[0] != tt.wantAPIG {
					t.Errorf("FilterRules() first rule APIGroups = %v", got[0].APIGroups)
				}
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	c := &AuthConfig{}
	ApplyDefaults(c)
	if c.Cache.SuccessTTL != defaultSuccessTTL {
		t.Errorf("SuccessTTL = %v, want %v", c.Cache.SuccessTTL, defaultSuccessTTL)
	}
	if c.Cache.FailureTTL != defaultFailureTTL {
		t.Errorf("FailureTTL = %v, want %v", c.Cache.FailureTTL, defaultFailureTTL)
	}
	if c.UserName != defaultUserName {
		t.Errorf("UserName = %q, want %q", c.UserName, defaultUserName)
	}
	if c.Limits.RequestTimeout != defaultRequestTimeout {
		t.Errorf("RequestTimeout = %v, want %v", c.Limits.RequestTimeout, defaultRequestTimeout)
	}
	// ApplyDefaults is idempotent and does not overwrite non-zero values
	ApplyDefaults(c)
	if c.Cache.SuccessTTL != defaultSuccessTTL || c.UserName != defaultUserName {
		t.Error("ApplyDefaults overwrote existing values")
	}
}

func TestAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name          string
		cfg           *AuthConfig
		applyDefaults bool
		check         func(t *testing.T, c *AuthConfig)
		wantErr       bool
	}{
		{
			name:          "sets defaults when zero",
			cfg:           &AuthConfig{},
			applyDefaults: true,
			check: func(t *testing.T, c *AuthConfig) {
				if c.Cache.SuccessTTL != defaultSuccessTTL {
					t.Errorf("SuccessTTL = %v, want %v", c.Cache.SuccessTTL, defaultSuccessTTL)
				}
				if c.Cache.FailureTTL != defaultFailureTTL {
					t.Errorf("FailureTTL = %v, want %v", c.Cache.FailureTTL, defaultFailureTTL)
				}
				if c.UserName != defaultUserName {
					t.Errorf("UserName = %q, want %q", c.UserName, defaultUserName)
				}
				if c.Limits.RequestTimeout != defaultRequestTimeout {
					t.Errorf("RequestTimeout = %v, want %v", c.Limits.RequestTimeout, defaultRequestTimeout)
				}
			},
			wantErr: false,
		},
		{
			name:          "preserves non-zero values",
			applyDefaults: false,
			cfg: &AuthConfig{
				UserName: "custom",
				Cache: struct {
					SuccessTTL time.Duration `yaml:"success_ttl,omitempty"`
					FailureTTL time.Duration `yaml:"failure_ttl,omitempty"`
				}{
					SuccessTTL: 2 * time.Minute,
					FailureTTL:  1 * time.Minute,
				},
				Limits: struct {
					QPS            float32       `yaml:"qps,omitempty"`
					Burst          int           `yaml:"burst,omitempty"`
					RequestTimeout time.Duration `yaml:"request_timeout,omitempty"`
				}{
					RequestTimeout: 5 * time.Second,
				},
			},
			check: func(t *testing.T, c *AuthConfig) {
				if c.UserName != "custom" {
					t.Errorf("UserName = %q, want custom", c.UserName)
				}
				if c.Cache.SuccessTTL != 2*time.Minute {
					t.Errorf("SuccessTTL = %v", c.Cache.SuccessTTL)
				}
				if c.Limits.RequestTimeout != 5*time.Second {
					t.Errorf("RequestTimeout = %v", c.Limits.RequestTimeout)
				}
			},
			wantErr: false,
		},
		{
			name:          "valid with Authz",
			applyDefaults: false,
			cfg: &AuthConfig{
				Authz: &AuthzConfig{
					APIGroup: "registry.example.com",
					Resource: "repositories",
				},
			},
			check:   nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.applyDefaults {
				ApplyDefaults(tt.cfg)
			}
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.check != nil && err == nil {
				tt.check(t, tt.cfg)
			}
		})
	}
}

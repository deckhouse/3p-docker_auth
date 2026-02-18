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

	authorizationv1 "k8s.io/api/authorization/v1"
)

func TestRules_IsActionAllowed(t *testing.T) {
	tests := []struct {
		name         string
		rules        []authorizationv1.ResourceRule
		verb         string
		resourcePath string
		want         bool
	}{
		{
			name:         "empty rules",
			rules:        []authorizationv1.ResourceRule{},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         false,
		},
		{
			name: "empty resource path",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
			},
			verb:         "get",
			resourcePath: "",
			want:         false,
		},
		{
			name: "verb match with empty resource names",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "verb mismatch",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"create"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         false,
		},
		{
			name: "rule with multiple verbs - requested verb in list",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get", "create", "delete"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
			},
			verb:         "create",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "rule with multiple verbs - requested verb not in list",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get", "create"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
			},
			verb:         "delete",
			resourcePath: "foo/bar",
			want:         false,
		},
		{
			name: "rule with multiple verbs - first verb matches",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get", "create", "delete"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "rule with multiple verbs - last verb matches",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get", "create", "delete"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar"},
				},
			},
			verb:         "delete",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "verb wildcard match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"*"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "exact resource name match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "resource name mismatch",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/baz"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         false,
		},
		{
			name: "wildcard pattern match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/*"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "wildcard pattern no match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/*"},
				},
			},
			verb:         "get",
			resourcePath: "baz/bar",
			want:         false,
		},
		{
			name: "doublestar recursive pattern match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/**"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar/baz/qux",
			want:         true,
		},
		{
			name: "doublestar recursive pattern no match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/**"},
				},
			},
			verb:         "get",
			resourcePath: "bar/foo/baz",
			want:         false,
		},
		{
			name: "multiple resource names - first matches",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar", "baz/qux"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "multiple resource names - second matches",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar", "baz/qux"},
				},
			},
			verb:         "get",
			resourcePath: "baz/qux",
			want:         true,
		},
		{
			name: "multiple resource names - none match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar", "baz/qux"},
				},
			},
			verb:         "get",
			resourcePath: "other/path",
			want:         false,
		},
		{
			name: "multiple rules - first matches",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"create"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "multiple rules - none match",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"create"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{},
				},
				{
					Verbs:         []string{"delete"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         false,
		},
		{
			name: "complex pattern with multiple wildcards",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"team-*/**"},
				},
			},
			verb:         "get",
			resourcePath: "team-frontend/apps/web",
			want:         true,
		},
		{
			name: "case-insensitive resourcePath - uppercase",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar"},
				},
			},
			verb:         "get",
			resourcePath: "FOO/BAR",
			want:         true,
		},
		{
			name: "case-insensitive resourcePath - mixed case",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"foo/bar"},
				},
			},
			verb:         "get",
			resourcePath: "FoO/BaR",
			want:         true,
		},
		{
			name: "case-insensitive pattern - uppercase pattern",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"FOO/BAR"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "case-insensitive pattern - mixed case pattern",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"FoO/BaR"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "case-insensitive pattern with wildcard - uppercase",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"FOO/*"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar",
			want:         true,
		},
		{
			name: "case-insensitive doublestar pattern - uppercase",
			rules: []authorizationv1.ResourceRule{
				{
					Verbs:         []string{"get"},
					APIGroups:     []string{"registry.example.com"},
					Resources:     []string{"repositories"},
					ResourceNames: []string{"FOO/**"},
				},
			},
			verb:         "get",
			resourcePath: "foo/bar/baz",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Rules(tt.rules).IsActionAllowed(tt.verb, tt.resourcePath)
			if got != tt.want {
				t.Errorf("Rules.IsActionAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

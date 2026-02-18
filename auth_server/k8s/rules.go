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
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/cesanta/glog"
	authorizationv1 "k8s.io/api/authorization/v1"
)

// Rules is the result of fetching rules for a user in a namespace (e.g. from SelfSubjectRulesReview).
type Rules []authorizationv1.ResourceRule

// IsActionAllowed checks if the verb is allowed for the resource path using doublestar matching.
// Pattern matching uses github.com/bmatcuk/doublestar/v4 for recursive glob support (**).
func (r Rules) IsActionAllowed(verb string, resourcePath string) bool {
	if resourcePath == "" || len(r) == 0 {
		return false
	}

	resourcePath = strings.ToLower(resourcePath)
	for _, rule := range r {
		if matchRule(rule, verb, resourcePath) {
			return true
		}
	}

	return false
}

// matchRule checks if a single ResourceRule matches the verb and the resource path (ResourceNames with doublestar).
func matchRule(rule authorizationv1.ResourceRule, verb string, resourcePath string) bool {
	if !slices.Contains(rule.Verbs, verb) && !slices.Contains(rule.Verbs, "*") {
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

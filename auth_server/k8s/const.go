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

import "time"

const (
	UserLabel        = "k8s-username"
	GroupsLabel      = "k8s-groups"
	ExtraLabelPrefix = "k8s-extra-"

	// DefaultCacheSize is the default size for the LRU cache used in Kubernetes authorization.
	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/plugin/pkg/authorizer/webhook/webhook.go#L130
	DefaultCacheSize = 8192

	// DefaultRequestTimeout is the default timeout for Kubernetes API requests.
	DefaultRequestTimeout = 10 * time.Second

	// DefaultBackoffInitialDelay is the default initial delay for exponential backoff retries.
	// Ref: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/pkg/util/webhook/webhook.go#L42
	DefaultBackoffInitialDelay = 500 * time.Millisecond
)

// verbsMap maps Docker actions to Kubernetes verbs (standard for Docker Registry).
var verbsMap = map[string]string{
	"pull":   "get",
	"push":   "create",
	"delete": "delete",
}

// GetK8sVerb returns the Kubernetes verb for the given Docker action.
// It returns the verb and a boolean indicating whether the action was found.
func GetK8sVerb(dockerAction string) (string, bool) {
	verb, ok := verbsMap[dockerAction]
	return verb, ok
}

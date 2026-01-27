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

import "strings"

// SplitNamespaceAndPath splits a repository name into namespace and relative path.
// The format is "namespace/path" where namespace is required and path is optional.
//
// Returns:
//   - ns: the namespace part (always present, even if empty)
//   - relativePath: the relative path part (empty if not present in the input)
func SplitNamespaceAndPath(name string) (ns string, relativePath string) {
	parts := strings.SplitN(name, "/", 2)

	ns = parts[0]
	if len(parts) == 2 {
		relativePath = parts[1]
	}

	return ns, relativePath
}

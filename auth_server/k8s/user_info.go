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

import "github.com/cesanta/docker_auth/auth_server/api"

// UserInfo represents Kubernetes user information from authenticator.Response.User.
// It mirrors the structure of k8s.io/apiserver/pkg/authentication/user.Info.
type UserInfo struct {
	Name        string
	UID         string
	Groups      []string
	BearerToken string
}

// IsValid reports whether UserInfo has the fields required for Kubernetes authorization
// and rules fetching (username, uid, and bearer token).
func (u *UserInfo) IsValid() bool {
	return u.Name != "" && u.UID != "" && u.BearerToken != ""
}

// ToLabels converts UserInfo to api.Labels format.
// It uses the label constants defined in this package:
// - UserLabel ("username") and UIDLabel ("uid") from TokenReview user
// - "groups" for group membership (same as other auth methods)
func (u *UserInfo) ToLabels() api.Labels {
	labels := api.Labels{}

	if u.Name != "" {
		labels[UserLabel] = []string{u.Name}
	}

	if u.UID != "" {
		labels[UIDLabel] = []string{u.UID}
	}

	if len(u.Groups) > 0 {
		labels["groups"] = u.Groups
	}

	return labels
}

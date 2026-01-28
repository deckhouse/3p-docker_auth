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
	"strings"

	"github.com/cesanta/docker_auth/auth_server/api"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
)

// UserInfo represents Kubernetes user information from authenticator.Response.User.
// It mirrors the structure of k8s.io/apiserver/pkg/authentication/user.Info.
type UserInfo struct {
	Name   string
	UID    string
	Groups []string
	Extra  map[string][]string
}

// ToLabels converts UserInfo to api.Labels format.
// It uses the label constants defined in this package:
// - UserLabel for the username
// - UIDLabel for the UID
// - GroupsLabel for groups
// - ExtraLabelPrefix for extra fields
func (u *UserInfo) ToLabels() api.Labels {
	labels := api.Labels{}

	if u.Name != "" {
		labels[UserLabel] = []string{u.Name}
	}

	if u.UID != "" {
		labels[UIDLabel] = []string{u.UID}
	}

	if len(u.Groups) > 0 {
		labels[GroupsLabel] = u.Groups
	}

	if u.Extra != nil {
		for k, v := range u.Extra {
			if len(v) > 0 {
				key := ExtraLabelPrefix + k
				labels[key] = v
			}
		}
	}

	return labels
}

// UserInfoFromLabels creates a UserInfo from api.Labels.
// It extracts the username, UID, groups, and extra fields from the labels.
func UserInfoFromLabels(labels api.Labels) *UserInfo {
	u := &UserInfo{
		Name:   "",
		UID:    "",
		Groups: nil,
		Extra:  make(map[string][]string),
	}

	for k, vs := range labels {
		switch {
		case k == UserLabel:
			if len(vs) > 0 {
				u.Name = vs[0]
			}
		case k == UIDLabel:
			if len(vs) > 0 {
				u.UID = vs[0]
			}
		case k == GroupsLabel:
			if len(vs) > 0 {
				u.Groups = vs
			}
		case strings.HasPrefix(k, ExtraLabelPrefix):
			extraKey := strings.TrimPrefix(k, ExtraLabelPrefix)
			if len(vs) > 0 {
				u.Extra[extraKey] = vs
			}
		}
	}

	return u
}

// UserInfoFromUser creates a UserInfo from a user.Info interface.
// It extracts the username, UID, groups, and extra fields from the user.Info.
func UserInfoFromUser(userInfo user.Info) *UserInfo {
	u := &UserInfo{}

	if userInfo == nil {
		u.Name = ""
		u.UID = ""
		u.Groups = nil
		u.Extra = make(map[string][]string)
		return u
	}

	u.Name = userInfo.GetName()
	u.UID = userInfo.GetUID()
	u.Groups = userInfo.GetGroups()
	u.Extra = userInfo.GetExtra()
	if u.Extra == nil {
		u.Extra = make(map[string][]string)
	}

	return u
}

// ToImpersonationConfig converts UserInfo to rest.ImpersonationConfig.
// This can be used to configure a Kubernetes REST client to impersonate the user.
func (u *UserInfo) ToImpersonationConfig() rest.ImpersonationConfig {
	return rest.ImpersonationConfig{
		UserName: u.Name,
		UID:      u.UID,
		Groups:   u.Groups,
		Extra:    u.Extra,
	}
}

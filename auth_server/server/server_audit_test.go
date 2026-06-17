/*
   Copyright 2026 Flant JSC

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

package server

import (
	"testing"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/k8s"
)

func TestAuditSubject(t *testing.T) {
	tests := []struct {
		name string
		ar   authRequest
		want string
	}{
		{
			name: "kubernetes identity from username label",
			ar:   authRequest{Account: "token", Labels: api.Labels{k8s.UserLabel: {"system:serviceaccount:test:ci-robot"}}},
			want: "system:serviceaccount:test:ci-robot",
		},
		{
			name: "kubernetes user identity",
			ar:   authRequest{Account: "token", Labels: api.Labels{k8s.UserLabel: {"max@flant.com"}}},
			want: "max@flant.com",
		},
		{
			name: "no username label falls back to account",
			ar:   authRequest{Account: "static-user"},
			want: "static-user",
		},
		{
			name: "empty username label falls back to account",
			ar:   authRequest{Account: "token", Labels: api.Labels{k8s.UserLabel: {}}},
			want: "token",
		},
		{
			name: "blank username value falls back to account",
			ar:   authRequest{Account: "token", Labels: api.Labels{k8s.UserLabel: {""}}},
			want: "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ar.auditSubject(); got != tt.want {
				t.Errorf("auditSubject() = %q, want %q", got, tt.want)
			}
		})
	}
}

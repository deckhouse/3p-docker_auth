/*
   Copyright 2019 Cesanta Software Ltd.

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

package api

import "errors"

type Labels map[string][]string

// Authentication plugin interface.
type Authenticator interface {
	// Given a user name and a password (plain text), responds with the result or an error.
	// Error should only be reported if request could not be serviced, not if it should be denied.
	// A special NoMatch error is returned if the authorizer could not reach a decision,
	// e.g. none of the rules matched.
	// Another special WrongPass error is returned if the authorizer failed to authenticate.
	// Implementations must be goroutine-safe.
	Authenticate(user string, password PasswordString) (bool, Labels, error)

	// Finalize resources in preparation for shutdown.
	// When this call is made there are guaranteed to be no Authenticate requests in flight
	// and there will be no more calls made to this instance.
	Stop()

	// Human-readable name of the authenticator.
	Name() string
}

var NoMatch = errors.New("did not match any rule")

// AuthFailed indicates authentication failed. It wraps an underlying error whose
// message is included in Error() and shown in HTTP responses.
type AuthFailed struct {
	Err error
}

func (e *AuthFailed) Error() string {
	if e.Err != nil {
		return "Auth failed: " + e.Err.Error()
	}
	return "Auth failed"
}

func (e *AuthFailed) Unwrap() error { return e.Err }

// NewAuthFailed returns an AuthFailed wrapping cause.
func NewAuthFailed(cause error) error {
	return &AuthFailed{Err: cause}
}

// WrongPass is an AuthFailed for wrong password. Use this or NewAuthFailed for auth failures.
var WrongPass = NewAuthFailed(errors.New("wrong password for user"))

type PasswordString string

func (ps PasswordString) String() string {
	if len(ps) == 0 {
		return ""
	}
	return "***"
}

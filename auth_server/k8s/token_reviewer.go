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
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/util/webhook"
	webhookauthn "k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// ErrTokenNotAuthenticated is returned by the token authenticator's AuthenticateToken when
// the token was rejected (TokenReview.Status.Authenticated is false). Use errors.Is(err, ErrTokenNotAuthenticated)
// to distinguish this from other errors (e.g. network or API failures).
// When TokenReview.Status.Error is set, the returned error wraps ErrTokenNotAuthenticated and preserves the status message.
var ErrTokenNotAuthenticated = errors.New("token not authenticated")

// TokenReviewer is the interface for creating TokenReview requests.
// Implementations are used by the webhook token authenticator to call the Kubernetes TokenReview API.
type TokenReviewer interface {
	Create(ctx context.Context, review *authenticationv1.TokenReview, _ metav1.CreateOptions) (*authenticationv1.TokenReview, int, error)
}

var _ authenticator.Token = (*tokenReviewer)(nil)
var _ TokenReviewer = (*tokenReviewer)(nil)


// tokenReviewer implements authenticator.Token by calling the Kubernetes
// TokenReview API. It is a fork of the upstream WebhookTokenAuthenticator so that
// AuthenticateToken returns ErrTokenNotAuthenticated when the token is rejected, allowing
// callers to distinguish authentication failure from transient errors.
type tokenReviewer struct {
	client         rest.Interface
	retryBackoff   wait.Backoff
	implicitAuds   authenticator.Audiences
	requestTimeout time.Duration
	metrics        webhookauthn.AuthenticatorMetrics
}

// Create implements TokenReviewer.
func (w *tokenReviewer) Create(ctx context.Context, tokenReview *authenticationv1.TokenReview, opts metav1.CreateOptions) (*authenticationv1.TokenReview, int, error) {
	result := &authenticationv1.TokenReview{}

	restResult := w.client.Post().
		Resource("tokenreviews").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(tokenReview).
		Do(ctx)

	var statusCode int
	restResult.StatusCode(&statusCode)
	err := restResult.Into(result)

	return result, statusCode, err
}

// NewTokenReviewer creates a webhook token authenticator using the given AuthenticationV1
// client. It returns the authenticator.Token interface.
//
// Original: https://github.com/kubernetes/kubernetes/blob/release-1.31/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/webhook/webhook.go
func NewTokenReviewer(
	tokenReview authenticationv1client.AuthenticationV1Interface,
	implicitAuds authenticator.Audiences,
	retryBackoff wait.Backoff,
	requestTimeout time.Duration,
	metrics webhookauthn.AuthenticatorMetrics,
) (authenticator.Token, error) {
	w := &tokenReviewer{
		client:         tokenReview.RESTClient(),
		retryBackoff:   retryBackoff,
		implicitAuds:   implicitAuds,
		requestTimeout: requestTimeout,
		metrics:        metrics,
	}

	return w, nil
}

// AuthenticateToken implements authenticator.Token. It returns (nil, false, err) where err
// is ErrTokenNotAuthenticated (or wraps it with TokenReview.Status.Error when set) when the token
// was rejected, and (nil, false, err) for other errors (e.g. network failure, timeout).
// Callers can use errors.Is(err, ErrTokenNotAuthenticated) to tell "user not authenticated" from "other error".
func (w *tokenReviewer) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	wantAuds, checkAuds := authenticator.AudiencesFrom(ctx)

	r := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: wantAuds,
		},
	}

	var (
		result *authenticationv1.TokenReview
		auds   authenticator.Audiences
		cancel context.CancelFunc
	)

	if w.requestTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, w.requestTimeout)
		defer cancel()
	}

	if err := webhook.WithExponentialBackoff(ctx, w.retryBackoff, func() error {
		var tokenReviewErr error
		var statusCode int

		start := time.Now()
		result, statusCode, tokenReviewErr = w.Create(ctx, r, metav1.CreateOptions{})
		latency := time.Since(start)

		if statusCode != 0 {
			w.metrics.RecordRequestTotal(ctx, strconv.Itoa(statusCode))
			w.metrics.RecordRequestLatency(ctx, strconv.Itoa(statusCode), latency.Seconds())
			return tokenReviewErr
		}

		if tokenReviewErr != nil {
			w.metrics.RecordRequestTotal(ctx, " ")
			w.metrics.RecordRequestLatency(ctx, " ", latency.Seconds())
		}

		return tokenReviewErr
	}, webhook.DefaultShouldRetry); err != nil {
		return nil, false, err
	}

	if checkAuds {
		gotAuds := w.implicitAuds
		if len(result.Status.Audiences) > 0 {
			gotAuds = result.Status.Audiences
		}
		auds = wantAuds.Intersect(gotAuds)
		if len(auds) == 0 {
			return nil, false, ErrTokenNotAuthenticated
		}
	}

	if !result.Status.Authenticated {
		if len(result.Status.Error) != 0 {
			return nil, false, fmt.Errorf("%w: %s", ErrTokenNotAuthenticated, result.Status.Error)
		}

		return nil, false, ErrTokenNotAuthenticated
	}

	var extra map[string][]string
	if result.Status.User.Extra != nil {
		extra = make(map[string][]string, len(result.Status.User.Extra))
		for k, v := range result.Status.User.Extra {
			extra[k] = v
		}
	}

	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   result.Status.User.Username,
			UID:    result.Status.User.UID,
			Groups: result.Status.User.Groups,
			Extra:  extra,
		},
		Audiences: auds,
	}, true, nil
}

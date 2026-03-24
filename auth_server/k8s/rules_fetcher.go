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
	"time"

	"golang.org/x/sync/singleflight"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/util/webhook"
	webhookauthn "k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
)

// RulesFetcherMetrics holds Prometheus metrics for the rules fetcher.
// When provided to NewRulesFetcher, all fields must be set or none (pass nil to disable metrics).
type RulesFetcherMetrics struct {
	RequestsTotal  *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
}

// RulesFilterFunc filters a list of rules (e.g. by API group and resource).
type RulesFilterFunc func(rules Rules) Rules

// ErrRulesInitError is returned when rules fetch initialization fails (e.g. empty bearer token
// or invalid client config). CachedRulesFetcher does not cache this error.
var ErrRulesInitError = errors.New("rules fetcher initialization failed")

// RulesFetcher fetches resource rules.
type RulesFetcher interface {
	GetRules(userInfo UserInfo, ns string) (Rules, error)
}

// rulesFetcher fetches rules via SelfSubjectRulesReview with retry and metrics.
type rulesFetcher struct {
	requestTimeout time.Duration
	restConfig     *rest.Config
	metrics        *RulesFetcherMetrics
	rulesFilter    RulesFilterFunc
}

// NewRulesFetcher creates a RulesFetcher that calls Kubernetes SelfSubjectRulesReview.
// restConfig must be non-nil; requestTimeout must be positive; if metrics is non-nil, all its fields must be set.
// rulesFilter is optional; when non-nil, it is applied to the fetched rules before returning.
func NewRulesFetcher(requestTimeout time.Duration, restConfig *rest.Config, metrics *RulesFetcherMetrics, rulesFilter RulesFilterFunc) (RulesFetcher, error) {
	if restConfig == nil {
		return nil, fmt.Errorf("restConfig is required")
	}

	if requestTimeout <= 0 {
		return nil, fmt.Errorf("requestTimeout must be positive")
	}

	if metrics != nil {
		if metrics.RequestsTotal == nil || metrics.RequestLatency == nil {
			return nil, fmt.Errorf("metrics: all fields should be set")
		}
	}

	return &rulesFetcher{
		requestTimeout: requestTimeout,
		restConfig:     restConfig,
		metrics:        metrics,
		rulesFilter:    rulesFilter,
	}, nil
}

// buildClient returns a Kubernetes client that authenticates with userInfo.BearerToken.
func (k *rulesFetcher) buildClient(userInfo UserInfo) (kubernetes.Interface, error) {
	if userInfo.BearerToken == "" {
		return nil, fmt.Errorf("BearerToken is required for rules fetch")
	}

	cfg := rest.CopyConfig(k.restConfig)
	cfg.BearerToken = userInfo.BearerToken
	cfg.BearerTokenFile = ""

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// recordMetrics records request count and latency with code "ok" or "error".
func (k *rulesFetcher) recordMetrics(ok bool, durationSeconds float64) {
	if k.metrics == nil {
		return
	}

	code := "ok"
	if !ok {
		code = "error"
	}

	k.metrics.RequestsTotal.WithLabelValues(code).Inc()
	k.metrics.RequestLatency.WithLabelValues(code).Observe(durationSeconds)
}

// GetRules fetches resource rules from Kubernetes using SelfSubjectRulesReview.
// If rulesFilter was set in NewRulesFetcher, it is applied to the result.
func (k *rulesFetcher) GetRules(userInfo UserInfo, ns string) (Rules, error) {
	backoff := *webhookauthn.DefaultRetryBackoff()

	ctx, cancel := context.WithTimeout(context.Background(), k.requestTimeout)
	defer cancel()

	client, err := k.buildClient(userInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build kubernetes client: %w", ErrRulesInitError, err)
	}

	ssrr := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: ns},
	}

	var rules []authorizationv1.ResourceRule

	err = webhook.WithExponentialBackoff(ctx, backoff, func() error {
		start := time.Now()

		res, err := client.
			AuthorizationV1().
			SelfSubjectRulesReviews().
			Create(ctx, ssrr, metav1.CreateOptions{})

		duration := time.Since(start).Seconds()
		k.recordMetrics(err == nil, duration)

		if err != nil {
			return err
		}

		rules = res.Status.ResourceRules

		return nil
	}, webhook.DefaultShouldRetry)

	if err != nil {
		return nil, err
	}

	out := Rules(rules)
	if k.rulesFilter != nil {
		out = k.rulesFilter(out)
	}

	return out, nil
}

// cachedRulesFetcher wraps a RulesFetcher with an LRU cache.
type cachedRulesFetcher struct {
	inner      RulesFetcher
	cache      *cache.LRUExpireCache
	inflight   singleflight.Group
	successTTL time.Duration
	failureTTL time.Duration
}

// NewCachedRulesFetcher creates a RulesFetcher that caches results from inner. The cache uses DefaultCacheSize; successTTL and failureTTL control how long results are cached.
func NewCachedRulesFetcher(inner RulesFetcher, successTTL, failureTTL time.Duration) RulesFetcher {
	return &cachedRulesFetcher{
		inner:      inner,
		cache:      cache.NewLRUExpireCache(DefaultCacheSize),
		successTTL: successTTL,
		failureTTL: failureTTL,
	}
}

// GetRules returns cached rules or delegates to the inner fetcher and caches the result.
// At most one in-flight inner.GetRules request runs per cache key; concurrent callers for the same key share the result.
func (c *cachedRulesFetcher) GetRules(userInfo UserInfo, ns string) (Rules, error) {
	if userInfo.Name == "" && userInfo.UID == "" {
		return nil, fmt.Errorf("userInfo.Name and userInfo.UID is required for rules cache key")
	}

	key, err := ComputeHash(ns, userInfo.Name, userInfo.UID)
	if err != nil {
		return nil, fmt.Errorf("failed to compute cache key: %w", err)
	}

	if val, ok := c.cache.Get(key); ok {
		switch v := val.(type) {
		case Rules:
			return v, nil
		case error:
			return nil, v
		}
	}

	v, err, _ := c.inflight.Do(key, func() (any, error) {
		rules, err := c.inner.GetRules(userInfo, ns)
		if err != nil {
			if c.failureTTL > 0 && !errors.Is(err, ErrRulesInitError) {
				c.cache.Add(key, err, c.failureTTL)
			}

			return nil, err
		}

		if c.successTTL > 0 {
			c.cache.Add(key, rules, c.successTTL)
		}

		return rules, nil
	})

	if err != nil {
		return nil, err
	}

	return v.(Rules), nil
}

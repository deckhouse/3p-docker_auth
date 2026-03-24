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
	"fmt"
	"time"

	"golang.org/x/sync/singleflight"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NamespaceChecker checks whether a Kubernetes namespace exists.
type NamespaceChecker interface {
	// Exists returns true if the namespace exists, false if it does not.
	// Returns an error for API or context errors (e.g. timeout).
	Exists(ctx context.Context, ns string) (bool, error)
}

// namespaceChecker checks namespace existence via the Kubernetes Core API.
type namespaceChecker struct {
	requestTimeout time.Duration
	client         kubernetes.Interface
}

// NewNamespaceChecker creates a NamespaceChecker that uses the Kubernetes API to verify namespace existence.
// restConfig must be non-nil; requestTimeout must be positive and is used when ctx has no deadline.
// The Kubernetes client is built once and reused for all Exists calls.
func NewNamespaceChecker(requestTimeout time.Duration, restConfig *rest.Config) (NamespaceChecker, error) {
	if restConfig == nil {
		return nil, fmt.Errorf("restConfig is required")
	}
	if requestTimeout <= 0 {
		return nil, fmt.Errorf("requestTimeout must be positive")
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return &namespaceChecker{
		requestTimeout: requestTimeout,
		client:         client,
	}, nil
}

// Exists checks if the namespace exists by calling the CoreV1 Namespaces API.
func (n *namespaceChecker) Exists(ctx context.Context, ns string) (bool, error) {
	if ns == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, n.requestTimeout)
	defer cancel()

	_, err := n.client.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}

	if errors.IsNotFound(err) {
		return false, nil
	}

	return false, fmt.Errorf("failed to get namespace %q: %w", ns, err)
}

// cachedNamespaceChecker wraps a NamespaceChecker with an LRU cache.
type cachedNamespaceChecker struct {
	inner      NamespaceChecker
	cache      *cache.LRUExpireCache
	inflight   singleflight.Group
	successTTL time.Duration
	failureTTL time.Duration
}

// nsResult holds the result of an Exists call for caching.
type nsResult struct {
	exists bool
	err    error
}

// NewCachedNamespaceChecker creates a NamespaceChecker that caches results from inner.
// The cache uses DefaultCacheSize; successTTL and failureTTL control how long results are cached.
func NewCachedNamespaceChecker(inner NamespaceChecker, successTTL, failureTTL time.Duration) NamespaceChecker {
	return &cachedNamespaceChecker{
		inner:      inner,
		cache:      cache.NewLRUExpireCache(DefaultCacheSize),
		inflight:   singleflight.Group{},
		successTTL: successTTL,
		failureTTL: failureTTL,
	}
}

// Exists returns the cached result or delegates to the inner checker and caches the result.
// At most one in-flight inner.Exists request runs per namespace; concurrent callers for the same namespace share the result.
func (c *cachedNamespaceChecker) Exists(ctx context.Context, ns string) (bool, error) {
	if ns == "" {
		return false, nil
	}

	if val, ok := c.cache.Get(ns); ok {
		r := val.(nsResult)
		return r.exists, r.err
	}

	v, _, _ := c.inflight.Do(ns, func() (any, error) {
		exists, err := c.inner.Exists(ctx, ns)
		res := nsResult{exists: exists, err: err}

		if err != nil {
			if c.failureTTL > 0 {
				c.cache.Add(ns, res, c.failureTTL)
			}
			return res, nil
		}

		if c.successTTL > 0 {
			c.cache.Add(ns, res, c.successTTL)
		}

		return res, nil
	})

	r := v.(nsResult)
	return r.exists, r.err
}

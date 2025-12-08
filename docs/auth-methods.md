## Github

First you need to setup a [Github OAuth Application](https://github.com/settings/applications).

- The callback url needs to be `$fqdn:5001/github_auth`
   - `$fqdn` is the domain where docker_auth is accessed
   - `5001` or what port is specified in the `server` block

Once you have setup a Github OAuth application you need to add a `github` block to the docker_auth config file:

```yaml
github_auth:
  organization: "my-org-name"
  client_id: "..."
  client_secret: "..." # or client_secret_file
  level_token_db:
    path: /data/tokens.db
    # Optional token hash cost for bcrypt hashing
    # token_hash_cost: 5
```

Then specify what teams can do via acls

```yaml
acl:
  - match: {team: "infrastructure"}
    actions: ["pull", "push"]
    comment: "Infrastructure team members can push and all images"
```

## Kubernetes

Authenticate Docker users using Kubernetes bearer tokens. The password provided to `docker login` is treated as a Bearer token and validated via the Kubernetes TokenReview API. This requires the service account used by docker-auth to have permission to create TokenReviews.

Enable in config:

```yaml
kubernetes_auth:
  # Use in-cluster config by default; or specify kubeconfig path.
  # kubeconfig: "/path/to/kubeconfig"

  # Limits for outgoing TokenReview calls
  limits:
    request_timeout: "5s"
    # Optional client-go throttling for outgoing Kubernetes requests.
    # If qps/burst are <= 0, client-go defaults are used (QPS=5, Burst=10).
    qps: 10
    burst: 20

  # Cache settings for authentication results
  cache:
    # TTL for successful authentication results (0 disables caching)
    success_ttl: "2m"
    # TTL for failed authentication results (0 disables caching)
    failure_ttl: "2m"

  # Map k8s user groups/extra to labels for ACL matching
  labels:
    include_groups: true   # expose k8s user groups as labels["groups"]
    include_extra: false   # expose TokenReview user.extra[*] as labels
  # Note: when using Kubernetes auth, the docker login username must be "token"
  # and the password must be a valid Kubernetes bearer token.
```

Kubernetes authorization:

```yaml
kubernetes_authz:
  # kubeconfig: "/path/to/kubeconfig" # optional; empty means in-cluster

  # Limits for outgoing SelfSubjectRulesReview calls
  limits:
    request_timeout: "5s"
    # Optional client-go throttling for outgoing Kubernetes requests
    qps: 10
    burst: 20

  # Cache settings for authorization results (SSRR)
  cache:
    # TTL for successful authorization results (0 disables caching)
    success_ttl: "2m"
    # TTL for failed authorization results (0 disables caching)
    failure_ttl: "2m"

  # Parameters for constructing the SelfSubjectRulesReview.
  # Note: The Namespace for the review is derived from the first segment of the repository name (e.g. "ns/image" -> "ns").
  # The returned RBAC rules are matched against the remaining path.
  # Recursive globbing (e.g. "images/**") is supported.
  review:
    api_group: "registry.deckhouse.io"
    resource: "payloadrepositorytags"
    # Label key containing username from AuthN labels (default: k8s_username)
    user_label: "k8s_username"
```

Required RBAC for docker-auth's ServiceAccount:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: docker-auth-tokenreviewer
rules:
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
- apiGroups: ["authorization.k8s.io"]
  resources: ["selfsubjectrulesreviews"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: docker-auth-k8s-auth-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: docker-auth-tokenreviewer
subjects:
- kind: ServiceAccount
  name: <docker-auth-sa>
  namespace: <docker-auth-namespace>
```

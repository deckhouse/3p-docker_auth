## Supported authentication methods

This build supports:

- **Static users** (`users` in config) — BCrypt passwords
- **plugin_authn** — authentication plugin
- **kubernetes_auth** — Kubernetes bearer token via TokenReview API

---

## Kubernetes

Authenticate Docker users using Kubernetes bearer tokens. The password provided to `docker login` is treated as a Bearer token and validated via the Kubernetes TokenReview API. This requires the service account used by docker-auth to have permission to create TokenReviews.

**Important:** When using Kubernetes auth, the docker login username must be `"token"` (or the value specified in `username`) and the password must be a valid Kubernetes bearer token.

### Authentication Configuration

Enable Kubernetes authentication in config:

```yaml
kubernetes_auth:
  # Optional path to kubeconfig. If empty or not specified, in-cluster config is used
  # (service account token and CA certificate mounted in the pod).
  # kubeconfig: "/path/to/kubeconfig"

  # Optional username that must be used for Kubernetes token authentication.
  # Defaults to "token" if not specified.
  # username: "token"

  # Limits for outgoing TokenReview calls
  limits:
    request_timeout: "5s"  # Timeout for individual API requests
    # Optional client-go throttling for outgoing Kubernetes requests.
    # QPS: If zero, DefaultQPS: 5 is used. If negative, throttling is disabled.
    # Burst: If zero, DefaultBurst: 10 is used. Only relevant when QPS > 0.
    qps: 10
    burst: 20

  # Cache settings for authentication results
  cache:
    # TTL for successful authentication results (default: 5m, 0 disables caching)
    success_ttl: "1m"
    # TTL for failed authentication results (default: 30s, 0 disables caching)
    failure_ttl: "30s"
```

### Labels from Kubernetes Authentication

When a user authenticates via Kubernetes, the following labels are automatically created from the TokenReview response:

- `username`: The Kubernetes username (same key as other auth methods for ACL)
- `uid`: The Kubernetes user UID
- `groups`: Kubernetes groups the user belongs to (same label as other auth methods for ACL)

These labels can be used in ACL rules for authorization:

```yaml
acl:
  - match: { labels: { "groups": "developers" } }
    actions: ["pull", "push"]
    comment: "Developers can pull and push images"
  - match: { labels: { "groups": "admins" } }
    actions: ["*"]
    comment: "Admins have full access"
```

### Authentication failures

When the token is invalid or not authenticated (e.g. expired, revoked, or rejected by the API server), the server responds with **HTTP 401 Unauthorized**. The response body includes a short message such as `Auth failed: token not authenticated` so clients can distinguish authentication failures from other errors. Successful TokenReview returns user labels as above; invalid or empty responses are treated as authentication failure.

### Kubernetes Authorization (RBAC)

Kubernetes authorization uses SelfSubjectRulesReview to check RBAC permissions. Authorization is **optional** and is enabled by adding the `authz` section to your `kubernetes_auth` configuration.

**Quick Reference:**
- **Enable**: Add `authz` section under `kubernetes_auth`
- **Disable**: Omit the `authz` section
- **Evaluation Order**: ACL is checked first, then Kubernetes authz
- **Logic**: OR logic - if ACL or Kubernetes authz allows, access is granted
- **Priority**: ACL is checked first; if it allows, Kubernetes authz is not evaluated

#### Enabling Authorization

To enable Kubernetes RBAC-based authorization, simply add the `authz` section under `kubernetes_auth`:

```yaml
kubernetes_auth:
  # ... authentication config above ...
  
  # Enable Kubernetes authorization (RBAC via SelfSubjectRulesReview)
  authz:
    # Required: Kubernetes API group for the custom resource
    api_group: "registry.example.com"
    # Required: Kubernetes resource name (plural form)
    resource: "registries"
    # Optional: Docker actions for which namespace existence is checked before RBAC.
    # If set, the namespace (first segment of the repo name) must exist in the cluster
    # when the request includes at least one of these actions (e.g. push, delete).
    # If empty or omitted, namespace existence is not checked.
    # namespace_check_verbs: ["push", "delete"]
```

**When authorization is enabled:**
- Authorization checks are performed using Kubernetes RBAC rules
- The system queries SelfSubjectRulesReview to determine user permissions
- Repository access is controlled by Kubernetes Role/RoleBinding or ClusterRole/ClusterRoleBinding
- ACL rules (if configured) are evaluated first - if ACL allows, Kubernetes authz is not checked

**When authorization is NOT enabled (authz section omitted):**
- Only authentication is performed via TokenReview
- Authorization must be handled by other methods (ACL rules, plugin authz, etc.)
- Kubernetes RBAC is not checked for registry access

**Note:** You can use Kubernetes authentication with traditional ACL-based authorization by omitting the `authz` section and configuring ACL rules instead.

**How it works:**

1. **Namespace extraction**: The namespace for the SelfSubjectRulesReview is derived from the first segment of the repository name. For example:
   - Repository: `my-namespace/my-app` → Namespace: `my-namespace`, Path: `my-app`
   - Repository: `prod/backend/api` → Namespace: `prod`, Path: `backend/api`

2. **Namespace existence check** (optional): If `namespace_check_verbs` is set, the server checks that the namespace (first segment of the repository name) exists in the cluster before running RBAC. The check runs only when the request includes at least one of the listed Docker actions (e.g. `push`, `delete`). If the namespace does not exist, access is denied. This avoids unnecessary SelfSubjectRulesReview calls for invalid namespaces.

3. **Action to verb mapping**: Docker actions are mapped to Kubernetes verbs:
   - `pull` → `get`
   - `push` → `create`
   - `delete` → `delete`

4. **RBAC rule matching**: The authorization checks if the authenticated user has the required verb permission for the specified API group and resource. The resource path (after the namespace) is matched against RBAC `resourceNames` using recursive globbing (e.g., `images/**`).

**Example RBAC rules:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: registry-reader
  namespace: my-namespace
rules:
- apiGroups: ["registry.example.com"]
  resources: ["registries"]
  verbs: ["get"]
  resourceNames:
    - "my-app"
    - "shared/**"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: registry-writer
  namespace: my-namespace
rules:
- apiGroups: ["registry.example.com"]
  resources: ["registries"]
  verbs: ["get", "create", "delete"]
  resourceNames:
    - "my-app/**"
```

**Important Notes:**

- The authorization uses the same `limits` and `cache` settings from the parent `kubernetes_auth` configuration.
- Optional `namespace_check_verbs` limits namespace existence checks to certain Docker actions (e.g. only for `push` and `delete`); if omitted, namespace existence is not checked.
- When `authz` is enabled, Kubernetes RBAC authorization is checked. If ACL rules are also configured, **both** are evaluated - access is granted if either ACL or Kubernetes authz allows it (OR logic).
- To use only Kubernetes RBAC authorization, enable `authz` and omit or leave ACL empty.
- To use only ACL-based authorization, omit the `authz` section and configure ACL rules.

### Authorization Evaluation Order: ACL vs Kubernetes Authz

When both ACL and Kubernetes authz are configured, they are evaluated in a specific order. The first authorizer that allows access wins (OR logic). If both return `NoMatch` or deny, access is denied.

**Evaluation Order:**

1. **ACL rules are checked first** (if configured)
2. **Kubernetes authz is checked second** (if `authz` section is enabled)

**How it works:**

1. ACL is evaluated first
2. If ACL allows → **access granted** (Kubernetes authz is **not checked** - short-circuit)
3. If ACL denies or returns NoMatch → Kubernetes authz is evaluated
4. If Kubernetes authz allows → **access granted**
5. If both deny → **access denied**

**Important behaviors:**

- **OR Logic**: If ACL or Kubernetes authz allows access, the request is authorized. You don't need both to approve.
- **First Match Wins**: Once ACL or Kubernetes authz returns allowed actions, evaluation stops and those actions are granted.
- **NoMatch Handling**: If ACL returns `NoMatch` (meaning it doesn't apply to this request), evaluation continues to Kubernetes authz.
- **Default Deny**: If both ACL and Kubernetes authz return `NoMatch` or deny, access is denied by default.

**Example scenarios with ACL and Kubernetes Authz:**

```yaml
# Scenario 1: ACL allows, Kubernetes authz would deny
# Result: Access GRANTED (ACL is checked first and allows, K8s authz is not evaluated)
acl:
  - match: { labels: { "groups": "developers" } }
    actions: ["pull", "push"]

kubernetes_auth:
  authz:
    api_group: "registry.example.com"
    resource: "registries"
# User in "developers" group gets access from ACL, Kubernetes authz is not evaluated

# Scenario 2: ACL denies (or NoMatch), Kubernetes authz allows
# Result: Access GRANTED (Kubernetes authz is checked after ACL and allows)
acl:
  - match: { labels: { "groups": "readonly" } }
    actions: ["pull"]  # Only readonly group matches, developers don't match

kubernetes_auth:
  authz:
    api_group: "registry.example.com"
    resource: "registries"
# ACL returns NoMatch for developers group, Kubernetes RBAC allows → Access granted

# Scenario 3: ACL explicitly denies, Kubernetes authz allows
# Result: Access GRANTED (Even explicit deny in ACL, K8s authz can override)
acl:
  - match: { labels: { "groups": "developers" } }
    actions: []  # Explicit deny (empty actions)

kubernetes_auth:
  authz:
    api_group: "registry.example.com"
    resource: "registries"
# ACL explicitly denies, but Kubernetes RBAC allows → Access granted (OR logic)

# Scenario 4: Both deny
# Result: Access DENIED
acl:
  - match: { labels: { "groups": "developers" } }
    actions: []  # Deny

kubernetes_auth:
  authz:
    api_group: "registry.example.com"
    resource: "registries"
# ACL denies, Kubernetes authz also denies → Access denied
```

**Summary Table: ACL vs Kubernetes Authz**

| Configuration | ACL Rules | Kubernetes Authz | Evaluation Order | Result |
|--------------|-----------|-------------------|------------------|--------|
| Auth only | ✅ | ❌ | ACL only | ACL decides |
| Auth + Authz | ✅ | ✅ | ACL → K8s Authz | First to allow wins |
| Auth + Authz | ❌ | ✅ | K8s Authz only | K8s RBAC decides |
| Auth + Authz | ✅ (deny) | ✅ (allow) | ACL → K8s Authz | ✅ **Access granted** (K8s allows) |
| Auth + Authz | ✅ (allow) | ✅ (deny) | ACL → K8s Authz | ✅ **Access granted** (ACL allows, K8s not checked) |
| Auth + Authz | ✅ (deny) | ✅ (deny) | ACL → K8s Authz | ❌ **Access denied** (both deny) |

**Key Points:**
- ACL is evaluated **before** Kubernetes authz
- If ACL allows access, Kubernetes authz is **not evaluated** (short-circuit)
- If ACL denies or returns NoMatch, Kubernetes authz is evaluated
- Kubernetes authz can override ACL denials (OR logic)

**Best Practices:**

- **Use ACL for**: Simple, static rules that apply to all users; quick allow/deny based on labels or accounts
- **Use Kubernetes authz for**: Dynamic, namespace-based permissions managed via RBAC; fine-grained control per namespace
- **Kubernetes RBAC as primary**: Omit ACL rules or make them very restrictive if you want Kubernetes RBAC to be the only source of truth
- **ACL as fallback**: Configure ACL first (it's evaluated first anyway) and enable Kubernetes authz as a secondary check for cases ACL doesn't cover
- **ACL as fast-path**: Since ACL is evaluated **before** Kubernetes authz, if ACL allows, Kubernetes authz is never checked. This means ACL can act as a fast-path for common cases, while Kubernetes authz handles complex namespace-based scenarios.

### Required RBAC for docker-auth's ServiceAccount

The docker-auth service account needs permissions to create TokenReviews and SelfSubjectRulesReviews:

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
  name: docker-auth  # Replace with your service account name
  namespace: docker-auth  # Replace with your namespace
```

### Usage Examples

#### Example 1: Authentication Only (Authorization NOT Enabled)

This example uses Kubernetes for authentication only. The `authz` section is **omitted**, so authorization is handled by ACL rules. ACL is evaluated first (and only, in this case):

```yaml
kubernetes_auth:
  limits:
    request_timeout: "5s"
    qps: 10
    burst: 20
  cache:
    success_ttl: "1m"
    failure_ttl: "30s"
  # Note: No 'authz' section - Kubernetes RBAC authorization is NOT enabled

acl:
  - match: { labels: { "groups": "developers" } }
    actions: ["pull", "push"]
    comment: "Developers can pull and push all images"
  - match: { labels: { "groups": "readonly" } }
    actions: ["pull"]
    comment: "Read-only users can only pull images"
  - match: { labels: { "username": "admin" } }
    actions: ["*"]
    comment: "Admin user has full access"
  - match: { labels: { "uid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" } }
    actions: ["*"]
    comment: "User with specific UID has full access"
```

#### Example 2: Authentication + Kubernetes RBAC Authorization (Authorization Enabled)

This example enables Kubernetes RBAC authorization by including the `authz` section. **Evaluation order**: ACL is checked first, then Kubernetes RBAC. If either allows access, the request is authorized:

```yaml
kubernetes_auth:
  limits:
    request_timeout: "5s"
    qps: 10
    burst: 20
  cache:
    success_ttl: "1m"
    failure_ttl: "30s"
  # Authorization is ENABLED - Kubernetes RBAC will be checked
  authz:
    api_group: "registry.example.com"
    resource: "registries"
    # Optional: check namespace exists only for push/delete (not for pull)
    # namespace_check_verbs: ["push", "delete"]
```

With corresponding Kubernetes RBAC rules:

```yaml
# Allow developers to pull/push in their namespace
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: registry-developer
  namespace: dev
rules:
- apiGroups: ["registry.example.com"]
  resources: ["registries"]
  verbs: ["get", "create"]
  resourceNames:
    - "my-app/**"
    - "shared/**"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: registry-developer-binding
  namespace: dev
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: registry-developer
subjects:
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
```

#### Example 3: Docker Login

To authenticate with Kubernetes tokens:

```bash
# Get your Kubernetes token (ServiceAccount token)
TOKEN=$(kubectl get secret $(kubectl get sa my-sa -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d)

# Or for a user token (if using OIDC/OAuth)
TOKEN=$(kubectl config view --raw -o jsonpath='{.users[?(@.name=="my-user")].user.token}')

# Login to Docker registry
echo "$TOKEN" | docker login -u token --password-stdin registry.example.com
```

### Repository Name Format

When using Kubernetes authorization, repository names should follow the format: `namespace/path/to/image`

- The first segment (`namespace`) is used as the Kubernetes namespace for the SelfSubjectRulesReview
- The remaining path (`path/to/image`) is matched against RBAC `resourceNames` using glob patterns

Examples:
- `prod/backend/api` → Namespace: `prod`, Path: `backend/api`
- `dev/my-app` → Namespace: `dev`, Path: `my-app`
- `shared/common/base` → Namespace: `shared`, Path: `common/base`

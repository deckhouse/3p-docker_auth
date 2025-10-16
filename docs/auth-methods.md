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
  request_timeout: "5s"
  labels:
    include_groups: true   # expose k8s user groups as labels["groups"]
    include_extra: false   # expose TokenReview user.extra[*] as labels
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
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: docker-auth-tokenreviewer-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: docker-auth-tokenreviewer
subjects:
- kind: ServiceAccount
  name: <docker-auth-sa>
  namespace: <docker-auth-namespace>
```

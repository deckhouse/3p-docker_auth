package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/distribution/registry/auth/token"
	"golang.org/x/crypto/bcrypt"
)

// FuzzAuthEndpoint drives the /auth endpoint against the two ACL policies the
// registry module actually ships.
//
// Threat model coverage (registry-threat-model.md), harness 4. This server is
// the only thing standing between a node's credentials and write access to the
// registry that the whole cluster pulls from, and the request it decides on is
// almost entirely attacker-shaped: the scope string is free-form, arrives in a
// query parameter, may be repeated, and is parsed by hand.
//
// The oracle does not reimplement the ACL. It asserts bounds that the shipped
// policies fix, so a change in parsing that widens a grant is caught without
// the test having to agree with the implementation on how matching works:
//
//   - No 5xx: the endpoint is on the pull path of every node.
//   - No grant beyond the request: a token may not carry an action the client
//     did not ask for. Anything else means the scope no longer bounds the token.
//   - No substitution: the resource named in the token must be the resource
//     named in the request. A token for a different repository is a token to
//     push an image where the client was only allowed to read one.
//   - Policy ceilings: the read-only account and the mirror puller are granted
//     exactly "pull" by their entries, so no other action may ever appear --
//     except for the mirror puller against registry:catalog, which its own
//     entry grants "*" by design.
//   - An account with no user entry gets 401 and no token at all.
func FuzzAuthEndpoint(f *testing.F) {
	env := authFuzzEnv(f)

	// Scopes a registry client really sends, plus the shapes that stress the
	// hand-written parser: the colon-in-name form, repeated and contradictory
	// actions, an unanchored type, an empty name, a very long action list.
	seeds := []string{
		"repository:system/deckhouse:pull",
		"repository:system/deckhouse:pull,push",
		"repository:system/deckhouse:push",
		"repository:system/deckhouse:delete",
		"repository:system/deckhouse:*",
		"registry:catalog:*",
		"registry:catalog:pull",
		"repository:registry.example.com:5000/img:pull,push",
		"repository(plugin):system/deckhouse:pull",
		"repository:system/deckhouse:pull,pull,pull",
		"repository:system/deckhouse:pull,push,delete,*",
		"repository::pull",
		"repository:system/deckhouse:",
		"Xrepository:system/deckhouse:push",
		"repository!:system/deckhouse:push",
		"REPOSITORY:system/deckhouse:push",
		"repository:system/deckhouse:pull repository:other:push",
		"repository:a:b:c:d:pull",
		"",
		":::",
		"repository:system/deckhouse:PULL",
		"repository:system/deckhouse: pull",
	}

	for _, scope := range seeds {
		for _, selector := range []byte{0, 1, 2, 3, 4} {
			f.Add(selector, false, scope, "registry", byte(0))
		}
		f.Add(byte(0), true, scope, "registry", byte(0))
		f.Add(byte(0), false, scope, "registry", byte(1))
		f.Add(byte(5), false, scope, "registry", byte(1))
	}

	f.Fuzz(func(t *testing.T, accountSelector byte, wrongPassword bool, scope, service string, policySelector byte) {
		if len(scope) > 4096 || len(service) > 256 {
			return
		}

		policy := env.policies[int(policySelector)%len(env.policies)]
		account := policy.accounts[int(accountSelector)%len(policy.accounts)]

		password := account.password
		if wrongPassword {
			password += "-wrong"
		}

		query := url.Values{}
		query.Set("service", service)
		if scope != "" {
			query.Set("scope", scope)
		}

		request, err := http.NewRequest(http.MethodGet,
			policy.server.URL+"/auth?"+query.Encode(), nil)
		if err != nil {
			t.Fatalf("cannot build the auth request: %v", err)
		}
		request.SetBasicAuth(account.name, password)

		response, err := policy.server.Client().Do(request)
		if err != nil {
			t.Fatalf("the auth request failed at the transport level: %v", err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatalf("cannot read the auth response: %v", err)
		}

		if response.StatusCode >= 500 {
			t.Fatalf("%s produced %s for scope %q, which a client must not be able to cause: %s",
				policy.name, response.Status, scope, body)
		}

		// Credentials that should not authenticate must not yield a token.
		if !account.known || wrongPassword {
			if response.StatusCode == http.StatusOK {
				t.Fatalf("%s: account %q authenticated with %s and received a token",
					policy.name, account.name, describeCredentials(account.known, wrongPassword))
			}
			return
		}

		if response.StatusCode != http.StatusOK {
			// A malformed scope is rejected with 400, which is correct.
			return
		}

		claims := decodeClaims(t, body)

		requested := requestedActions(scope)

		for _, granted := range claims.Access {
			resource := granted.Type + ":" + granted.Name

			// No grant beyond the request.
			want, asked := requested[resource]
			if !asked {
				t.Fatalf("%s: a token for scope %q grants %v on %q, which the request did not name; "+
					"the requested resources were %v",
					policy.name, scope, granted.Actions, resource, resourceNames(requested))
			}
			for _, action := range granted.Actions {
				if !slices.Contains(want, action) {
					t.Fatalf("%s: a token for scope %q grants %q on %q, which was not requested; "+
						"the request asked for %v",
						policy.name, scope, action, resource, want)
				}
			}

			// Policy ceiling.
			if account.ceiling == nil {
				continue
			}
			if account.catalogException && granted.Type == "registry" && granted.Name == "catalog" {
				continue
			}
			for _, action := range granted.Actions {
				if !slices.Contains(account.ceiling, action) {
					t.Fatalf("%s: account %q is granted %q on %q by scope %q, but its ACL entry grants "+
						"only %v; the scope reached a more permissive entry than the one written for it",
						policy.name, account.name, action, resource, scope, account.ceiling)
				}
			}
		}

		// The subject must be the account that authenticated: the registry
		// authorises by the subject, so a token issued under another name is a
		// token for another identity.
		if claims.Subject != account.name {
			t.Fatalf("%s: %q authenticated but the token names subject %q",
				policy.name, account.name, claims.Subject)
		}
	})
}

// requestedActions maps "<type>:<name>" to the actions the scope string asked
// for, following the same reading of the scope grammar that the server does.
func requestedActions(scope string) map[string][]string {
	requested := map[string][]string{}

	for _, scopeStr := range strings.Split(scope, " ") {
		parts := strings.Split(scopeStr, ":")

		var name, actions string
		switch len(parts) {
		case 3:
			name, actions = parts[1], parts[2]
		case 4:
			name, actions = parts[1]+":"+parts[2], parts[3]
		default:
			continue
		}

		// The type the server derives is the first run of lowercase
		// alphanumerics in parts[0], because scopeRegex is not anchored. The
		// oracle keys on whatever the token reports for the type and checks the
		// name and actions, so it accepts any type the parser produced for this
		// scope entry rather than duplicating that normalisation.
		for _, resourceType := range plausibleTypes(parts[0]) {
			key := throughJSON(resourceType + ":" + name)
			for _, action := range strings.Split(actions, ",") {
				requested[key] = append(requested[key], throughJSON(action))
			}
		}
	}

	return requested
}

// plausibleTypes lists the resource types the server could report for a raw
// scope type, which is any lowercase-alphanumeric run inside it plus the raw
// value itself.
func plausibleTypes(raw string) []string {
	types := []string{raw}

	current := strings.Builder{}
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			current.WriteRune(r)
			continue
		}
		if current.Len() > 0 {
			types = append(types, current.String())
			current.Reset()
		}
	}
	if current.Len() > 0 {
		types = append(types, current.String())
	}

	// A class in parentheses is stripped from the type.
	if open := strings.IndexByte(raw, '('); open >= 0 {
		types = append(types, raw[:open])
	}

	return types
}

// throughJSON puts a string through the same encoding the token does.
//
// The claim set is marshalled to JSON, and encoding/json is not byte-preserving
// for a string that is not valid UTF-8: it substitutes U+FFFD. The oracle
// compares what the token reports against what the request asked for, so the
// expected side has to travel the same lossy path or the two disagree on input
// the registry would never produce anyway -- a repository name is confined to a
// safe character class by distribution's own grammar.
func throughJSON(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}

	var decoded string
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return value
	}
	return decoded
}

func resourceNames(requested map[string][]string) []string {
	names := make([]string, 0, len(requested))
	for name := range requested {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func describeCredentials(known, wrongPassword bool) refusedCredentials {
	return refusedCredentials{known: known, wrongPassword: wrongPassword}
}

// refusedCredentials renders why a set of credentials should have been refused.
type refusedCredentials struct {
	known         bool
	wrongPassword bool
}

func (b refusedCredentials) String() string {
	switch {
	case !b.known && b.wrongPassword:
		return "no user entry and a wrong password"
	case !b.known:
		return "no user entry"
	default:
		return "a wrong password"
	}
}

// decodeClaims reads the claim set out of the issued token. The signature is
// not checked: this harness is about what the server decides to put in the
// token, and the signing key is its own.
func decodeClaims(t *testing.T, body []byte) token.ClaimSet {
	t.Helper()

	var response struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("cannot parse the auth response %q: %v", body, err)
	}

	parts := strings.Split(response.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("the issued token has %d parts, expected 3", len(parts))
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("cannot base64-decode the token claims: %v", err)
	}

	var claims token.ClaimSet
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("cannot parse the token claims %q: %v", claimsJSON, err)
	}

	return claims
}

// authAccount is one identity the harness can present, with the ceiling its ACL
// entry puts on what it may be granted.
type authAccount struct {
	name     string
	password string
	known    bool

	// ceiling bounds the actions the policy may grant. A nil ceiling means the
	// entry grants "*", so only the no-grant-beyond-request bound applies.
	ceiling []string

	// catalogException marks an account whose policy grants it everything on
	// registry:catalog through an entry of its own.
	catalogException bool
}

type authPolicy struct {
	name     string
	server   *httptest.Server
	accounts []authAccount
}

type authEnv struct {
	policies []*authPolicy
}

var (
	authFuzzOnce  sync.Once
	authFuzzValue *authEnv
)

func authFuzzEnv(f *testing.F) *authEnv {
	f.Helper()

	return startAuthEnv(func(format string, args ...interface{}) {
		f.Fatalf(format, args...)
	})
}

// newBehaviourServer hands a plain test the node-policy server.
func newBehaviourServer(t *testing.T) *httptest.Server {
	t.Helper()

	env := startAuthEnv(func(format string, args ...interface{}) {
		t.Fatalf(format, args...)
	})
	return env.policies[0].server
}

// startAuthEnv brings up both policies once per process.
func startAuthEnv(fatalf func(string, ...interface{})) *authEnv {
	dir, err := os.MkdirTemp("", "docker-auth-fuzz")
	if err != nil {
		fatalf("cannot create the config directory: %v", err)
		return nil
	}

	authFuzzOnce.Do(func() {
		certPath, keyPath := writeTokenKeyPair(fatalf, dir)

		// The passwords are hashed at bcrypt's minimum cost. The harness is
		// about authorisation decisions, and a work factor chosen for password
		// storage would cap it at a few executions per second.
		hash := func(password string) string {
			hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				fatalf("cannot hash a password: %v", err)
			}
			return string(hashed)
		}

		// The node-side policy, as
		// modules/038-registry/images/nodeservices-manager/app/internal/staticpod/templates/auth/config.yaml.tpl
		// renders it.
		nodeAccounts := []authAccount{
			{name: "ro-user", password: "ro-password", known: true, ceiling: []string{"pull"}},
			{name: "rw-user", password: "rw-password", known: true},
			{name: "pusher", password: "pusher-password", known: true},
			{name: "puller", password: "puller-password", known: true,
				ceiling: []string{"pull"}, catalogException: true},
			{name: "nobody", password: "nobody-password"},
			{name: "", password: ""},
		}

		nodeConfig := fmt.Sprintf(`
server:
  addr: "127.0.0.1:5051"
  real_ip_header: "X-Forwarded-For"
token:
  issuer: "Registry server"
  expiration: 900
  certificate: %q
  key: %q
users:
  "ro-user":
    password: %q
  "rw-user":
    password: %q
  "puller":
    password: %q
  "pusher":
    password: %q
acl:
  - match: { account: "ro-user" }
    actions: ["pull"]
    comment: "has readonly access"
  - match: { account: "rw-user" }
    actions: [ "*" ]
    comment: "has full access"
  - match: { account: "pusher" }
    actions: [ "*" ]
    comment: "mirrorer pusher"
  - match: { account: "puller", type: "registry", name: "catalog" }
    actions: ["*"]
    comment: "mirrorer puller catalog"
  - match: { account: "puller" }
    actions: ["pull"]
    comment: "mirrorer puller"
`, certPath, keyPath,
			hash("ro-password"), hash("rw-password"), hash("puller-password"), hash("pusher-password"))

		// The in-cluster proxy policy, from
		// modules/038-registry/templates/inclusterproxy/secret.yaml: one
		// account, pull only.
		proxyAccounts := []authAccount{
			{name: "upstream-user", password: "upstream-password", known: true, ceiling: []string{"pull"}},
			{name: "rw-user", password: "rw-password"},
			{name: "nobody", password: "nobody-password"},
		}

		proxyConfig := fmt.Sprintf(`
server:
  addr: "127.0.0.1:5051"
token:
  issuer: "Registry server"
  expiration: 900
  certificate: %q
  key: %q
users:
  "upstream-user":
    password: %q
acl:
  - match: { account: "upstream-user" }
    actions: ["pull"]
`, certPath, keyPath, hash("upstream-password"))

		authFuzzValue = &authEnv{policies: []*authPolicy{
			startAuthServer(fatalf, dir, "node policy", nodeConfig, nodeAccounts),
			startAuthServer(fatalf, dir, "in-cluster proxy policy", proxyConfig, proxyAccounts),
		}}
	})

	if authFuzzValue == nil {
		fatalf("the auth servers did not start")
	}
	return authFuzzValue
}

func startAuthServer(fatalf func(string, ...interface{}), dir, name, configYAML string, accounts []authAccount) *authPolicy {
	path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yaml")
	if err := os.WriteFile(path, []byte(configYAML), 0o600); err != nil {
		fatalf("cannot write the %s config: %v", name, err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		fatalf("cannot load the %s config: %v", name, err)
	}

	authServer, err := NewAuthServer(config)
	if err != nil {
		fatalf("cannot start the %s server: %v", name, err)
	}

	return &authPolicy{
		name:     name,
		server:   httptest.NewServer(authServer),
		accounts: accounts,
	}
}

// writeTokenKeyPair generates the key the server signs tokens with. The token
// signature is not what this harness examines, so a fresh throwaway key is
// exactly what is wanted -- nothing here is a credential.
func writeTokenKeyPair(fatalf func(string, ...interface{}), dir string) (string, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatalf("cannot generate the token key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "docker-auth-fuzz-token"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		fatalf("cannot create the token certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fatalf("cannot marshal the token key: %v", err)
	}

	certPath := filepath.Join(dir, "token.crt")
	keyPath := filepath.Join(dir, "token.key")

	if err := os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		fatalf("cannot write the token certificate: %v", err)
	}
	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		fatalf("cannot write the token key: %v", err)
	}

	return certPath, keyPath
}

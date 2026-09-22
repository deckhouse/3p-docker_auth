package server

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// FuzzAuthRequest fuzzes the parts of the /auth request that FuzzAuthEndpoint
// holds fixed.
//
// Threat model coverage (registry-threat-model.md), harness 4. Section 6 names
// six things to vary on this endpoint: `service`, `scope`, `account`, repeated
// and contradictory scopes, bad encoding, anomalous length, and the
// `Authorization` header. FuzzAuthEndpoint covers `service` and `scope` and
// asserts the ACL invariants; it reaches the rest only incidentally, because it
// picks an account from a fixed table and always builds a well-formed Basic
// header. This target takes the other three:
//
//   - `account` as a free-form query parameter, including the case where it
//     disagrees with the authenticated user. Authorize keys entirely on
//     ar.Account, so a client that could authenticate as one identity and be
//     authorised as another would be authorised as whoever it named.
//   - The raw `Authorization` header: a scheme that is not Basic, a payload that
//     is not base64, base64 of something with no colon, an empty user or
//     password, an anomalously long value.
//   - Repeated `scope` parameters. ParseRequest iterates req.Form["scope"], so
//     `?scope=a&scope=b` is a different code path from `?scope=a b`, and the two
//     must not disagree about what was requested.
//
// The oracle is the same shape as the sibling target's: an issued token may not
// exceed the request, may not name another identity, and no client-shaped
// request may produce a 5xx.
func FuzzAuthRequest(f *testing.F) {
	env := authFuzzEnv(f)

	type seed struct {
		authorization string
		account       string
		scopeA        string
		scopeB        string
	}

	basic := func(user, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	}

	seeds := []seed{
		// The request a registry client really makes.
		{basic("ro-user", "ro-password"), "", "repository:system/deckhouse:pull", ""},
		// account agreeing and disagreeing with the authenticated user.
		{basic("ro-user", "ro-password"), "ro-user", "repository:system/deckhouse:pull", ""},
		{basic("ro-user", "ro-password"), "rw-user", "repository:system/deckhouse:pull,push", ""},
		{basic("ro-user", "ro-password"), "nobody", "repository:system/deckhouse:pull", ""},
		{"", "rw-user", "repository:system/deckhouse:push", ""},
		{"", "", "repository:system/deckhouse:pull", ""},
		// Repeated scopes, agreeing and contradictory.
		{basic("rw-user", "rw-password"), "", "repository:a:pull", "repository:b:push"},
		{basic("ro-user", "ro-password"), "", "repository:a:pull", "repository:a:push"},
		{basic("ro-user", "ro-password"), "", "repository:a:pull", "repository:a:pull"},
		{basic("puller", "puller-password"), "", "registry:catalog:*", "repository:a:push"},
		// Authorization headers that are not a well-formed Basic credential.
		{"Basic", "", "repository:a:pull", ""},
		{"Basic ", "", "repository:a:pull", ""},
		{"Basic !!!!", "", "repository:a:pull", ""},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon")), "", "repository:a:pull", ""},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte(":")), "", "repository:a:pull", ""},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("ro-user:")), "", "repository:a:pull", ""},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte(":ro-password")), "", "repository:a:pull", ""},
		{"Bearer token", "", "repository:a:pull", ""},
		{"basic " + base64.StdEncoding.EncodeToString([]byte("ro-user:ro-password")), "", "repository:a:pull", ""},
		{"Basic " + strings.Repeat("A", 8192), "", "repository:a:pull", ""},
		{basic(strings.Repeat("u", 4096), "p"), "", "repository:a:pull", ""},
		{basic("ro-user", "ro-password"), strings.Repeat("a", 4096), "repository:a:pull", ""},
		// Encodings the parser has to survive.
		{basic("ro-user", "ro-password"), "%80", "repository:a:pull", ""},
		{basic("ro-user", "ro-password"), "ro\x00user", "repository:a:pull", ""},
	}

	for _, s := range seeds {
		f.Add(s.authorization, s.account, s.scopeA, s.scopeB, byte(0))
		f.Add(s.authorization, s.account, s.scopeA, s.scopeB, byte(1))
	}

	f.Fuzz(func(t *testing.T, authorization, account, scopeA, scopeB string, policySelector byte) {
		if len(authorization) > 16384 || len(account) > 4096 ||
			len(scopeA) > 4096 || len(scopeB) > 4096 {
			return
		}
		if !sendableHeaderValue(authorization) {
			// net/http refuses to put it on the wire, and the server side of
			// net/http would reject it before any of this server's code ran.
			return
		}

		policy := env.policies[int(policySelector)%len(env.policies)]

		query := url.Values{}
		query.Set("service", "registry")
		if account != "" {
			query.Set("account", account)
		}
		if scopeA != "" {
			query.Add("scope", scopeA)
		}
		if scopeB != "" {
			query.Add("scope", scopeB)
		}

		request, err := http.NewRequest(http.MethodGet,
			policy.server.URL+"/auth?"+query.Encode(), nil)
		if err != nil {
			t.Fatalf("cannot build the auth request: %v", err)
		}
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}

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
			t.Fatalf("%s produced %s, which a client must not be able to cause\n"+
				"\tAuthorization: %q\n\taccount: %q\n\tscope: %q, %q\n\tbody: %s",
				policy.name, response.Status, authorization, account, scopeA, scopeB, body)
		}

		if response.StatusCode != http.StatusOK {
			return
		}

		claims := decodeClaims(t, body)

		// The subject is what the registry authorises by, so it has to be the
		// identity that authenticated -- not the one the request named.
		user, password, haveBasic := parseBasic(authorization)

		switch {
		case haveBasic && account != "" && account != user:
			t.Fatalf("%s issued a token although the request authenticated as %q and claimed "+
				"account %q; Authorize keys on the account, so the two disagreeing must be refused",
				policy.name, user, account)

		case haveBasic:
			if claims.Subject != user {
				t.Fatalf("%s authenticated %q but the token names subject %q",
					policy.name, user, claims.Subject)
			}
			if !accountKnown(policy, user, password) {
				t.Fatalf("%s issued a token for %q, which is not an account of this policy "+
					"with that password", policy.name, user)
			}

		default:
			// No Basic credential at all. The account then defaults to the
			// empty user, and no policy has an entry for it.
			if claims.Subject != "" {
				t.Fatalf("%s issued a token with subject %q for a request that carried no "+
					"credential (Authorization: %q)", policy.name, claims.Subject, authorization)
			}
			for _, granted := range claims.Access {
				if len(granted.Actions) > 0 {
					t.Fatalf("%s granted %v on %s:%s to a request that carried no credential",
						policy.name, granted.Actions, granted.Type, granted.Name)
				}
			}
		}

		// No grant beyond the request, with the repeated parameters read the
		// way ParseRequest reads them: every value of every `scope`.
		requested := map[string][]string{}
		for _, scope := range []string{scopeA, scopeB} {
			if scope == "" {
				continue
			}
			for resource, actions := range requestedActions(scope) {
				requested[resource] = append(requested[resource], actions...)
			}
		}

		for _, granted := range claims.Access {
			resource := granted.Type + ":" + granted.Name

			want, asked := requested[resource]
			if !asked {
				t.Fatalf("%s: a token grants %v on %q, which neither scope named; "+
					"the request asked for %v\n\tscope: %q, %q",
					policy.name, granted.Actions, resource, resourceNames(requested), scopeA, scopeB)
			}
			for _, action := range granted.Actions {
				if !contains(want, action) {
					t.Fatalf("%s: a token grants %q on %q, which was not requested; "+
						"the request asked for %v", policy.name, action, resource, want)
				}
			}
		}
	})
}

// parseBasic reads a Basic credential the way net/http's BasicAuth does, which
// is what the server uses.
func parseBasic(authorization string) (user, password string, ok bool) {
	const prefix = "Basic "
	if len(authorization) < len(prefix) ||
		!strings.EqualFold(authorization[:len(prefix)], prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(authorization[len(prefix):])
	if err != nil {
		return "", "", false
	}

	user, password, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	return user, password, true
}

// accountKnown reports whether the policy has an entry for this name with this
// password.
func accountKnown(policy *authPolicy, name, password string) bool {
	for _, account := range policy.accounts {
		if account.name == name {
			return account.known && account.password == password
		}
	}
	return false
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// sendableHeaderValue reports whether net/http will put the value on the wire.
// It mirrors the rule in net/http: no control bytes other than horizontal tab.
func sendableHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

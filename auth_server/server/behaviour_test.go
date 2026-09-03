package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cesanta/docker_auth/auth_server/api"
	"github.com/cesanta/docker_auth/auth_server/authn"
)

// TestStaticUserWithoutPasswordAuthenticatesAnyPassword pins the behaviour that
// makes the `password` key mandatory for anything generating this config.
//
// authn/static_auth.go compares the password only when the entry has one:
//
//	if reqs.Password != nil { ...bcrypt... }
//	return AuthenticateResult{Authenticated: true, ...}
//
// So an entry with no password authenticates every password, the empty one
// included. This is upstream's documented behaviour and not a defect in itself,
// but it removes any margin for error from whatever writes the config: an
// omitted key is not a weaker password, it is no password at all.
//
// Registry module note. The node-side template
// (images/nodeservices-manager/app/internal/staticpod/templates/auth/config.yaml.tpl)
// writes `password: {{ quote .PasswordHash }}` unconditionally, so an empty hash
// still yields a non-nil entry whose bcrypt comparison fails and denies access.
// A template change that made the key conditional -- a `{{- with }}` around it,
// or omitting it when the hash is empty -- would silently turn that account into
// a passwordless one. This test states the property that change would break.
func TestStaticUserWithoutPasswordAuthenticatesAnyPassword(t *testing.T) {
	withHash := api.PasswordString("$2a$04$LX8DTgWXCsHDrQ6Wmv7Jyu5xhP4W.LKvQjV7hnCTxGX2wDU2Vhn0S")

	authenticator := authn.NewStaticUserAuth(map[string]*authn.Requirements{
		"no-password":   {},
		"with-password": {Password: &withHash},
	})

	for _, password := range []api.PasswordString{"", "anything", "wrong"} {
		result, err := authenticator.Authenticate("no-password", password)
		if err != nil {
			t.Fatalf("authenticating %q against an entry with no password failed: %v", password, err)
		}
		if !result.Authenticated {
			t.Fatalf("an entry with no password refused %q; the behaviour this test pins has changed, "+
				"which is an improvement -- update the note in the registry module's FUZZING.md", password)
		}
	}

	// The contrast: an entry that has a hash rejects a password that is not it.
	result, err := authenticator.Authenticate("with-password", "not-the-password")
	if err != nil {
		t.Fatalf("authenticating against an entry with a password failed: %v", err)
	}
	if result.Authenticated {
		t.Fatal("an entry with a password accepted the wrong one")
	}
}

// TestScopeTypeIsNotAnchored pins the reading of the scope grammar.
//
// server.go builds the resource type with
//
//	scopeRegex = regexp.MustCompile(`([a-z0-9]+)(\([a-z0-9]+\))?`)
//
// and FindStringSubmatch, which is not anchored. The type is therefore the first
// run of lowercase alphanumerics anywhere in the field, so "Xrepository",
// "repository!" and "..repository.." all name the type "repository", and a
// scope the resource grammar does not admit is accepted as one that it does.
//
// This is not an escalation under either policy the registry module ships: both
// decide on the account, and the one entry that does constrain the type
// (`{ account: puller, type: registry, name: catalog }`) grants nothing a
// client could not request with a well-formed scope. It matters for what could
// be written next -- an ACL entry that restricts by type cannot assume the type
// is the string the client sent, and a rule meant to apply to one type will
// also apply to every string containing it.
func TestScopeTypeIsNotAnchored(t *testing.T) {
	cases := []struct {
		raw   string
		want  string
		class string
	}{
		{raw: "repository", want: "repository"},
		{raw: "registry", want: "registry"},
		{raw: "repository(plugin)", want: "repository"},
		{raw: "Xrepository", want: "repository"},
		{raw: "repository!", want: "repository"},
		{raw: "..registry..", want: "registry"},
		{raw: "REPOSITORYrepository", want: "repository"},
	}

	for _, c := range cases {
		gotType, gotClass, err := parseScope(c.raw)
		if err != nil {
			t.Errorf("parseScope(%q) failed: %v", c.raw, err)
			continue
		}
		if gotType != c.want || gotClass != c.class {
			t.Errorf("parseScope(%q) = (%q, %q), pinned as (%q, %q)",
				c.raw, gotType, gotClass, c.want, c.class)
		}
	}

	// A field with no lowercase alphanumeric run has no type to find, and that
	// is the only case the parser rejects.
	if _, _, err := parseScope("REPOSITORY"); err == nil {
		t.Error("parseScope(\"REPOSITORY\") succeeded; only a field with no lowercase " +
			"alphanumeric run is expected to be rejected")
	}

	// The class is never returned. scopeRegex has two capture groups, so
	// FindStringSubmatch always yields three elements and parseScope's
	// `case 4: return parts[1], parts[3]` cannot be reached -- reaching it
	// would index past the slice. The class a scope declares is therefore
	// dropped, and authScope.Class is always empty.
	//
	// Nothing downstream reads it: MatchConditions has no class field, and
	// CreateToken puts only Type and Name in the token. So this is dead code
	// rather than a lost restriction -- but a future ACL that wanted to
	// distinguish `repository(plugin)` from `repository` would find the field
	// silently empty rather than absent, which is the more dangerous of the two.
	if _, class, err := parseScope("repository(plugin)"); err != nil || class != "" {
		t.Errorf("parseScope(\"repository(plugin)\") returned class %q (err %v); it is pinned as "+
			"always empty because the case that would return it is unreachable", class, err)
	}
}

// TestAccountOverridesAreRefused covers the one cross-field check ParseRequest
// makes: the `account` parameter may not disagree with the authenticated user.
// Without it a client could authenticate as one identity and be authorised as
// another, since Authorize keys entirely on ar.Account.
func TestAccountOverridesAreRefused(t *testing.T) {
	server := newBehaviourServer(t)

	query := url.Values{}
	query.Set("service", "registry")
	query.Set("scope", "repository:system/deckhouse:pull,push")
	query.Set("account", "rw-user")

	request, err := http.NewRequest(http.MethodGet, server.URL+"/auth?"+query.Encode(), nil)
	if err != nil {
		t.Fatalf("cannot build the auth request: %v", err)
	}
	request.SetBasicAuth("ro-user", "ro-password")

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("the auth request failed: %v", err)
	}
	response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("authenticating as ro-user while claiming account rw-user returned %s, expected 400",
			response.Status)
	}
}

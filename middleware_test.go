package caddy_oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	"github.com/shyndman/caddy-oidc/authenticator"
	"github.com/shyndman/caddy-oidc/internal/pkgtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPolicyProvisioned atomic.Bool

type testPolicyMatcher struct{}

func init() {
	caddy.RegisterModule(new(testPolicyMatcher))
}

func (*testPolicyMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.test_policy_provision",
		New: func() caddy.Module { return new(testPolicyMatcher) },
	}
}

func (*testPolicyMatcher) Provision(caddy.Context) error {
	testPolicyProvisioned.Store(true)

	return nil
}

func (*testPolicyMatcher) MatchWithError(*http.Request) (bool, error) {
	return true, nil
}

type TestHandler struct {
	calls int
}

func (h *TestHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	h.calls++

	w.WriteHeader(http.StatusOK)

	return nil
}

func TestOIDCMiddleware_Provision_ProvisionsPolicies(t *testing.T) {
	t.Parallel()

	testPolicyProvisioned.Store(false)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := "http://" + r.Host
		_, _ = fmt.Fprintf(w, `{
			"issuer": %q,
			"authorization_endpoint": %q,
			"token_endpoint": %q,
			"jwks_uri": %q
		}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/keys")
	}))
	t.Cleanup(server.Close)

	configJSON := fmt.Appendf(nil, `{
		"apps": {
			"oidc": {
				"default": {
					"issuer": %q,
					"client_id": "xyz",
					"authenticators": {
						"authenticators": [{"authenticator": "bearer"}]
					}
				}
			},
			"http": {
				"servers": {
					"test": {
						"routes": [{
							"handle": [{
								"handler": "oidc",
								"policies": [{
									"action": "allow",
									"match": {"test_policy_provision": {}}
								}]
							}]
						}]
					}
				}
			}
		}
	}`, server.URL)

	var config caddy.Config

	err := json.Unmarshal(configJSON, &config)
	require.NoError(t, err)
	require.NoError(t, caddy.Validate(&config))
	assert.True(t, testPolicyProvisioned.Load())
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_AuthorizationFlowSupported(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Sec-Fetch-Mode", "same-origin")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	r.Header.Set("Upgrade-Insecure-Requests", "1")

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, 0, h.calls)
	assert.Equal(t, http.StatusFound, w.Code)

	redir, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)

	assert.Equal(t, "http", redir.Scheme)
	assert.Equal(t, "openid", redir.Host)
	assert.Equal(t, "/example/authorize", redir.Path)
	assert.Equal(t, "S256", redir.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, redir.Query().Get("code_challenge"))
	assert.Equal(t, "code", redir.Query().Get("response_type"))
	assert.Equal(t, "xyz", redir.Query().Get("client_id"))
	assert.NotEmpty(t, redir.Query().Get("state"))
	assert.Equal(t, "http://example.com/oauth2/callback", redir.Query().Get("redirect_uri"))

	c, err := http.ParseSetCookie(w.Header().Get("Set-Cookie"))
	if assert.NoError(t, err) {
		assert.Equal(t, fmt.Sprintf("%s|%s", "test-cookie", redir.Query().Get("state")), c.Name)
	}
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_BearerOnly(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
	}

	auth.provider.Authenticators.Authenticators = []authenticator.RequestAuthenticator{
		&authenticator.BearerAuthenticator{},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Sec-Fetch-Dest", "document")

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.Equal(t, 0, h.calls)
	require.Error(t, err)

	var he caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &he) {
		assert.ErrorIs(t, he.Unwrap(), ErrAccessDenied)
		assert.Equal(t, http.StatusUnauthorized, he.StatusCode)
	}
}

func TestOIDCMiddleware_ServeHTTP_WithoutAuth_NoRedirectSupport(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.Equal(t, 0, h.calls)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusUnauthorized, ce.StatusCode)
	}

	wwwAuthenticate := w.Header().Get("WWW-Authenticate")
	assert.NotEmpty(t, wwwAuthenticate)
	assert.Equal(t, `Bearer resource_metadata="http://example.com/.well-known/oauth-protected-resource", scope="openid profile email offline_access"`, wwwAuthenticate)
}

func TestOIDCMiddleware_ServeHTTP_BearerOK(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
		Policies: Ruleset{
			{
				Action: ActionAllow,
				Matchers: caddyhttp.MatcherSet{
					&MatchUser{Usernames: []string{"*"}},
				},
			},
		},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(auth.provider.Clock().Add(time.Hour)))

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, h.calls)
	assert.Empty(t, r.Header.Get("Authorization"))
}

func TestOIDCMiddleware_ServeHTTP_WithBearerAuthentication_EmptyRuleset(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(auth.provider.Clock().Add(time.Hour)))

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.ErrorIs(t, err, ErrAccessDenied)
}

func TestOIDCMiddleware_ServeHTTP_WellKnownOAuthProtectedResource(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
	}

	auth.provider.ProtectedResource.Audience = true

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, 0, h.calls)

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.JSONEq(t, `{
  "resource": "http://example.com",
  "authorization_servers": [
    "https://openid/example"
  ],
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "offline_access"
  ],
  "bearer_methods_supported": [
    "header"
  ],
  "audience": "xyz"
}
`, w.Body.String())
}

func TestOIDCMiddleware_ServeHTTP_WellKnownOAuthProtectedResource_Disabled(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
	}

	auth.provider.ProtectedResource.Disable = true

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	assert.Equal(t, 0, h.calls)

	var ce caddyhttp.HandlerError
	if assert.ErrorAs(t, err, &ce) {
		assert.Equal(t, http.StatusNotFound, ce.StatusCode)
	}
}

func TestOIDCMiddleware_ServeHTTP_SetsReplacerVars(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
		Policies: Ruleset{
			{
				ID:     "TestRule",
				Action: ActionAllow,
				Matchers: caddyhttp.MatcherSet{
					&MatchUser{Usernames: []string{"*"}},
				},
			},
		},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(auth.provider.Clock().Add(time.Hour)))

	repl := caddyhttp.NewTestReplacer(r)

	h := new(TestHandler)

	err := auth.ServeHTTP(w, r, h)
	require.NoError(t, err)
	assert.Equal(t, 1, h.calls)

	assert.Equal(t, "false", repl.ReplaceAll("{http.auth.user.anonymous}", ""))
	assert.Equal(t, "test", repl.ReplaceAll("{http.auth.user.id}", ""))
	assert.Equal(t, "xyz", repl.ReplaceAll("{http.auth.user.claim.aud}", ""))
	assert.Equal(t, "read,write", repl.ReplaceAll("{http.auth.user.claim.roles}", ""))
	assert.Equal(t, "TestRule", repl.ReplaceAll("{http.auth.rule}", ""))
	assert.Equal(t, "allow", repl.ReplaceAll("{http.auth.result}", ""))
	assert.Equal(t, "bearer", repl.ReplaceAll("{http.auth.method}", ""))
}

func TestOIDCMiddleware_ServeHTTP_SetsReplacerVars_Header(t *testing.T) {
	t.Parallel()

	auth := &OIDCMiddleware{
		provider: GenerateTestProvider(),
		Policies: Ruleset{
			{
				ID:     "TestRule",
				Action: ActionAllow,
				Matchers: caddyhttp.MatcherSet{
					&MatchUser{Usernames: []string{"*"}},
				},
			},
		},
	}

	adapter := caddyconfig.GetAdapter("caddyfile")
	require.NotNil(t, adapter)

	config, _, err := adapter.Adapt([]byte(`:0 {
		header X-Placeholder {http.auth.user.claim.email} {
			defer
		}
	}`), nil)
	require.NoError(t, err)

	var adapted struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Handle []json.RawMessage `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}

	err = json.Unmarshal(config, &adapted)
	require.NoError(t, err)

	var headerHandler headers.Handler

	for _, server := range adapted.Apps.HTTP.Servers {
		for _, route := range server.Routes {
			for _, rawHandler := range route.Handle {
				var handler struct {
					Handler string `json:"handler"`
				}

				err = json.Unmarshal(rawHandler, &handler)
				require.NoError(t, err)

				if handler.Handler == "headers" {
					err = json.Unmarshal(rawHandler, &headerHandler)
					require.NoError(t, err)
				}
			}
		}
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+pkgtest.GenerateTestJWTExpiresAt(auth.provider.Clock().Add(time.Hour)))

	caddyhttp.NewTestReplacer(r)

	h := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return headerHandler.ServeHTTP(w, r, new(TestHandler))
	})

	err = auth.ServeHTTP(w, r, h)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "x@example.org", w.Header().Get("X-Placeholder"))
}

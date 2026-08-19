package caddy_oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/shyndman/caddy-oidc/authenticator"
	"github.com/shyndman/caddy-oidc/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchWildcard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		input   string
		expect  bool
	}{
		{
			name:    "exact match",
			pattern: "steve@example.com",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "exact match",
			pattern: "steve@example.com",
			input:   "bob@example.com",
			expect:  false,
		},
		{
			name:    "prefix wildcard match",
			pattern: "steve@*",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "prefix wildcard no match",
			pattern: "steve@*",
			input:   "bob@example.com",
			expect:  false,
		},
		{
			name:    "suffix wildcard match",
			pattern: "*@example.com",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "suffix wildcard no match",
			pattern: "*@example.com",
			input:   "steve@other.com",
			expect:  false,
		},
		{
			name:    "contains wildcard match",
			pattern: "*@example*",
			input:   "steve@example.com",
			expect:  true,
		},
		{
			name:    "contains wildcard no match",
			pattern: "*@example*",
			input:   "steve@other.com",
			expect:  false,
		},
		{
			name:    "match all wildcard",
			pattern: "*",
			input:   "anything@example.com",
			expect:  true,
		},
		{
			name:    "match all wildcard empty input",
			pattern: "*",
			input:   "",
			expect:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ok := MatchWildcard(tt.pattern, tt.input)
			assert.Equal(t, tt.expect, ok)
		})
	}
}

func TestMatchUser_MatchWithError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		session session.Session
		matcher MatchUser
		match   bool
	}{
		{
			name:    "match empty",
			session: session.Session{},
			matcher: MatchUser{},
			match:   true,
		},
		{
			name:    "match anonymous",
			session: session.Session{Anonymous: true},
			matcher: MatchUser{},
			match:   false,
		},
		{
			name:    "match any user",
			session: session.Session{UID: "steve@example.com"},
			matcher: MatchUser{
				Usernames: []string{"*"},
			},
			match: true,
		},
		{
			name:    "match exact multiple",
			session: session.Session{UID: "steve@example.com"},
			matcher: MatchUser{
				Usernames: []string{"bob@example.com", "steve@example.com"},
			},
			match: true,
		},
		{
			name:    "match exact with replacer variable",
			session: session.Session{UID: "steve@example.com"},
			matcher: MatchUser{
				Usernames: []string{"steve@{test.domain}"},
			},
			match: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			repl := caddy.NewReplacer()
			repl.Set("test.domain", "example.com")
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
			r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, &tt.session))

			ok, err := tt.matcher.MatchWithError(r)
			require.NoError(t, err)
			assert.Equal(t, tt.match, ok)
		})
	}
}

func TestMatchAnonymous_MatchWithError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		session *session.Session
		match   bool
	}{
		{
			name:    "match no session",
			session: nil,
			match:   true,
		},
		{
			name:    "match anonymous session",
			session: &session.Session{Anonymous: true},
			match:   true,
		},
		{
			name:    "no match authenticated session",
			session: &session.Session{UID: "steve@example.com"},
			match:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)

			if tt.session != nil {
				r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, tt.session))
			}

			matcher := MatchAnonymous{}
			ok, err := matcher.MatchWithError(r)
			require.NoError(t, err)
			assert.Equal(t, tt.match, ok)
		})
	}
}

func TestMatchClaim_MatchWithError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claims  string
		matcher MatchClaim
		match   bool
	}{
		{
			name:    "match no claim",
			claims:  `{}`,
			matcher: MatchClaim{},
			match:   true,
		},
		{
			name:   "match claim not exist",
			claims: `{}`,
			matcher: MatchClaim{
				{Name: "sub", Values: []string{"steve@example.com"}},
			},
			match: false,
		},
		{
			name:   "match claim with no values",
			claims: `{"foo": "bar"}`,
			matcher: MatchClaim{
				{Name: "foo"},
			},
			match: true,
		},
		{
			name:   "match claim with no values missing claim",
			claims: `{}`,
			matcher: MatchClaim{
				{Name: "foo"},
			},
			match: false,
		},
		{
			name:   "match claim exist incorrect type",
			claims: `{"sub": 1234}`,
			matcher: MatchClaim{
				{Name: "sub", Values: []string{"steve@example.com"}},
			},
			match: false,
		},
		{
			name:   "match claim string",
			claims: `{"sub": "steve@example.com"}`,
			matcher: MatchClaim{
				{Name: "sub", Values: []string{"steve@example.com"}},
			},
			match: true,
		},
		{
			name:   "match claim string any",
			claims: `{"sub": "steve@example.com"}`,
			matcher: MatchClaim{
				{Name: "sub", Values: []string{"bob@example.com", "steve@example.com"}},
			},
			match: true,
		},
		{
			name:   "match claim string wildcard",
			claims: `{"sub": "steve@example.com"}`,
			matcher: MatchClaim{
				{Name: "sub", Values: []string{"*@example.com"}},
			},
			match: true,
		},
		{
			name:   "match claim array any",
			claims: `{"role": ["write", "read"]}`,
			matcher: MatchClaim{
				{Name: "role", Values: []string{"read"}},
			},
			match: true,
		},
		{
			name:   "match claim array any in any",
			claims: `{"role": ["write", "read"]}`,
			matcher: MatchClaim{
				{Name: "role", Values: []string{"delete", "write"}},
			},
			match: true,
		},
		{
			name:   "match claim array any in all",
			claims: `{"role": ["write", "read"]}`,
			matcher: MatchClaim{
				{Name: "role", Values: []string{"read"}},
				{Name: "role", Values: []string{"write"}},
			},
			match: true,
		},
		{
			name:   "match claim array any wildcard",
			claims: `{"role": ["read:users", "read:settings", "write:settings"]}`,
			matcher: MatchClaim{
				{Name: "role", Values: []string{"delete", "write:*"}},
			},
			match: true,
		},
		{
			name:   "match claim string with replacer variable",
			claims: `{"host": "example.com"}`,
			matcher: MatchClaim{
				{Name: "host", Values: []string{"{http.host}"}},
			},
			match: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, &session.Session{
				Claims: json.RawMessage(tt.claims),
			}))

			repl := caddy.NewReplacer()
			repl.Set("http.host", "example.com")
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))

			ok, err := tt.matcher.MatchWithError(r)
			require.NoError(t, err)
			assert.Equal(t, tt.match, ok)
		})
	}
}

func TestMatchAuthMethod_MatchWithError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		method  authenticator.AuthMethod
		matcher MatchAuthMethod
		match   bool
	}{
		{
			name:   "unmatched",
			method: authenticator.AuthMethodNone,
			matcher: MatchAuthMethod{
				Match: []authenticator.AuthMethod{authenticator.AuthMethodCookie, authenticator.AuthMethodBearer},
			},
			match: false,
		},
		{
			name:   "match one",
			method: authenticator.AuthMethodCookie,
			matcher: MatchAuthMethod{
				Match: []authenticator.AuthMethod{authenticator.AuthMethodCookie},
			},
			match: true,
		},
		{
			name:   "match any",
			method: authenticator.AuthMethodCookie,
			matcher: MatchAuthMethod{
				Match: []authenticator.AuthMethod{authenticator.AuthMethodBearer, authenticator.AuthMethodCookie},
			},
			match: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = r.WithContext(context.WithValue(r.Context(), AuthMethodCtxKey, tt.method))

			ok, err := tt.matcher.MatchWithError(r)
			require.NoError(t, err)
			assert.Equal(t, tt.match, ok)
		})
	}
}

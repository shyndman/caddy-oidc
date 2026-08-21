package caddy_oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/shyndman/caddy-oidc/internal/directory"
	"github.com/shyndman/caddy-oidc/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testDirectoryRows struct {
	rows [][]string
	pos  int
}

func (f *testDirectoryRows) Next() bool {
	if f.pos >= len(f.rows) {
		return false
	}

	f.pos++

	return true
}

func (f *testDirectoryRows) Scan(dest ...any) error {
	row := f.rows[f.pos-1]

	for i, d := range dest {
		*(d.(*string)) = row[i] //nolint:forcetypeassert
	}

	return nil
}

func (*testDirectoryRows) Err() error                                   { return nil }
func (*testDirectoryRows) Close()                                       {}
func (*testDirectoryRows) Conn() *pgx.Conn                              { return nil }
func (f *testDirectoryRows) Values() ([]any, error)                     { return nil, nil }
func (*testDirectoryRows) RawValues() [][]byte                          { return nil }
func (*testDirectoryRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (*testDirectoryRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

type testDirectoryQueryer struct{ rows *testDirectoryRows }

func (q *testDirectoryQueryer) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return q.rows, nil
}

func testDirectory(t *testing.T) *directory.Directory {
	t.Helper()

	q := &testDirectoryQueryer{
		rows: &testDirectoryRows{
			rows: [][]string{
				{"x@example.org", "Alice", "admin"},
				{"x@example.org", "Alice", "reader"},
			},
		},
	}

	dir, err := directory.Load(context.Background(), q)
	require.NoError(t, err)

	return dir
}

// testAppWithRuntime returns an App whose runtime initializer returns the
// given prebuilt state, so a test can isolate request-time behavior without
// forcing database access or key parsing.
func testAppWithRuntime(runtime *appRuntime) *App {
	a := newApp()
	a.loadRuntime = sync.OnceValues(func() (*appRuntime, error) { return runtime, nil })
	return a
}

func TestMatchRole_MatchWithError(t *testing.T) {
	t.Parallel()

	app := testAppWithRuntime(&appRuntime{directory: testDirectory(t)})

	tests := []struct {
		name    string
		roles   []string
		session *session.Session
		expect  bool
	}{
		{
			name:    "match",
			roles:   []string{"admin"},
			session: &session.Session{Claims: json.RawMessage(`{"email": "x@example.org"}`)},
			expect:  true,
		},
		{
			name:    "match with placeholder",
			roles:   []string{"{test.role}"},
			session: &session.Session{Claims: json.RawMessage(`{"email": "x@example.org"}`)},
			expect:  true,
		},
		{
			name:    "match with different case",
			roles:   []string{"admin"},
			session: &session.Session{Claims: json.RawMessage(`{"email": "X@Example.ORG"}`)},
			expect:  true,
		},
		{
			name:    "no matching role",
			roles:   []string{"owner"},
			session: &session.Session{Claims: json.RawMessage(`{"email": "x@example.org"}`)},
			expect:  false,
		},
		{
			name:    "multiple roles OR",
			roles:   []string{"owner", "reader"},
			session: &session.Session{Claims: json.RawMessage(`{"email": "x@example.org"}`)},
			expect:  true,
		},
		{
			name:    "comma-split roles OR",
			roles:   []string{"admin", "reader"},
			session: &session.Session{Claims: json.RawMessage(`{"email": "x@example.org"}`)},
			expect:  true,
		},
		{
			name:    "anonymous",
			roles:   []string{"admin"},
			session: &session.Session{Anonymous: true},
			expect:  false,
		},
		{
			name:    "no session",
			roles:   []string{"admin"},
			session: nil,
			expect:  false,
		},
		{
			name:    "no email claim",
			roles:   []string{"admin"},
			session: &session.Session{Claims: json.RawMessage(`{"sub": "test"}`)},
			expect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matcher := &MatchRole{Roles: tt.roles, app: app}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			repl := caddy.NewReplacer()
			repl.Set("test.role", "admin")
			r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl))
			if tt.session != nil {
				r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, tt.session))
			}

			got, err := matcher.MatchWithError(r)
			require.NoError(t, err)
			assert.Equal(t, tt.expect, got)
		})
	}
}

func TestMatchRole_MatchWithError_EmptyRoles(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, &session.Session{
		Claims: json.RawMessage(`{"email": "x@example.org"}`),
	}))

	matcher := &MatchRole{app: testAppWithRuntime(&appRuntime{directory: testDirectory(t)})}

	got, err := matcher.MatchWithError(r)
	require.NoError(t, err)
	assert.False(t, got)
}

func TestMatchRole_MatchWithError_NoDirectory(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, &session.Session{
		Claims: json.RawMessage(`{"email": "x@example.org"}`),
	}))

	matcher := &MatchRole{Roles: []string{"admin"}, app: testAppWithRuntime(&appRuntime{})}

	_, err := matcher.MatchWithError(r)
	require.Error(t, err)
}

func TestRuleset_UnmarshalCaddyfile_RoleShorthand(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser(`{
		allow residents, media_consumers
		deny guests
	}`)

	var ruleset Ruleset

	err := ruleset.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	require.Len(t, ruleset, 2)

	var allowMatcher MatchRole
	require.NoError(t, json.Unmarshal(ruleset[0].MatcherSetsRaw["role"], &allowMatcher))
	assert.Equal(t, ActionAllow, ruleset[0].Action)
	assert.Equal(t, []string{"residents", "media_consumers"}, allowMatcher.Roles)

	var denyMatcher MatchRole
	require.NoError(t, json.Unmarshal(ruleset[1].MatcherSetsRaw["role"], &denyMatcher))
	assert.Equal(t, ActionDeny, ruleset[1].Action)
	assert.Equal(t, []string{"guests"}, denyMatcher.Roles)
}

func TestRuleset_UnmarshalCaddyfile_RoleShorthand_NoCommas(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser(`{
		allow residents media_consumers
	}`)

	var ruleset Ruleset

	err := ruleset.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	require.Len(t, ruleset, 1)

	var matcher MatchRole
	require.NoError(t, json.Unmarshal(ruleset[0].MatcherSetsRaw["role"], &matcher))
	assert.Equal(t, []string{"residents", "media_consumers"}, matcher.Roles)
}

func TestOIDCMiddleware_UnmarshalCaddyfile_SingleLineRoles(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser(`oidc allow residents, media_consumers`)

	var mw OIDCMiddleware

	err := mw.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	require.Len(t, mw.Policies, 1)
	assert.Equal(t, ActionAllow, mw.Policies[0].Action)

	var matcher MatchRole
	require.NoError(t, json.Unmarshal(mw.Policies[0].MatcherSetsRaw["role"], &matcher))
	assert.Equal(t, []string{"residents", "media_consumers"}, matcher.Roles)
}

func TestOIDCMiddleware_UnmarshalCaddyfile_RoleBlock(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser(`oidc {
		allow residents, media_consumers
	}`)

	var mw OIDCMiddleware

	err := mw.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	require.Len(t, mw.Policies, 1)

	var matcher MatchRole
	require.NoError(t, json.Unmarshal(mw.Policies[0].MatcherSetsRaw["role"], &matcher))
	assert.Equal(t, []string{"residents", "media_consumers"}, matcher.Roles)
}

func TestMatchRole_RequestForcesInitializationBeforeStart(t *testing.T) {
	t.Parallel()

	var count atomic.Int32

	a := newApp()
	a.loadRuntime = sync.OnceValues(func() (*appRuntime, error) {
		count.Add(1)
		return &appRuntime{directory: testDirectory(t)}, nil
	})
	matcher := &MatchRole{Roles: []string{"admin"}, app: a}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	r = r.WithContext(context.WithValue(r.Context(), SessionCtxKey, &session.Session{
		Claims: json.RawMessage(`{"email": "x@example.org"}`),
	}))

	got, err := matcher.MatchWithError(r)
	require.NoError(t, err)
	assert.True(t, got)

	require.NoError(t, a.Start())
	require.Equal(t, int32(1), count.Load())
}

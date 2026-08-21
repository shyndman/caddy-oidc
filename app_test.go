package caddy_oidc

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGlobalConfig_DefaultProvider(t *testing.T) {
	t.Parallel()

	_, app := parseGlobalOIDCConfig(t, nil, `oidc {
		issuer http://openid/default
		client_id default-client
		scope openid email
	}`)

	assert.Equal(t, "http://openid/default", app.Default.Issuer)
	assert.Equal(t, "default-client", app.Default.ClientID)
	assert.Equal(t, []string{"openid", "email"}, app.Default.Scope)
	assert.Empty(t, app.Providers)
}

func TestParseGlobalConfig_NamedProviderInheritsCurrentDefault(t *testing.T) {
	t.Parallel()

	parsed, _ := parseGlobalOIDCConfig(t, nil, `oidc {
		issuer http://openid/default
		client_id default-client
		scope openid email
	}`)

	_, app := parseGlobalOIDCConfig(t, parsed, `oidc named {
		client_id named-client
		scope profile
	}`)

	require.Contains(t, app.Providers, "named")

	named, err := app.GetInheritedProvider("named")
	require.NoError(t, err)

	assert.Equal(t, "http://openid/default", named.Issuer)
	assert.Equal(t, "named-client", named.ClientID)
	assert.Equal(t, []string{"profile"}, named.Scope)

	assert.Equal(t, "http://openid/default", app.Default.Issuer)
	assert.Equal(t, "default-client", app.Default.ClientID)
	assert.Equal(t, []string{"openid", "email"}, app.Default.Scope)
}

func TestParseGlobalConfig_DefaultChangesAfterNamedProviderAreReflected(t *testing.T) {
	t.Parallel()

	parsed, _ := parseGlobalOIDCConfig(t, nil, `oidc {
		issuer http://openid/default
		client_id default-client
		scope openid email
	}`)

	parsed, _ = parseGlobalOIDCConfig(t, parsed, `oidc named {
		client_id named-client
		scope profile
	}`)

	_, app := parseGlobalOIDCConfig(t, parsed, `oidc {
		issuer http://openid/updated-default
		scope groups
	}`)

	require.Contains(t, app.Providers, "named")

	named, err := app.GetInheritedProvider("named")
	require.NoError(t, err)

	assert.Equal(t, "http://openid/updated-default", app.Default.Issuer)
	assert.Equal(t, "default-client", app.Default.ClientID)
	assert.Equal(t, []string{"openid", "email", "groups"}, app.Default.Scope)

	assert.Equal(t, "http://openid/updated-default", named.Issuer)
	assert.Equal(t, "named-client", named.ClientID)
	assert.Equal(t, []string{"profile"}, named.Scope)
}

func TestParseGlobalConfig_AppDirectivesAcceptedInDefaultBlock(t *testing.T) {
	t.Parallel()

	_, app := parseGlobalOIDCConfig(t, nil, `oidc {
		postgres postgres://directory
	}`)

	assert.Equal(t, "postgres://directory", app.Postgres)
}

func TestParseGlobalConfig_AppDirectivesRejectedInNamedProvider(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser(`oidc named {
		postgres postgres://directory
	}`)

	_, err := parseGlobalConfig(d, nil)
	require.ErrorContains(t, err, "unrecognized subdirective")
}

func TestParseGlobalConfig_UserTokenRejected(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser(`oidc {
		user_token {
			private_key /run/secrets/user-token.pem
		}
	}`)

	_, err := parseGlobalConfig(d, nil)
	require.ErrorContains(t, err, "unrecognized subdirective")
}

func parseGlobalOIDCConfig(t *testing.T, prev any, input string) (httpcaddyfile.App, App) {
	t.Helper()

	d := caddyfile.NewTestDispenser(input)
	parsed, err := parseGlobalConfig(d, prev)
	require.NoError(t, err)

	globalApp, ok := parsed.(httpcaddyfile.App)
	require.True(t, ok)
	require.Equal(t, moduleID, globalApp.Name)

	var app App

	err = json.Unmarshal(globalApp.Value, &app)
	require.NoError(t, err)

	return globalApp, app
}

// TestAppRuntime_ConcurrentInitializersRunOnce proves that concurrent request
// and Start paths wait for one initializer and observe the same runtime.
func TestAppRuntime_ConcurrentInitializersRunOnce(t *testing.T) {
	t.Parallel()

	var (
		count   atomic.Int32
		started = make(chan struct{})
		release = make(chan struct{})
		got     *appRuntime
	)

	rt := sync.OnceValues(func() (*appRuntime, error) {
		count.Add(1)
		started <- struct{}{}
		<-release
		return &appRuntime{}, nil
	})

	a := newApp()
	a.loadRuntime = rt

	results := make(chan error, 2)
	fromRequest := func() {
		r, err := a.runtime()
		if err == nil {
			got = r
		}
		results <- err
	}
	fromStart := func() {
		results <- a.Start()
	}

	go fromRequest()
	go fromStart()

	<-started
	release <- struct{}{}

	err1 := <-results
	err2 := <-results
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, int32(1), count.Load())
	assert.Equal(t, &appRuntime{}, got)
}

// TestAppRuntime_ErrorsAreCached proves that an initialization failure from a
// request-first call is cached, so the later Start call returns the same
// failure without re-running the initializer.
func TestAppRuntime_ErrorsAreCached(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("database unreachable")
	count := atomic.Int32{}

	a := newApp()
	a.loadRuntime = sync.OnceValues(func() (*appRuntime, error) {
		count.Add(1)
		return nil, sentinel
	})

	_, err1 := a.runtime()
	assert.Same(t, sentinel, err1)

	err2 := a.Start()
	assert.Same(t, sentinel, err2)

	require.Equal(t, int32(1), count.Load())
}

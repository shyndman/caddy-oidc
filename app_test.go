package caddy_oidc

import (
	"encoding/json"
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
		user_token {
			private_key /run/secrets/user-token.pem
		}
	}`)

	assert.Equal(t, "postgres://directory", app.Postgres)
	require.NotNil(t, app.UserToken)
	assert.Equal(t, "/run/secrets/user-token.pem", app.UserToken.PrivateKey)
}

func TestParseGlobalConfig_AppDirectivesRejectedInNamedProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name: "postgres",
			input: `oidc named {
				postgres postgres://directory
			}`,
		},
		{
			name: "user_token",
			input: `oidc named {
				user_token {
					private_key /run/secrets/user-token.pem
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			d := caddyfile.NewTestDispenser(tt.input)
			_, err := parseGlobalConfig(d, nil)
			require.ErrorContains(t, err, "unrecognized subdirective")
		})
	}
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

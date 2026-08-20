package authenticator

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/shyndman/caddy-oidc/internal/pkgtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderAuthenticator_UnmarshalCaddyfile(t *testing.T) {
	t.Parallel()

	d := caddyfile.NewTestDispenser("X-Foo")

	var au HeaderAuthenticator

	err := au.UnmarshalCaddyfile(d)
	require.NoError(t, err)
	require.Equal(t, "X-Foo", au.Header)
}

func TestHeaderAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = HeaderAuthenticator{
			Header: "X-Api-Key",
		}
	)

	expiresAt := cfg.Now().Add(time.Hour)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Api-Key", pkgtest.GenerateTestJWTExpiresAt(expiresAt))

	s, err := au.AuthenticateRequest(&cfg, r)
	require.NoError(t, err)
	assert.Equal(t, expiresAt.Unix(), s.ExpiresAt)
}

func TestHeaderAuthenticator_AuthenticateRequest_MissingHeader(t *testing.T) {
	t.Parallel()

	var (
		cfg pkgtest.TestOIDCConfiguration
		au  = HeaderAuthenticator{
			Header: "X-Api-Key",
		}
	)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := au.AuthenticateRequest(&cfg, r)
	assert.ErrorIs(t, err, ErrNoAuthentication)
}

func TestHeaderAuthenticator_StripRequest(t *testing.T) {
	t.Parallel()

	var au = HeaderAuthenticator{
		Header: "X-Api-Key",
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Api-Key", "xyz")

	au.StripRequest(r)

	assert.Empty(t, r.Header.Get("X-Api-Key"))
}

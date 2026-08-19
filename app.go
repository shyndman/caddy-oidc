// Package caddy_oidc is a Caddy plugin for providing authentication and authorization using an OIDC IdP
package caddy_oidc

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/shyndman/caddy-oidc/authenticator" // Registers the built-in authenticator modules
	"github.com/shyndman/caddy-oidc/internal/baseline"
)

const moduleID = "oidc"

func init() {
	caddy.RegisterModule(new(App))
	httpcaddyfile.RegisterGlobalOption("oidc", parseGlobalConfig)
}

func parseGlobalConfig(d *caddyfile.Dispenser, prev any) (any, error) {
	var app App

	switch prev := prev.(type) {
	case httpcaddyfile.App:
		err := json.Unmarshal(prev.Value, &app)
		if err != nil {
			return nil, err
		}
	case nil:
		// Hasn't been initialized yet
	default:
		return nil, fmt.Errorf("conflicting global parser option for the oidc directive: %T", prev)
	}

	for d.Next() {
		// Default target is the global default
		var mod = &app.Default

		// If there is an argument, then define a named provider
		if d.NextArg() {
			var name = d.Val()

			if app.Providers == nil {
				app.Providers = make(map[string]*OIDCProviderModule)
			}

			var ok bool

			mod, ok = app.Providers[name]
			if !ok {
				mod = new(OIDCProviderModule)
				app.Providers[name] = mod
			}
		}

		err := mod.UnmarshalCaddyfile(d)
		if err != nil {
			return nil, err
		}
	}

	return httpcaddyfile.App{
		Name:  moduleID,
		Value: caddyconfig.JSON(&app, nil),
	}, nil
}

func parseCaddyfileHandler[T any, Ptr interface {
	*T
	caddyfile.Unmarshaler
	caddyhttp.MiddlewareHandler
}](h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(T)

	err := Ptr(handler).UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}

	return Ptr(handler), nil
}

var _ caddy.App = (*App)(nil)
var _ caddy.Module = (*App)(nil)

// App holds configuration for all the named OIDC providers within a Caddy configuration.
type App struct {
	// Default contains the default / baseline OIDC configuration for this App.
	// The Default is used as a baseline configuration during caddyfile unmarshalling of named providers
	// and can be referenced directly in an OIDCMiddleware when a provider is not defined.
	Default   OIDCProviderModule             `json:"default"`
	Providers map[string]*OIDCProviderModule `json:"providers,omitempty"`
}

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  moduleID,
		New: func() caddy.Module { return new(App) },
	}
}

func (*App) Start() error { return nil }
func (*App) Stop() error  { return nil }

// GetInheritedProvider returns the OIDCProviderModule for the given name.
// If the name is empty, then the default provider is returned.
// If the named provider is not configured, then an error is returned.
//
// If a named provider is configured, then the baseline configuration is applied to the provider
// from the application global default provider configuration.
//
// The caller must not modify the returned provider.
func (a *App) GetInheritedProvider(name string) (*OIDCProviderModule, error) {
	if name == "" {
		return &a.Default, nil
	}

	mod, ok := a.Providers[name]
	if !ok {
		return nil, fmt.Errorf("oidc: named provider '%s' is not configured", name)
	}

	// Create a copy of the reference module
	// Then apply the global default as a baseline
	copied := new(OIDCProviderModule)
	*copied = *mod

	baseline.Apply(copied, &a.Default)

	return copied, nil
}

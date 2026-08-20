// Package caddy_oidc is a Caddy plugin for providing authentication and authorization using an OIDC IdP
package caddy_oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jackc/pgx/v5"
	_ "github.com/shyndman/caddy-oidc/authenticator" // Registers the built-in authenticator modules
	"github.com/shyndman/caddy-oidc/internal/baseline"
	"github.com/shyndman/caddy-oidc/internal/directory"
	"github.com/shyndman/caddy-oidc/internal/token"
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
		namedProvider := d.NextArg()
		if namedProvider {
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

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			ok, err := unmarshalGlobalToken(d, &app, mod, namedProvider)
			if err != nil {
				return nil, err
			}

			if !ok {
				return nil, d.SyntaxErr("unrecognized subdirective")
			}
		}
	}

	return httpcaddyfile.App{
		Name:  moduleID,
		Value: caddyconfig.JSON(&app, nil),
	}, nil
}

func unmarshalGlobalToken(
	d *caddyfile.Dispenser,
	app *App,
	mod *OIDCProviderModule,
	namedProvider bool,
) (bool, error) {
	if namedProvider {
		return mod.UnmarshalCaddyfileToken(d)
	}

	return unmarshalAppOrProviderToken(d, app, mod)
}

// unmarshalAppOrProviderToken parses a single subdirective from the global
// oidc block. App-level options (postgres, user_token) apply to App; the rest
// are delegated to the provider.
func unmarshalAppOrProviderToken(d *caddyfile.Dispenser, app *App, mod *OIDCProviderModule) (bool, error) {
	switch d.Val() {
	case "postgres":
		if !d.Args(&app.Postgres) {
			return false, d.ArgErr()
		}

		return true, nil
	case "user_token":
		cfg := new(UserTokenConfig)

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "private_key":
				if !d.Args(&cfg.PrivateKey) {
					return false, d.ArgErr()
				}
			default:
				return false, d.SyntaxErr("unrecognized user_token subdirective")
			}
		}

		app.UserToken = cfg

		return true, nil
	default:
		return mod.UnmarshalCaddyfileToken(d)
	}
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

	// Postgres is the connection string for the read-only PostgreSQL database
	// that backs the authorization directory. When set, the directory is
	// loaded into memory at each startup.
	Postgres string `json:"postgres,omitempty"`

	// UserToken configures the signed user token that identifies the
	// authenticated user to downstream services.
	UserToken *UserTokenConfig `json:"user_token,omitempty"`

	// loadRuntime initializes once and caches the authorization directory and
	// user token signer. It is normally forced by Start, but an early request
	// can force the same one-time load and wait for its result.
	loadRuntime func() (*appRuntime, error)
}

// appRuntime is the immutable runtime state of the app. It is published as a
// unit so no reader observes a partially initialized directory or signer.
type appRuntime struct {
	directory *directory.Directory
	minter    *token.Minter
}

// newApp creates an App with a one-time runtime initializer that reads the
// decoded configuration only when first invoked.
func newApp() *App {
	a := new(App)
	a.loadRuntime = sync.OnceValues(a.initializeRuntime)
	return a
}

// runtime forces or returns the loaded runtime state. It returns the same
// complete value to every caller, or the same cached error.
func (a *App) runtime() (*appRuntime, error) {
	return a.loadRuntime()
}

// UserTokenConfig holds the configuration for the signed user token.
type UserTokenConfig struct {
	// PrivateKey is the PEM-encoded ES256 (P-256) private key used to sign
	// user tokens. It supports Caddy placeholders such as {env.KEY} and
	// {file./path/to/key}.
	PrivateKey string `json:"private_key"`
}

func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  moduleID,
		New: func() caddy.Module { return newApp() },
	}
}

// directoryLoadTimeout bounds a single directory load at startup so that an
// unreachable database cannot hang the proxy indefinitely.
const directoryLoadTimeout = 10 * time.Second

// Start forces the one-time runtime initialization and reports its result.
// On failure, the configuration fails to load and Caddy keeps serving the
// previous configuration. After initialization, request paths use the cached
// directory and signer; they never touch the database.
func (a *App) Start() error {
	_, err := a.runtime()
	return err
}

func (*App) Stop() error { return nil }

// initializeRuntime constructs the authorization directory and user token
// signer as local values and publishes them together. It returns no partial
// state after a failure.
func (a *App) initializeRuntime() (*appRuntime, error) {
	rt := &appRuntime{}

	if a.Postgres != "" {
		dir, err := a.loadDirectory()
		if err != nil {
			return nil, fmt.Errorf("oidc: load authorization directory: %w", err)
		}
		rt.directory = dir
	}

	if a.UserToken != nil {
		minter, err := a.createMinter()
		if err != nil {
			return nil, fmt.Errorf("oidc: set up user token signer: %w", err)
		}
		rt.minter = minter
	}

	return rt, nil
}

func (a *App) loadDirectory() (*directory.Directory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), directoryLoadTimeout)
	defer cancel()

	conn, err := pgx.Connect(ctx, a.Postgres)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	defer conn.Close(context.Background())

	dir, err := directory.Load(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("load directory: %w", err)
	}

	return dir, nil
}

func (a *App) createMinter() (*token.Minter, error) {
	keyPEM := caddy.NewReplacer().ReplaceAll(a.UserToken.PrivateKey, "")

	minter, err := token.NewFromPEM([]byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return minter, nil
}

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

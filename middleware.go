package caddy_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/shyndman/caddy-oidc/authenticator"
	"github.com/shyndman/caddy-oidc/internal/baseline"
	"github.com/shyndman/caddy-oidc/internal/directory"
	"github.com/shyndman/caddy-oidc/request"
	"github.com/shyndman/caddy-oidc/session"
	"github.com/tidwall/gjson"
)

func init() {
	caddy.RegisterModule(new(OIDCMiddleware))
	httpcaddyfile.RegisterHandlerDirective("oidc", parseCaddyfileHandler[OIDCMiddleware])
	httpcaddyfile.RegisterDirectiveOrder("oidc", httpcaddyfile.Before, "basicauth")
}

const (
	// SessionCtxKey is the context key used to store the authentication session object.
	// The context value is of type *Session.
	SessionCtxKey caddy.CtxKey = "oidc_session"
	// AuthMethodCtxKey is the context key used to store the authentication method used for the incoming request.
	// The context value is of type AuthMethod.
	AuthMethodCtxKey caddy.CtxKey = "oidc_auth_method"
)

// ErrAccessDenied is returned when the request is denied access.
var ErrAccessDenied = errors.New("access denied")

var _ caddy.Module = (*OIDCMiddleware)(nil)
var _ caddy.Provisioner = (*OIDCMiddleware)(nil)
var _ caddy.Validator = (*OIDCMiddleware)(nil)
var _ caddyfile.Unmarshaler = (*OIDCMiddleware)(nil)
var _ caddyhttp.MiddlewareHandler = (*OIDCMiddleware)(nil)

// OIDCMiddleware is a middleware that authenticates and authorizes requests based on configured rules.
// It contains its own OIDC provider configuration.
// During provisioning, it applies the inherited baseline configuration to the local configuration.
type OIDCMiddleware struct {
	OIDCProviderModule

	// Inherits is the name of a globally configured OIDC provider to inherit settings from.
	// The inherited configuration will be merged with the local configuration.
	Inherits string  `json:"inherits,omitempty"`
	Policies Ruleset `json:"policies"`

	provider *Provider
	app      *App
}

// WellKnownJWKSURLPath is the well-known path that serves the JSON Web Key
// Set of the user token signing key.
const WellKnownJWKSURLPath = "/.well-known/jwks.json"

func (mw *OIDCMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidc",
		New: func() caddy.Module { return new(OIDCMiddleware) },
	}
}

// UnmarshalCaddyfile sets up the OIDCMiddleware from Caddyfile tokens.
/*
	oidc [example] {

		allow|deny {
			...
		}
    }
*/
func (mw *OIDCMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			// `oidc allow role1, role2` is shorthand for a role-based
			// allow rule with the default provider.
			if d.Val() == "allow" || d.Val() == "deny" {
				if err := mw.unmarshalRoleLine(d); err != nil {
					return err
				}

				continue
			}

			mw.Inherits = d.Val()
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			ok, err := mw.OIDCProviderModule.UnmarshalCaddyfileToken(d)
			if err != nil {
				return err
			}

			if ok {
				continue
			}

			ok, err = mw.Policies.UnmarshalCaddyfileToken(d)
			if err != nil {
				return err
			}

			if ok {
				continue
			}

			return d.SyntaxErr("unrecognized subdirective")
		}
	}

	return nil
}

// unmarshalRoleLine parses the single-line role shorthand of the oidc
// directive: `oidc allow residents, media_consumers`.
func (mw *OIDCMiddleware) unmarshalRoleLine(d *caddyfile.Dispenser) error {
	var pol Rule

	switch d.Val() {
	case "allow":
		pol.Action = ActionAllow
	case "deny":
		pol.Action = ActionDeny
	}

	var args []string

	for d.NextArg() {
		args = append(args, d.Val())
	}

	matcherConfig, err := json.Marshal(MatchRole{Roles: splitRoleArgs(args)})
	if err != nil {
		return err
	}

	pol.MatcherSetsRaw = caddy.ModuleMap{"role": matcherConfig}

	mw.Policies = append(mw.Policies, &pol)

	return nil
}

// Provision sets up the OIDCMiddleware by loading the configured OIDC provider
// and then provisioning the configured ruleset for the middleware.
// The named provider must be configured.
func (mw *OIDCMiddleware) Provision(ctx caddy.Context) error {
	val, err := ctx.AppIfConfigured(moduleID)
	if err != nil {
		return err
	}

	app := val.(*App) //nolint:forcetypeassert

	mw.app = app

	// Get the inherited provider configuration.
	base, err := app.GetInheritedProvider(mw.Inherits)
	if err != nil {
		return err
	}

	// Apply the inherited baseline to our provider configuration.
	baseline.Apply(&mw.OIDCProviderModule, base)

	err = mw.OIDCProviderModule.Provision(ctx)
	if err != nil {
		return err
	}

	mw.provider, err = mw.OIDCProviderModule.Create(ctx)
	if err != nil {
		return err
	}

	err = mw.Policies.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

// Validate validates the configuration of the OIDCMiddleware.
func (mw *OIDCMiddleware) Validate() error {
	if mw.provider == nil {
		return errors.New("provider not provisioned")
	}

	return errors.Join(
		mw.OIDCProviderModule.Validate(),
		mw.Policies.Validate(),
	)
}

func (*OIDCMiddleware) setReplacerVars(repl *caddy.Replacer, session *session.Session, authMethod authenticator.AuthMethod) {
	repl.Set("http.auth.method", authMethod.String())
	repl.Set("http.auth.user.anonymous", session.Anonymous)

	if !session.Anonymous {
		repl.Set("http.auth.user.id", session.UID)
	}

	claimValues := gjson.ParseBytes(session.Claims)
	claimValues.ForEach(func(key, value gjson.Result) bool {
		var valueStringBuilder strings.Builder

		switch {
		case value.IsArray():
			for i, v := range value.Array() {
				if i > 0 {
					valueStringBuilder.WriteByte(',')
				}

				valueStringBuilder.WriteString(v.String())
			}
		default:
			valueStringBuilder.WriteString(value.String())
		}

		repl.Set("http.auth.user.claim."+key.String(), valueStringBuilder.String())

		return true
	})
}

// interceptRequest intercepts the request and performs authentication and authorization checks.
// If returns "true" if the request was handled and a response was written.
func (mw *OIDCMiddleware) interceptRequest(rw http.ResponseWriter, r *http.Request) (bool, error) {
	// Check if the request is an OAuth callback.
	// Only supported if there is a session cookie authenticator configuration.
	if r.Method == http.MethodGet {
		cookie, ok := authenticator.GetAuthenticator[*authenticator.SessionCookieAuthenticator](&mw.provider.Authenticators)
		if ok && cookie.IsCallbackURL(r) {
			return true, cookie.HandleCallback(mw.provider, rw, r)
		}
	}

	// Check for supported well-knowns
	if r.Method == http.MethodGet && r.URL.Path == WellKnownOAuthProtectedResourcePath {
		return true, mw.provider.ServeHTTPOAuthProtectedResource(rw, r)
	}
	if r.Method == http.MethodGet && r.URL.Path == WellKnownJWKSURLPath {
		return true, mw.serveJWKS(rw)
	}

	authMethod, s, err := mw.provider.Authenticators.AuthenticateRequest(mw.provider, r)
	if err != nil {
		return false, err
	}

	// Strip the request if configured
	mw.provider.Authenticators.StripRequest(r)

	// Set replacer vars
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		mw.setReplacerVars(repl, s, authMethod)
	}

	// Inject context vars
	ctx := context.WithValue(r.Context(), SessionCtxKey, s)
	ctx = context.WithValue(ctx, AuthMethodCtxKey, authMethod)

	r = r.WithContext(ctx)

	result, err := mw.Policies.Evaluate(r)
	if err != nil {
		return false, err
	}

	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.rule", result.RuleID)
		repl.Set("http.auth.result", result.Result.String())
	}

	switch result.Result {
	case EvaluationResultAllow:
		if err := mw.mintUserToken(r, s); err != nil {
			return false, err
		}

		return false, nil
	case EvaluationResultExplicitDeny:
	case EvaluationResultImplicitDeny:
		// If the evaluation result is an implicit reject, then check if the session is anonymous.
		// If anonymous:
		//		Start the authorization flow if the request is likely coming from a browser (if session cookies are enabled).
		//		Otherwise, return a 401 Unauthorized error.
		if s.Anonymous {
			if r.Method == http.MethodGet && request.IsBrowserInteractive(r) {
				cookie, ok := authenticator.GetAuthenticator[*authenticator.SessionCookieAuthenticator](&mw.provider.Authenticators)
				if ok {
					return true, cookie.StartLogin(mw.provider, rw, r)
				}
			}

			if rs, ok := mw.provider.ProtectedResourceMetadata(r); ok {
				rw.Header().Set("WWW-Authenticate", rs.WWWAuthenticate())
			}

			return false, caddyhttp.Error(http.StatusUnauthorized, ErrAccessDenied)
		}
	}

	return false, caddyhttp.Error(http.StatusForbidden, ErrAccessDenied)
}

// mintUserToken signs a user token for an authenticated request that the
// downstream application will receive as an Authorization header.
// It mints nothing when user_token is not configured or the request is
// anonymous, and returns an error only when signing genuinely fails.
func (mw *OIDCMiddleware) mintUserToken(r *http.Request, s *session.Session) error {
	if mw.app == nil || mw.app.minter == nil {
		return nil
	}

	if s == nil || s.Anonymous {
		return nil
	}

	email := gjson.GetBytes(s.Claims, "email")
	if !email.Exists() || email.Type != gjson.String {
		return nil
	}

	normalizedEmail := directory.NormalizeEmail(email.String())

	var (
		name  string
		roles []string
	)

	if dir := mw.app.Directory(); dir != nil {
		if u, ok := dir.User(normalizedEmail); ok {
			name = u.Name
			roles = u.Roles
		}
	}

	tokenString, err := mw.app.minter.Sign(mw.provider.Issuer, normalizedEmail, name, roles, mw.provider.Now(), s.Expires())
	if err != nil {
		return err
	}

	r.Header.Set("Authorization", "Bearer "+tokenString)

	return nil
}

// serveJWKS writes the public key for user token verification at the well-known
// JWKS path. It returns 404 when user_token is not configured.
func (mw *OIDCMiddleware) serveJWKS(rw http.ResponseWriter) error {
	if mw.app == nil || mw.app.minter == nil {
		return caddyhttp.Error(http.StatusNotFound, errors.New("user_token is not configured"))
	}

	payload, err := mw.app.minter.JWKS()
	if err != nil {
		return err
	}

	rw.Header().Set("Content-Type", "application/jwk-set+json")
	_, _ = rw.Write(payload)

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
// It wraps interceptRequest to handle errors to ensure any error returned is a caddyhttp.HandlerError.
// Without this, Caddy's error_directive does not properly set error replacer vars,
// which can result in HTTP 200 responses when it tries to parse `{err.status_code}`.
func (mw *OIDCMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	handled, err := mw.interceptRequest(rw, r)
	if err != nil {
		var he caddyhttp.HandlerError
		if !errors.As(err, &he) {
			he = caddyhttp.Error(http.StatusInternalServerError, err)
		}

		return he
	}

	if handled {
		return nil
	}

	return next.ServeHTTP(rw, r)
}

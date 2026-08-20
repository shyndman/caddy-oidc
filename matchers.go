package caddy_oidc

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/shyndman/caddy-oidc/authenticator"
	"github.com/shyndman/caddy-oidc/session"
	"github.com/tidwall/gjson"
)

func init() {
	caddy.RegisterModule(new(MatchUser))
	caddy.RegisterModule(new(MatchAnonymous))
	caddy.RegisterModule(new(MatchClaim))
	caddy.RegisterModule(new(MatchAuthMethod))
	caddy.RegisterModule(new(MatchRole))
}

// MatchWildcard matches a possible wildcard pattern against a value.
// Uses the same wildcard matching logic as caddyhttp.MatchHeader.
func MatchWildcard(pattern string, value string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*"):
		return strings.Contains(value, pattern[1:len(pattern)-1])
	case strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(value, pattern[1:])
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	default:
		return pattern == value
	}
}

var (
	_ caddy.Module                      = (*MatchUser)(nil)
	_ caddyfile.Unmarshaler             = (*MatchUser)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchUser)(nil)
)

// MatchUser matches the request against a list of wildcard-matched usernames present
// within the session stored in the incoming context.
// If the session is anonymous, no usernames are considered and the match always fails.
type MatchUser struct {
	Usernames []string `json:"usernames,omitempty"`
}

func (*MatchUser) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.user",
		New: func() caddy.Module { return new(MatchUser) },
	}
}

func (m *MatchUser) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var username string
		if !d.Args(&username) {
			return d.ArgErr()
		}

		m.Usernames = append(m.Usernames, username)
	}

	return nil
}

func (m *MatchUser) MatchWithError(r *http.Request) (bool, error) {
	s, ok := r.Context().Value(SessionCtxKey).(*session.Session)
	if !ok {
		// No session stored in request context
		return false, nil
	}

	// No users can match anonymous sessions
	if s.Anonymous {
		return false, nil
	}

	if len(m.Usernames) == 0 {
		return true, nil
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer) //nolint:forcetypeassert

	for _, allowedVal := range m.Usernames {
		if MatchWildcard(repl.ReplaceAll(allowedVal, ""), s.UID) {
			return true, nil
		}
	}

	return false, nil
}

func (m *MatchUser) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)

	return ok
}

var (
	_ caddy.Module                      = (*MatchAnonymous)(nil)
	_ caddyfile.Unmarshaler             = (*MatchAnonymous)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchAnonymous)(nil)
)

// MatchAnonymous matches requests that are anonymous or do not have a valid session in the request context.
type MatchAnonymous struct{}

func (*MatchAnonymous) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.anonymous",
		New: func() caddy.Module { return new(MatchAnonymous) },
	}
}

func (*MatchAnonymous) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}

		if d.NextBlock(0) {
			return d.Err("unexpected block")
		}
	}

	return nil
}

func (*MatchAnonymous) MatchWithError(r *http.Request) (bool, error) {
	s, ok := r.Context().Value(SessionCtxKey).(*session.Session)
	if !ok || s.Anonymous {
		return true, nil
	}

	return false, nil
}

func (m *MatchAnonymous) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)

	return ok
}

var (
	_ caddy.Module                      = (*MatchClaim)(nil)
	_ caddyfile.Unmarshaler             = (*MatchClaim)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchClaim)(nil)
)

// A ClaimMatch represents a claim name and a list of (optional) allowed values for that claim.
type ClaimMatch struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// MatchWithRepl matches the session claims against the claim match.
// Claims must be a valid gjson result containing a JSON object.
// If there are no values to match, MatchWithRepl returns true as long as the claim exists.
// Otherwise, at least one value must match.
// Both names and values of the ClaimMatch are pre-processed using the replacer.
func (cm *ClaimMatch) MatchWithRepl(repl *caddy.Replacer, claims *gjson.Result) bool {
	sessionClaimValue := claims.Get(repl.ReplaceAll(cm.Name, ""))
	if !sessionClaimValue.Exists() {
		return false
	}

	// No values to match, check only for existence
	if len(cm.Values) == 0 {
		return true
	}

	for _, claimValue := range cm.Values {
		matchClaimValue := repl.ReplaceAll(claimValue, "")

		switch {
		case sessionClaimValue.Type == gjson.String:
			if MatchWildcard(matchClaimValue, sessionClaimValue.String()) {
				return true
			}
		case sessionClaimValue.IsArray():
			for _, claimValueMatchElem := range sessionClaimValue.Array() {
				if claimValueMatchElem.Type != gjson.String {
					continue
				}

				if MatchWildcard(matchClaimValue, claimValueMatchElem.String()) {
					return true
				}
			}
		default:
			// Unsupported claim value type
			return false
		}
	}

	return false
}

// MatchClaim matches claims in a request session.
// The claim value in the session must be a string or an array of strings.
// If the claim value is an array, the match succeeds if any of the values match.
type MatchClaim []ClaimMatch

func (*MatchClaim) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.claim",
		New: func() caddy.Module { return new(MatchClaim) },
	}
}

func (m *MatchClaim) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}

		var claim = ClaimMatch{
			Name:   d.Val(),
			Values: d.RemainingArgs(),
		}

		*m = append(*m, claim)
	}

	return nil
}

func (m *MatchClaim) MatchWithError(r *http.Request) (bool, error) {
	s, ok := r.Context().Value(SessionCtxKey).(*session.Session)
	if !ok {
		// No session stored in request context
		return false, nil
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer) //nolint:forcetypeassert

	claims := gjson.ParseBytes(s.Claims)
	if !claims.IsObject() {
		return false, errors.New("invalid JSON object in session claims")
	}

	for _, cm := range *m {
		if !cm.MatchWithRepl(repl, &claims) {
			return false, nil
		}
	}

	return true, nil
}

func (m *MatchClaim) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)

	return ok
}

var (
	_ caddy.Module                      = (*MatchAuthMethod)(nil)
	_ caddyfile.Unmarshaler             = (*MatchAuthMethod)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchAuthMethod)(nil)
)

// MatchAuthMethod matches the authentication method used for the incoming request.
type MatchAuthMethod struct {
	Match []authenticator.AuthMethod `json:"match,omitempty"`
}

func (*MatchAuthMethod) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.auth_method",
		New: func() caddy.Module { return new(MatchAuthMethod) },
	}
}

func (m *MatchAuthMethod) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var methodVal string
		if !d.Args(&methodVal) {
			return d.ArgErr()
		}

		method, err := authenticator.ParseAuthMethod(methodVal)
		if err != nil {
			return err
		}

		m.Match = append(m.Match, method)

		if d.NextBlock(0) {
			return d.Err("unexpected block")
		}
	}

	return nil
}

func (m *MatchAuthMethod) MatchWithError(r *http.Request) (bool, error) {
	authMethod, ok := r.Context().Value(AuthMethodCtxKey).(authenticator.AuthMethod)
	if !ok {
		// If the auth method isn't set in the request context, default to none
		authMethod = authenticator.AuthMethodNone
	}

	return slices.Contains(m.Match, authMethod), nil
}

var (
	_ caddy.Module                      = (*MatchRole)(nil)
	_ caddy.Provisioner                 = (*MatchRole)(nil)
	_ caddyfile.Unmarshaler             = (*MatchRole)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchRole)(nil)
)

// MatchRole matches a session against the roles stored in the authorization
// directory. A session matches when the email claim of the session maps to a
// user that holds at least one of the configured roles.
// An anonymous session has no email claim, so it never matches.
type MatchRole struct {
	Roles []string `json:"roles,omitempty"`

	// app is the oidc app that holds the authorization directory. It is set
	// during Provision and read at request time. The directory is initialized
	// once, normally by Start, but the first request can force it and waits
	// for the completed load.
	app *App
}

func (*MatchRole) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.role",
		New: func() caddy.Module { return new(MatchRole) },
	}
}

func (m *MatchRole) Provision(ctx caddy.Context) error {
	val, err := ctx.AppIfConfigured(moduleID)
	if err != nil {
		return err
	}

	m.app = val.(*App) //nolint:forcetypeassert

	return nil
}

func (m *MatchRole) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var role string
		if !d.Args(&role) {
			return d.ArgErr()
		}

		m.Roles = append(m.Roles, role)
	}

	return nil
}

func (m *MatchRole) MatchWithError(r *http.Request) (bool, error) {
	s, ok := r.Context().Value(SessionCtxKey).(*session.Session)
	if !ok || s.Anonymous {
		return false, nil
	}

	if len(m.Roles) == 0 {
		return false, nil
	}

	if m.app == nil {
		return false, errors.New("role matcher requires a configured postgres directory")
	}

	rt, err := m.app.runtime()
	if err != nil {
		return false, err
	}

	if rt.directory == nil {
		return false, errors.New("role matcher requires a configured postgres directory")
	}

	email := gjson.GetBytes(s.Claims, "email")
	if !email.Exists() || email.Type != gjson.String {
		return false, nil
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer) //nolint:forcetypeassert

	for _, role := range m.Roles {
		if rt.directory.HasRole(email.String(), repl.ReplaceAll(role, "")) {
			return true, nil
		}
	}

	return false, nil
}

func (m *MatchRole) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)

	return ok
}

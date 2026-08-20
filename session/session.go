// Package session contains types and functions for working with authentication sessions.
package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tidwall/gjson"
)

// Anonymous returns a session to use when a request is unauthenticated.
func Anonymous() *Session {
	return &Session{
		Anonymous: true,
		Claims:    json.RawMessage(`{}`),
	}
}

// MissingRequiredClaimError is returned when a required claim is not provided.
type MissingRequiredClaimError struct {
	Claim string
}

func (e MissingRequiredClaimError) Error() string {
	return fmt.Sprintf("request authentication is missing the required claim '%s'", e.Claim)
}

// Session represents an authentication session.
// A session can be one that is authenticated (anonymous) or authenticated with a user identity.
// A session may optionally expire.
type Session struct {
	Anonymous bool            `json:"-"`
	UID       string          `json:"u"`
	ExpiresAt int64           `json:"e,omitempty"`
	Claims    json.RawMessage `json:"c,omitempty"`
}

// NewFromIDToken creates a session from a verified ID token.
//
// The uidClaim must identify a string claim in the token.
func NewFromIDToken(uidClaim string, idToken *oidc.IDToken) (*Session, error) {
	// Extract the original claims from the token.
	var rawClaims *json.RawMessage

	err := idToken.Claims(&rawClaims)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusUnauthorized, err)
	}

	uid := gjson.GetBytes(*rawClaims, uidClaim)
	if !uid.Exists() || uid.Type != gjson.String {
		return nil, caddyhttp.Error(http.StatusUnauthorized, MissingRequiredClaimError{Claim: uidClaim})
	}

	return &Session{
		UID:       uid.String(),
		ExpiresAt: idToken.Expiry.Unix(),
		Claims:    *rawClaims,
	}, nil
}

// Expires returns the expiration time of the session.
// Returns a zero time if the session has no expiration time.
func (s *Session) Expires() time.Time {
	if s.ExpiresAt == 0 {
		return time.Time{}
	}

	return time.Unix(s.ExpiresAt, 0)
}

// Leeway is the amount of leeway permitted in a session's expiration time
// allowing for clock skew between the authenticator and the client.
const Leeway = time.Second * 5

// ValidateClock checks if the session is still valid.
// If the session has expired, then it returns an oidc.TokenExpiredError.
func (s *Session) ValidateClock(now time.Time) error {
	if expires := s.Expires(); !expires.IsZero() && expires.Before(now.Add(-Leeway)) {
		return &oidc.TokenExpiredError{Expiry: expires}
	}

	return nil
}

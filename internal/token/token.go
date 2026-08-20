// Package token signs short-lived user tokens (JWTs) for downstream services
// and produces the JWKS document that exposes the verification keys.
package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Claims is the payload of a user token.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Name      string   `json:"name,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// Minter signs user tokens with an ES256 private key.
type Minter struct {
	signer jose.Signer
	public jose.JSONWebKey
}

// NewFromPEM creates a Minter from a PEM-encoded ES256 (P-256) private key.
// The key may be in PKCS#8 or SEC1 form.
func NewFromPEM(keyPEM []byte) (*Minter, error) {
	key, err := parseECPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}

	public := jose.JSONWebKey{
		Key:       &key.PublicKey,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("compute JWK thumbprint: %w", err)
	}
	public.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), public.KeyID),
	)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	return &Minter{signer: signer, public: public}, nil
}

func parseECPrivateKeyPEM(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}

	var (
		key *ecdsa.PrivateKey
		err error
	)

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var anyKey any

		anyKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool

			key, ok = anyKey.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("private key is not an ECDSA key")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}

	if key.Curve.Params().Name != elliptic.P256().Params().Name {
		return nil, errors.New("private key must use the P-256 curve")
	}

	return key, nil
}

// Sign mints a signed user token.
func (m *Minter) Sign(issuer, sub, name string, roles []string, issuedAt, expiresAt time.Time) (string, error) {
	if expiresAt.IsZero() {
		return "", errors.New("user token expiry is required")
	}

	claims := Claims{
		Issuer:    issuer,
		Subject:   sub,
		Name:      name,
		Roles:     roles,
		IssuedAt:  issuedAt.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	sig, err := m.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign user token: %w", err)
	}

	return sig.CompactSerialize()
}

// JWKS returns the JSON Web Key Set that exposes the public verification key.
func (m *Minter) JWKS() ([]byte, error) {
	return json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{m.public}})
}

package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestPEM(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), key
}

func TestNewFromPEM(t *testing.T) {
	t.Parallel()

	pemBytes, _ := generateTestPEM(t)

	m, err := NewFromPEM(pemBytes)
	require.NoError(t, err)
	assert.NotNil(t, m)
}

func TestNewFromPEM_SEC1(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	_, err = NewFromPEM(pemBytes)
	require.NoError(t, err)
}

func TestNewFromPEM_Invalid(t *testing.T) {
	t.Parallel()

	_, err := NewFromPEM([]byte("not a key"))
	require.Error(t, err)
}

func TestNewFromPEM_WrongCurve(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = NewFromPEM(pemBytes)
	require.Error(t, err)
}

func TestSign_Verify(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	m, err := NewFromPEM(pemBytes)
	require.NoError(t, err)

	iat := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exp := iat.Add(time.Hour)

	sig, err := m.Sign("https://idp.example", "a@example.com", "Alice", []string{"admin", "reader"}, iat, exp)
	require.NoError(t, err)

	jws, err := jose.ParseSignedCompact(sig, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	payload, err := jws.Verify(&key.PublicKey)
	require.NoError(t, err)

	var claims Claims
	require.NoError(t, json.Unmarshal(payload, &claims))

	assert.Equal(t, "https://idp.example", claims.Issuer)
	assert.Equal(t, "a@example.com", claims.Subject)
	assert.Equal(t, "Alice", claims.Name)
	assert.Equal(t, []string{"admin", "reader"}, claims.Roles)
	assert.Equal(t, iat.Unix(), claims.IssuedAt)
	assert.Equal(t, exp.Unix(), claims.ExpiresAt)
}

func TestSign_NoExpiry(t *testing.T) {
	t.Parallel()

	pemBytes, key := generateTestPEM(t)

	m, err := NewFromPEM(pemBytes)
	require.NoError(t, err)

	sig, err := m.Sign("iss", "a@example.com", "", nil, time.Now(), time.Time{})
	require.NoError(t, err)

	jws, err := jose.ParseSignedCompact(sig, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	payload, err := jws.Verify(&key.PublicKey)
	require.NoError(t, err)

	var claims Claims
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, int64(0), claims.ExpiresAt)
}

func TestJWKS(t *testing.T) {
	t.Parallel()

	pemBytes, _ := generateTestPEM(t)

	m, err := NewFromPEM(pemBytes)
	require.NoError(t, err)

	raw, err := m.JWKS()
	require.NoError(t, err)

	var set jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(raw, &set))
	require.Len(t, set.Keys, 1)

	k := set.Keys[0]
	require.Equal(t, "ES256", k.Algorithm)
	require.Equal(t, "sig", k.Use)
	require.NotEmpty(t, k.KeyID)
	require.IsType(t, &ecdsa.PublicKey{}, k.Key)
	require.True(t, k.IsPublic())
	assert.NotContains(t, string(raw), `"d"`)

	sig, err := m.Sign("iss", "sub", "", nil, time.Now(), time.Time{})
	require.NoError(t, err)

	jws, err := jose.ParseSignedCompact(sig, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	require.Len(t, jws.Signatures, 1)

	keys := set.Key(jws.Signatures[0].Header.KeyID)
	require.Len(t, keys, 1)

	_, err = jws.Verify(keys[0].Key)
	require.NoError(t, err)
}

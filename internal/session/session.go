// Package session implements stateless, HMAC-signed cookie values.
//
// A value is "<base64url(json payload)>.<base64url(hmac-sha256)>". The payload
// carries its own expiry, so no server-side store is needed.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrInvalid = errors.New("invalid or expired cookie")

type Signer struct {
	key []byte
	now func() time.Time
}

func NewSigner(secret []byte, purpose string) *Signer {
	// Derive a per-purpose key so a cookie for one purpose can never be
	// replayed as another.
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("nexus-gh-auth/" + purpose))
	return &Signer{key: m.Sum(nil), now: time.Now}
}

type envelope struct {
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"d"`
}

// Seal signs v with the given lifetime.
func (s *Signer) Seal(v any, ttl time.Duration) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(envelope{Exp: s.now().Add(ttl).Unix(), Data: data})
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	return p + "." + base64.RawURLEncoding.EncodeToString(s.mac(p)), nil
}

// Open verifies the signature and expiry and decodes into v.
func (s *Signer) Open(value string, v any) error {
	p, sig, ok := strings.Cut(value, ".")
	if !ok {
		return ErrInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(p)) {
		return ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return ErrInvalid
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return ErrInvalid
	}
	if s.now().Unix() >= env.Exp {
		return ErrInvalid
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		return ErrInvalid
	}
	return nil
}

func (s *Signer) mac(p string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(p))
	return m.Sum(nil)
}

// RandomString returns n random bytes, base64url-encoded.
func RandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Package provider defines the seam between the bridge and an identity
// provider. GitHub is the only implementation in v1.
package provider

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// Identity is what the bridge learns about a user at login.
type Identity struct {
	Subject     string // provider-namespaced, stable, e.g. "github:42"
	ID          int64
	Login       string
	DisplayName string
	Email       string   // may be empty
	Groups      []string // lower-cased, already filtered to allowed orgs
}

type Provider interface {
	Name() string
	OAuth2Config(redirectURL string) *oauth2.Config
	// Identify fetches the identity using an HTTP client that carries the
	// user's access token. The token must not be retained.
	Identify(ctx context.Context, client *http.Client) (Identity, error)
	// FallbackEmail returns a syntactically valid placeholder address for
	// users without a usable email.
	FallbackEmail(id Identity) string
}

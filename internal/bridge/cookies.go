package bridge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
)

const (
	cookieSession = "_bridge_session"
	cookieLocal   = "_bridge_local"
	cookieOAuth   = "_bridge_oauth"
	cookiePrefix  = "_bridge_"

	// nexusSessionCookie is Nexus' own UI session cookie. It is cleared when
	// the signed-in identity changes so Nexus never keeps a session for the
	// previous user.
	nexusSessionCookie = "NXSESSIONID"

	localTTL = time.Hour
	oauthTTL = 10 * time.Minute
)

type sessionData struct {
	UserID string `json:"u"`
	Nonce  string `json:"n"`
}

type localData struct {
	Nonce    string `json:"n"`
	IssuedAt int64  `json:"t"`
}

type oauthData struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
}

func (b *Bridge) setCookie(w http.ResponseWriter, name, value, path string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: path, MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: b.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode,
	})
}

func (b *Bridge) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: b.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode,
	})
}

// session returns the valid session carried by r, if any.
func (b *Bridge) session(r *http.Request) (sessionData, bool) {
	var s sessionData
	c, err := r.Cookie(cookieSession)
	if err != nil || b.sessions.Open(c.Value, &s) != nil || s.UserID == "" {
		return sessionData{}, false
	}
	return s, true
}

// local returns the valid local-mode marker carried by r, if any.
func (b *Bridge) local(r *http.Request) (localData, bool) {
	var l localData
	c, err := r.Cookie(cookieLocal)
	if err != nil || b.locals.Open(c.Value, &l) != nil || l.Nonce == "" {
		return localData{}, false
	}
	return l, true
}

// csrfToken binds a logout form to the nonce of the caller's cookie, so a
// third-party page cannot produce a valid token.
func (b *Bridge) csrfToken(nonce string) string {
	m := hmac.New(sha256.New, b.csrfKey)
	m.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// stripBridgeCookies removes the bridge's own cookies from a request that is
// forwarded to Nexus.
func stripBridgeCookies(h http.Header) {
	filterCookies(h, func(name string) bool { return strings.HasPrefix(name, cookiePrefix) })
}

// filterCookies removes the cookies whose name matches drop from h.
func filterCookies(h http.Header, drop func(name string) bool) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			if part != "" && !drop(strings.TrimSpace(name)) {
				kept = append(kept, part)
			}
		}
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

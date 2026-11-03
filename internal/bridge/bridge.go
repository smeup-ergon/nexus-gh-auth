// Package bridge implements the GitHub login proxy in front of Nexus.
package bridge

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/smeup-ergon/nexus-gh-auth/internal/config"
	"github.com/smeup-ergon/nexus-gh-auth/internal/nexus"
	"github.com/smeup-ergon/nexus-gh-auth/internal/provider"
	"github.com/smeup-ergon/nexus-gh-auth/internal/session"
	"golang.org/x/oauth2"
)

const lastNameMarker = "(GitHub)"

type Bridge struct {
	cfg        *config.Config
	provider   provider.Provider
	oauth      *oauth2.Config
	nexus      *nexus.Client
	log        *slog.Logger
	audit      *slog.Logger
	userHeader string
	transport  http.RoundTripper
	httpClient *http.Client // used for GitHub calls

	sessions *session.Signer
	locals   *session.Signer
	oauthSt  *session.Signer
	csrfKey  []byte
	status   *statusCache

	ready atomic.Bool
}

func New(cfg *config.Config, p provider.Provider, nx *nexus.Client, log *slog.Logger) *Bridge {
	csrf := hmac.New(sha256.New, cfg.SessionSecret)
	csrf.Write([]byte("nexus-gh-auth/csrf"))
	return &Bridge{
		cfg:        cfg,
		provider:   p,
		oauth:      p.OAuth2Config(cfg.CallbackURL()),
		nexus:      nx,
		log:        log,
		audit:      log.With("type", "audit"),
		userHeader: http.CanonicalHeaderKey(cfg.NexusUserHeader),
		transport:  newTransport(),
		httpClient: &http.Client{Timeout: 30 * time.Second},
		sessions:   session.NewSigner(cfg.SessionSecret, "session"),
		locals:     session.NewSigner(cfg.SessionSecret, "local"),
		oauthSt:    session.NewSigner(cfg.SessionSecret, "oauth"),
		csrfKey:    csrf.Sum(nil),
		status:     newStatusCache(),
	}
}

// Startup waits for Nexus and checks that every role in ROLE_MAP exists. A
// missing role is fatal; an unreachable Nexus is retried until the timeout.
func (b *Bridge) Startup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, b.cfg.NexusStartupTimeout)
	defer cancel()
	delay := time.Second
	for {
		missing, err := b.nexus.MissingRoles(ctx, b.cfg.MappedRoles())
		if err == nil {
			if len(missing) > 0 {
				return errors.New("ROLE_MAP refers to Nexus roles that do not exist: " + strings.Join(missing, ", "))
			}
			b.ready.Store(true)
			b.log.Info("nexus reachable, role mapping verified", "roles", b.cfg.MappedRoles())
			return nil
		}
		// Credentials errors are retried too: on a first deployment the
		// service account may be created only after the bridge starts.
		hint := "nexus did not become reachable within NEXUS_STARTUP_TIMEOUT"
		var he *nexus.HTTPError
		if errors.As(err, &he) && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden) {
			hint = "NEXUS_ADMIN_USER cannot read roles (check credentials and the nx-roles-read privilege)"
		}
		b.log.Warn("waiting for nexus", "err", err.Error(), "retry_in", delay.String())
		select {
		case <-ctx.Done():
			return errors.New(hint + ": " + err.Error())
		case <-time.After(delay):
		}
		delay = min(delay*2, 15*time.Second)
	}
}

// WebHandler serves the bridge pages and proxies everything else to Nexus.
func (b *Bridge) WebHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_bridge/login", b.handleLogin)
	mux.HandleFunc("GET /_bridge/auth", b.handleAuth)
	mux.HandleFunc("GET /_bridge/callback", b.handleCallback)
	mux.HandleFunc("GET /_bridge/local", b.handleLocal)
	mux.HandleFunc("POST /_bridge/logout", b.handleLogout)
	mux.HandleFunc("GET /_bridge/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /_bridge/readyz", b.handleReady)
	mux.HandleFunc("/_bridge/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })

	proxy := b.newProxy(b.cfg.NexusURL, nil)
	proxyAs := func(user string) http.Handler {
		return b.newProxy(b.cfg.NexusURL, func(in, out *http.Request) { out.Header.Set(b.userHeader, user) })
	}
	proxyNoNexusSession := b.newProxy(b.cfg.NexusURL, func(in, out *http.Request) { stripCookie(out.Header, nexusSessionCookie) })

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 1. Local-account mode: Nexus handles authentication itself.
		if l, ok := b.local(r); ok {
			if isNexusSignOut(r) {
				b.endLocal(w)
			} else if time.Since(time.Unix(l.IssuedAt, 0)) > localTTL/2 {
				// Idle expiry: refresh once half the lifetime has passed.
				b.startLocal(w, l.Nonce)
			}
			proxy.ServeHTTP(w, r)
			return
		}
		// 2. GitHub session: assert the user to Nexus, unless the user has
		// been disabled in Nexus since signing in.
		if s, ok := b.session(r); ok && b.stillActive(w, r, s) {
			if isNexusSignOut(r) {
				b.clearCookie(w, cookieSession, "/")
				b.audit.Info("logout", "user", s.UserID, "via", "nexus")
			}
			proxyAs(s.UserID).ServeHTTP(w, r)
			return
		}
		// 3. Build tools and API clients authenticate against Nexus directly.
		if r.Header.Get("Authorization") != "" {
			proxyNoNexusSession.ServeHTTP(w, r)
			return
		}
		// 4. Browsers are sent to GitHub.
		if isBrowserNavigation(r) {
			http.Redirect(w, r, "/_bridge/login?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		// 5. Anything else is anonymous as far as Nexus is concerned. A
		// leftover Nexus UI session must not outlive the bridge session.
		proxyNoNexusSession.ServeHTTP(w, r)
	})
	return securityHeaders(mux)
}

// DockerHandler is a pure pass-through for the Docker registry connector.
func (b *Bridge) DockerHandler() http.Handler {
	return b.newProxy(b.cfg.NexusDockerURL, nil)
}

// stillActive checks the session's Nexus user. A disabled, locked or deleted
// user loses the session; a lookup error fails closed for this request only.
func (b *Bridge) stillActive(w http.ResponseWriter, r *http.Request, s sessionData) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	active, err := b.status.active(ctx, b.nexus, s.UserID)
	if err != nil {
		b.log.Warn("checking nexus user status", "user", s.UserID, "err", err.Error())
		return false
	}
	if !active {
		b.clearCookie(w, cookieSession, "/")
		b.clearCookie(w, nexusSessionCookie, "/")
		b.audit.Warn("session_revoked", "user", s.UserID, "reason", "nexus_user_inactive")
	}
	return active
}

func (b *Bridge) handleReady(w http.ResponseWriter, r *http.Request) {
	if !b.ready.Load() {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := b.nexus.Ping(ctx); err != nil {
		http.Error(w, "nexus unreachable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok\n"))
}

func (b *Bridge) handleLogin(w http.ResponseWriter, r *http.Request) {
	v := loginView{Return: safeReturn(r.URL.Query().Get("rd"))}
	if s, ok := b.session(r); ok {
		v.User, v.CSRF = s.UserID, b.csrfToken(s.Nonce)
	} else if l, ok := b.local(r); ok {
		v.Local, v.CSRF = true, b.csrfToken(l.Nonce)
	}
	b.render(w, http.StatusOK, loginPage, v)
}

func (b *Bridge) handleAuth(w http.ResponseWriter, r *http.Request) {
	st := oauthData{
		State:    session.RandomString(24),
		Verifier: oauth2.GenerateVerifier(),
		Return:   safeReturn(r.URL.Query().Get("rd")),
	}
	b.setCookie(w, cookieOAuth, b.mustSeal(b.oauthSt, st, oauthTTL), "/_bridge/callback", oauthTTL)
	http.Redirect(w, r, b.oauth.AuthCodeURL(st.State, oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

func (b *Bridge) handleCallback(w http.ResponseWriter, r *http.Request) {
	b.clearCookie(w, cookieOAuth, "/_bridge/callback")
	if !b.ready.Load() {
		b.refuse(w, refuseNexus, "", errors.New("startup role check not completed"))
		return
	}
	var st oauthData
	c, err := r.Cookie(cookieOAuth)
	q := r.URL.Query()
	if err != nil || b.oauthSt.Open(c.Value, &st) != nil || q.Get("state") == "" ||
		!hmac.Equal([]byte(q.Get("state")), []byte(st.State)) {
		b.refuse(w, refuseState, "", nil)
		return
	}
	if e := q.Get("error"); e != "" {
		b.refuse(w, refuseDenied, "", errors.New(e))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, b.httpClient)
	tok, err := b.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		b.refuse(w, refuseGitHub, "", err)
		return
	}
	// The token lives only for the duration of this request.
	id, err := b.provider.Identify(ctx, b.oauth.Client(ctx, tok))
	if err != nil {
		b.refuse(w, refuseGitHub, "", err)
		return
	}

	userID := b.cfg.NexusUserPrefix + strings.ToLower(id.Login)
	if len(id.Groups) == 0 {
		b.refuse(w, refuseOrg, userID, nil)
		return
	}
	roles := b.cfg.RolesFor(id.Groups)
	if len(roles) == 0 {
		b.refuse(w, refuseNoRole, userID, nil, "groups", id.Groups)
		return
	}
	email := id.Email
	if email == "" {
		email = b.provider.FallbackEmail(id)
	}
	res, err := b.nexus.Upsert(ctx, nexus.Desired{
		UserID: userID, FirstName: id.DisplayName, LastName: lastNameMarker, EmailAddress: email, Roles: roles,
	}, func() string { return session.RandomString(32) })
	switch {
	case errors.Is(err, nexus.ErrUserNotActive):
		b.refuse(w, refuseDisabled, userID, err)
		return
	case err != nil:
		b.refuse(w, refuseNexus, userID, err)
		return
	}
	if res.Created {
		b.audit.Info("nexus_user_created", "user", userID, "subject", id.Subject, "roles", roles)
	} else if len(res.RolesAdded)+len(res.RolesRemoved) > 0 {
		b.audit.Info("nexus_user_roles_changed", "user", userID, "added", res.RolesAdded, "removed", res.RolesRemoved)
	}

	b.status.set(userID, true)
	sess := sessionData{UserID: userID, Nonce: session.RandomString(16)}
	b.setCookie(w, cookieSession, b.mustSeal(b.sessions, sess, b.cfg.SessionTTL), "/", b.cfg.SessionTTL)
	b.clearCookie(w, cookieLocal, "/")
	b.clearCookie(w, nexusSessionCookie, "/") // never inherit another identity's Nexus UI session
	b.audit.Info("login", "user", userID, "subject", id.Subject, "groups", id.Groups, "roles", roles)
	http.Redirect(w, r, st.Return, http.StatusFound)
}

func (b *Bridge) startLocal(w http.ResponseWriter, nonce string) {
	l := localData{Nonce: nonce, IssuedAt: time.Now().Unix()}
	b.setCookie(w, cookieLocal, b.mustSeal(b.locals, l, localTTL), "/", localTTL)
}

func (b *Bridge) handleLocal(w http.ResponseWriter, r *http.Request) {
	b.startLocal(w, session.RandomString(16))
	b.clearCookie(w, cookieSession, "/")
	b.clearCookie(w, nexusSessionCookie, "/")
	b.audit.Info("local_mode_enabled", "remote", clientAddr(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (b *Bridge) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("csrf")
	valid := false
	user := ""
	if s, ok := b.session(r); ok && hmac.Equal([]byte(token), []byte(b.csrfToken(s.Nonce))) {
		valid, user = true, s.UserID
	}
	if l, ok := b.local(r); ok && hmac.Equal([]byte(token), []byte(b.csrfToken(l.Nonce))) {
		valid = true
	}
	if !valid {
		http.Redirect(w, r, "/_bridge/login", http.StatusSeeOther)
		return
	}
	b.clearCookie(w, cookieSession, "/")
	b.endLocal(w)
	b.audit.Info("logout", "user", user, "via", "bridge")
	http.Redirect(w, r, "/_bridge/login", http.StatusSeeOther)
}

func (b *Bridge) endLocal(w http.ResponseWriter) {
	b.clearCookie(w, cookieLocal, "/")
	b.clearCookie(w, nexusSessionCookie, "/")
}

func (b *Bridge) refuse(w http.ResponseWriter, why refusal, user string, cause error, attrs ...any) {
	args := append([]any{"reason", why.reason}, attrs...)
	if user != "" {
		args = append(args, "user", user)
	}
	if cause != nil {
		args = append(args, "err", cause.Error())
	}
	b.audit.Warn("login_refused", args...)
	b.render(w, why.status, errorPage, errorView{Title: why.title, Message: why.message})
}

func (b *Bridge) mustSeal(s *session.Signer, v any, ttl time.Duration) string {
	out, err := s.Seal(v, ttl)
	if err != nil {
		panic(err) // only fails for unmarshalable values, which would be a bug
	}
	return out
}

// safeReturn accepts only same-origin absolute paths outside /_bridge/.
func safeReturn(rd string) string {
	if rd == "" || !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.ContainsAny(rd, "\\\r\n\t") {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/_bridge/") {
		return "/"
	}
	return rd
}

func clientAddr(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return f
	}
	return r.RemoteAddr
}

func stripCookie(h http.Header, name string) {
	filterCookies(h, func(n string) bool { return n == name })
}

// securityHeaders adds headers to the bridge's own pages only; proxied
// Nexus responses are left untouched.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_bridge/") {
			h := w.Header()
			h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
		}
		next.ServeHTTP(w, r)
	})
}

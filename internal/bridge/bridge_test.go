package bridge_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/smeup-ergon/nexus-gh-auth/internal/bridge"
	"github.com/smeup-ergon/nexus-gh-auth/internal/config"
	"github.com/smeup-ergon/nexus-gh-auth/internal/github"
	"github.com/smeup-ergon/nexus-gh-auth/internal/nexus"
	"github.com/smeup-ergon/nexus-gh-auth/internal/testing/fakegithub"
	"github.com/smeup-ergon/nexus-gh-auth/internal/testing/fakenexus"
)

const header = "X-Forwarded-User"

type env struct {
	t      *testing.T
	gh     *fakegithub.Server
	nx     *fakenexus.Server
	docker *fakenexus.Server
	web    *httptest.Server
	reg    *httptest.Server
	logs   *syncBuffer
	bridge *bridge.Bridge
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newEnv(t *testing.T, extra map[string]string) *env {
	t.Helper()
	e := &env{t: t, gh: fakegithub.New(t), nx: fakenexus.New(t, "nx-admin", "nx-dev"), docker: fakenexus.New(t), logs: &syncBuffer{}}
	// The web server URL must be known before the config is built, so start
	// an unstarted server and plug the handler in afterwards.
	var handler http.Handler
	e.web = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	e.web.Start()
	t.Cleanup(e.web.Close)

	vars := map[string]string{
		"BASE_URL":             e.web.URL,
		"NEXUS_URL":            e.nx.URL,
		"NEXUS_DOCKER_URL":     e.docker.URL,
		"NEXUS_ADMIN_USER":     e.nx.AdminUser,
		"NEXUS_ADMIN_PASSWORD": e.nx.AdminPassword,
		"GITHUB_CLIENT_ID":     e.gh.ClientID,
		"GITHUB_CLIENT_SECRET": e.gh.ClientSecret,
		"GITHUB_URL":           e.gh.URL,
		"GITHUB_API_URL":       e.gh.APIURL(),
		"GITHUB_ORGS":          "myorg",
		"ROLE_MAP":             "myorg~platform=nx-admin,myorg~dev=nx-dev",
		"SESSION_SECRET":       strings.Repeat("x", 32),
	}
	for k, v := range extra {
		vars[k] = v
	}
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := vars[k]; return v, ok }, nil)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(e.logs, nil))
	gh := github.New(cfg.GitHubURL, cfg.GitHubAPIURL, cfg.GitHubClientID, cfg.GitHubClientSecret, cfg.GitHubOrgs)
	e.bridge = bridge.New(cfg, gh, nexus.New(cfg.NexusURL, cfg.NexusAdminUser, cfg.NexusAdminPassword), log)
	if err := e.bridge.Startup(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler = e.bridge.WebHandler()
	e.reg = httptest.NewServer(e.bridge.DockerHandler())
	t.Cleanup(e.reg.Close)

	e.gh.AddUser(fakegithub.User{ID: 1, Login: "Alice", Name: "Alice L", Email: "alice@example.com",
		Orgs: []string{"myorg"}, Teams: []fakegithub.Team{{Org: "myorg", Slug: "platform"}}})
	e.gh.AddUser(fakegithub.User{ID: 2, Login: "bob", Orgs: []string{"myorg"}, Teams: []fakegithub.Team{{Org: "myorg", Slug: "dev"}},
		Emails: []fakegithub.Email{{Email: "bob@example.com", Primary: true, Verified: true}}})
	e.gh.AddUser(fakegithub.User{ID: 3, Login: "eve", Orgs: []string{"elsewhere"}})
	e.gh.AddUser(fakegithub.User{ID: 4, Login: "carol", Orgs: []string{"myorg"}, Teams: []fakegithub.Team{{Org: "myorg", Slug: "unmapped"}}})
	e.gh.AddUser(fakegithub.User{ID: 5, Login: "dave", Orgs: []string{"myorg"}, Teams: []fakegithub.Team{{Org: "myorg", Slug: "dev"}}})
	return e
}

// browser is a cookie-keeping client that does not follow redirects, so each
// hop can be asserted.
type browser struct {
	t   *testing.T
	e   *env
	jar *cookiejar.Jar
	c   *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: e.t, e: e, jar: jar, c: &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) do(method, rawURL string, hdr http.Header, body io.Reader) *http.Response {
	b.t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		b.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	b.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (b *browser) page(path string) *http.Response {
	return b.do("GET", b.e.web.URL+path, http.Header{"Accept": {"text/html,application/xhtml+xml"}}, nil)
}

func location(t *testing.T, r *http.Response) string {
	t.Helper()
	if r.StatusCode != http.StatusFound && r.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(r.Body)
		t.Fatalf("want redirect, got %d: %s", r.StatusCode, body)
	}
	return r.Header.Get("Location")
}

// login runs the full GitHub flow for login and returns the final redirect
// response from the callback.
func (b *browser) login(login, start string) *http.Response {
	b.t.Helper()
	r := b.page(start)
	loginURL := location(b.t, r)
	if !strings.HasPrefix(loginURL, "/_bridge/login?rd=") {
		b.t.Fatalf("want login redirect, got %s", loginURL)
	}
	rd, _ := url.Parse(loginURL)
	r = b.do("GET", b.e.web.URL+"/_bridge/auth?rd="+url.QueryEscape(rd.Query().Get("rd")), nil, nil)
	authURL := location(b.t, r)
	// Tell the fake GitHub which user is signing in.
	r = b.do("GET", authURL+"&login="+login, nil, nil)
	cb := location(b.t, r)
	if !strings.HasPrefix(cb, b.e.web.URL+"/_bridge/callback?") {
		b.t.Fatalf("unexpected callback %s", cb)
	}
	return b.do("GET", cb, nil, nil)
}

func echo(t *testing.T, r *http.Response) fakenexus.Echo {
	t.Helper()
	if r.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(r.Body)
		t.Fatalf("want 200 from Nexus, got %d: %s", r.StatusCode, body)
	}
	var e fakenexus.Echo
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	return e
}

func body(t *testing.T, r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// AC1: a member of an allowed org with a mapped team lands in Nexus as
// gh-<login> with the mapped roles.
func TestLoginCreatesUserAndAssertsHeader(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	r := b.login("Alice", "/#browse/browse:maven-releases")
	if got := location(t, r); got != "/" {
		// Fragments never reach the server; the path is what is preserved.
		t.Errorf("return location = %q", got)
	}
	u, ok := e.nx.User("gh-alice")
	if !ok {
		t.Fatal("user not created")
	}
	if u.FirstName != "Alice L" || u.LastName != "(GitHub)" || u.EmailAddress != "alice@example.com" ||
		!reflect.DeepEqual(u.Roles, []string{"nx-admin"}) || u.Status != "active" || len(u.Password) < 40 {
		t.Errorf("created user = %+v", u)
	}

	got := echo(t, b.page("/service/rest/repository/browse/"))
	if got.Header.Get(header) != "gh-alice" {
		t.Errorf("header = %q", got.Header.Get(header))
	}
	for _, c := range strings.Split(got.Header.Get("Cookie"), ";") {
		if strings.HasPrefix(strings.TrimSpace(c), "_bridge_") {
			t.Errorf("bridge cookie forwarded to Nexus: %q", c)
		}
	}
	if !strings.Contains(e.logs.String(), `"msg":"login"`) || !strings.Contains(e.logs.String(), `"msg":"nexus_user_created"`) {
		t.Errorf("missing audit lines:\n%s", e.logs)
	}
}

func TestReturnPathPreserved(t *testing.T) {
	e := newEnv(t, nil)
	r := e.browser().login("bob", "/repository/maven-releases/?x=1")
	if got := location(t, r); got != "/repository/maven-releases/?x=1" {
		t.Errorf("return location = %q", got)
	}
	if u, _ := e.nx.User("gh-bob"); u.EmailAddress != "bob@example.com" || u.FirstName != "bob" {
		t.Errorf("user = %+v", u)
	}
}

func TestFallbackEmail(t *testing.T) {
	e := newEnv(t, nil)
	e.browser().login("dave", "/")
	u, _ := e.nx.User("gh-dave")
	host := strings.Split(strings.TrimPrefix(e.gh.URL, "http://"), ":")[0]
	if u.EmailAddress != "5+dave@users.noreply."+host {
		t.Errorf("email = %q", u.EmailAddress)
	}
}

// AC2: role changes on GitHub are applied at the next login.
func TestRolesUpdatedOnNextLogin(t *testing.T) {
	e := newEnv(t, nil)
	e.browser().login("bob", "/")
	e.gh.AddUser(fakegithub.User{ID: 2, Login: "bob", Orgs: []string{"myorg"},
		Teams: []fakegithub.Team{{Org: "myorg", Slug: "platform"}}})
	e.browser().login("bob", "/")
	u, _ := e.nx.User("gh-bob")
	if !reflect.DeepEqual(u.Roles, []string{"nx-admin"}) {
		t.Errorf("roles = %v", u.Roles)
	}
	if !strings.Contains(e.logs.String(), `"msg":"nexus_user_roles_changed"`) {
		t.Error("missing role-change audit line")
	}
}

// AC3: users outside the allowed orgs or without a mapped team are refused.
func TestRefusals(t *testing.T) {
	cases := map[string]struct {
		status int
		reason string
	}{
		"eve":   {http.StatusForbidden, "not_in_org"},
		"carol": {http.StatusForbidden, "no_mapped_role"},
	}
	for login, want := range cases {
		e := newEnv(t, nil)
		b := e.browser()
		r := b.login(login, "/")
		if r.StatusCode != want.status {
			t.Errorf("%s: status %d", login, r.StatusCode)
		}
		if _, ok := e.nx.User("gh-" + login); ok {
			t.Errorf("%s: Nexus user was created", login)
		}
		if !strings.Contains(e.logs.String(), `"reason":"`+want.reason+`"`) {
			t.Errorf("%s: audit missing reason %s:\n%s", login, want.reason, e.logs)
		}
		// Still not signed in.
		if loc := location(t, b.page("/")); !strings.HasPrefix(loc, "/_bridge/login") {
			t.Errorf("%s: signed in after refusal", login)
		}
	}
}

// AC9: a user disabled in Nexus stays blocked after a fresh GitHub login.
func TestDisabledUserRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.browser().login("bob", "/")
	u, _ := e.nx.User("gh-bob")
	u.Status = "disabled"
	e.nx.PutUser(u)

	b := e.browser()
	r := b.login("bob", "/")
	if r.StatusCode != http.StatusForbidden || !strings.Contains(body(t, r), "disabled") {
		t.Fatalf("status = %d", r.StatusCode)
	}
	if u2, _ := e.nx.User("gh-bob"); u2.Status != "disabled" {
		t.Errorf("status changed to %q", u2.Status)
	}
	if loc := location(t, b.page("/")); !strings.HasPrefix(loc, "/_bridge/login") {
		t.Error("session issued for a disabled user")
	}
}

// Rut Auth ignores the Nexus user status, so an existing session must stop
// asserting a user once that user is disabled in Nexus.
func TestDisablingRevokesExistingSession(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	b.login("bob", "/")
	if got := echo(t, b.page("/x")); got.Header.Get(header) != "gh-bob" {
		t.Fatal("not signed in")
	}
	u, _ := e.nx.User("gh-bob")
	u.Status = "disabled"
	e.nx.PutUser(u)
	e.bridge.ExpireStatusCache()

	if loc := location(t, b.page("/x")); !strings.HasPrefix(loc, "/_bridge/login") {
		t.Errorf("disabled user still signed in: %q", loc)
	}
	got := echo(t, b.do("GET", e.web.URL+"/service/rest/v1/status", nil, nil))
	if got.Header.Get(header) != "" {
		t.Error("header asserted for disabled user")
	}
	if !strings.Contains(e.logs.String(), `"msg":"session_revoked"`) {
		t.Error("missing audit line")
	}
}

func TestStatusLookupFailsClosed(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	b.login("bob", "/")
	e.bridge.ExpireStatusCache()
	e.nx.AdminPassword = "rotated" // bridge credentials no longer work
	if got := echo(t, b.do("GET", e.web.URL+"/x", nil, nil)); got.Header.Get(header) != "" {
		t.Error("header asserted although the status lookup failed")
	}
}

// AC4: forged headers never reach Nexus without a session, on both listeners.
func TestForgedHeaderStripped(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	forged := http.Header{header: {"admin"}, "X-Forwarded_User": {"admin"}, "x-forwarded-user": {"admin"}}

	for name, target := range map[string]string{"web": e.web.URL + "/service/rest/v1/status", "docker": e.reg.URL + "/v2/"} {
		got := echo(t, b.do("GET", target, forged, nil))
		for k := range got.Header {
			if strings.EqualFold(strings.ReplaceAll(k, "_", "-"), header) {
				t.Errorf("%s: forged header forwarded as %q", name, k)
			}
		}
	}
	// With basic auth too.
	h := forged.Clone()
	h.Set("Authorization", "Basic Y2k6cHc=")
	if got := echo(t, b.do("PUT", e.web.URL+"/repository/maven-releases/a.jar", h, strings.NewReader("x"))); got.Header.Get(header) != "" {
		t.Error("forged header forwarded with Authorization")
	}

	// A signed-in user cannot override their own identity either.
	b.login("bob", "/")
	if got := echo(t, b.do("GET", e.web.URL+"/service/rest/v1/status", forged, nil)); got.Header.Get(header) != "gh-bob" {
		t.Errorf("signed-in header = %q", got.Header.Get(header))
	}
}

// AC5 + AC6: build tools and Docker clients pass straight through.
func TestBuildToolsPassThrough(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	h := http.Header{"Authorization": {"Basic Y2k6cHc="}, "Accept": {"text/html"}, "X-Forwarded-Proto": {"https"}, "X-Forwarded-Host": {"nexus.example.com"}}
	payload := strings.Repeat("a", 1<<20)
	got := echo(t, b.do("PUT", e.web.URL+"/repository/maven-releases/x/1/x-1.jar", h, strings.NewReader(payload)))
	if got.Method != "PUT" || got.BodyLen != len(payload) || got.Header.Get("Authorization") != "Basic Y2k6cHc=" {
		t.Errorf("forwarded = %+v", got)
	}
	if got.Header.Get("X-Forwarded-Proto") != "https" || got.Header.Get("X-Forwarded-Host") != "nexus.example.com" {
		t.Errorf("forwarded headers not preserved: %v", got.Header)
	}
	if !strings.HasPrefix(got.Host, "127.0.0.1:") || got.Host != strings.TrimPrefix(e.web.URL, "http://") {
		t.Errorf("Host = %q, want the bridge's public host", got.Host)
	}

	// Docker: never redirected, never asserted, Authorization untouched.
	got = echo(t, b.do("GET", e.reg.URL+"/v2/myimage/manifests/latest", http.Header{"Authorization": {"Bearer abc"}, "Accept": {"text/html"}}, nil))
	if got.Path != "/v2/myimage/manifests/latest" || got.Header.Get("Authorization") != "Bearer abc" {
		t.Errorf("docker forwarded = %+v", got)
	}
}

// Rule 4 vs 5: browsers are redirected, other anonymous requests forwarded.
func TestAnonymousRouting(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	if loc := location(t, b.page("/")); loc != "/_bridge/login?rd=%2F" {
		t.Errorf("browser redirect = %q", loc)
	}
	got := echo(t, b.do("GET", e.web.URL+"/repository/maven-public/a.pom", http.Header{"Accept": {"*/*"}}, nil))
	if got.Header.Get(header) != "" {
		t.Error("anonymous request carried header")
	}
	// The ExtJS UI's XHR calls are not page loads.
	got = echo(t, b.do("POST", e.web.URL+"/service/extdirect", http.Header{"Accept": {"text/html"}}, strings.NewReader("{}")))
	if got.Method != "POST" {
		t.Error("POST not forwarded")
	}
}

// AC7: local-account escape route.
func TestLocalMode(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	b.login("bob", "/")
	if loc := location(t, b.do("GET", e.web.URL+"/_bridge/local", nil, nil)); loc != "/" {
		t.Errorf("local redirect = %q", loc)
	}
	// Bridge session was dropped; header never set; Nexus login form reachable.
	r := b.page("/")
	for _, c := range r.Cookies() {
		if c.Name == "_bridge_local" {
			t.Error("fresh local cookie re-issued on a proxied response")
		}
	}
	got := echo(t, r)
	if got.Header.Get(header) != "" {
		t.Errorf("header set in local mode: %q", got.Header.Get(header))
	}
	if !strings.Contains(e.logs.String(), `"msg":"local_mode_enabled"`) {
		t.Error("missing audit line")
	}
	// Nexus sign-out leaves local mode.
	b.do("DELETE", e.web.URL+"/service/rapture/session", nil, nil)
	if loc := location(t, b.page("/")); !strings.HasPrefix(loc, "/_bridge/login") {
		t.Errorf("still in local mode after sign-out: %q", loc)
	}
}

// AC8: Nexus "Sign out" ends the bridge session.
func TestNexusSignOutEndsSession(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	b.login("bob", "/")
	got := echo(t, b.do("DELETE", e.web.URL+"/service/rapture/session", nil, nil))
	if got.Header.Get(header) != "gh-bob" {
		t.Error("sign-out request not forwarded as the user")
	}
	if loc := location(t, b.page("/")); !strings.HasPrefix(loc, "/_bridge/login") {
		t.Errorf("session survived Nexus sign-out: %q", loc)
	}
}

func TestBridgeLogoutRequiresCSRF(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	b.login("bob", "/")
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	b.do("POST", e.web.URL+"/_bridge/logout", form, strings.NewReader("csrf=wrong"))
	if got := echo(t, b.page("/")); got.Header.Get(header) != "gh-bob" {
		t.Fatal("logout without valid CSRF token signed the user out")
	}
	page := body(t, b.page("/_bridge/login"))
	i := strings.Index(page, `name="csrf" value="`)
	token := page[i+len(`name="csrf" value="`):]
	token = token[:strings.Index(token, `"`)]
	b.do("POST", e.web.URL+"/_bridge/logout", form, strings.NewReader("csrf="+url.QueryEscape(token)))
	if loc := location(t, b.page("/")); !strings.HasPrefix(loc, "/_bridge/login") {
		t.Error("still signed in after logout")
	}
}

func TestOAuthStateValidation(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	// No state cookie at all.
	r := b.do("GET", e.web.URL+"/_bridge/callback?code=x&state=y", nil, nil)
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", r.StatusCode)
	}
	// A callback started in another browser.
	other := e.browser()
	authURL := location(t, other.do("GET", e.web.URL+"/_bridge/auth", nil, nil))
	cb := location(t, other.do("GET", authURL+"&login=bob", nil, nil))
	if r := b.do("GET", cb, nil, nil); r.StatusCode != http.StatusBadRequest {
		t.Errorf("cross-browser callback status = %d", r.StatusCode)
	}
	if _, ok := e.nx.User("gh-bob"); ok {
		t.Error("user created from a callback with a foreign state")
	}
}

func TestSafeReturn(t *testing.T) {
	e := newEnv(t, nil)
	for _, rd := range []string{"https://evil.example/", "//evil.example/", "/\\evil.example", "/_bridge/logout", "javascript:alert(1)"} {
		b := e.browser()
		r := b.do("GET", e.web.URL+"/_bridge/auth?rd="+url.QueryEscape(rd), nil, nil)
		cb := location(t, b.do("GET", location(t, r)+"&login=bob", nil, nil))
		if loc := location(t, b.do("GET", cb, nil, nil)); loc != "/" {
			t.Errorf("rd=%q redirected to %q", rd, loc)
		}
	}
}

func TestBridgeCookieFlagsAndHeaders(t *testing.T) {
	e := newEnv(t, nil)
	r := e.browser().do("GET", e.web.URL+"/_bridge/local", nil, nil)
	var found bool
	for _, c := range r.Cookies() {
		if c.Name == "_bridge_local" {
			found = true
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure {
				t.Errorf("cookie flags = %+v", c)
			}
		}
	}
	if !found {
		t.Error("no local cookie")
	}
	if !strings.Contains(r.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("missing CSP on bridge page")
	}
	// Proxied responses are untouched.
	if got := e.browser().do("GET", e.web.URL+"/repository/x", nil, nil); got.Header.Get("Content-Security-Policy") != "" {
		t.Error("CSP added to proxied response")
	}
}

func TestNoSecretsInLogs(t *testing.T) {
	e := newEnv(t, map[string]string{"LOG_LEVEL": "debug"})
	e.browser().login("Alice", "/")
	e.browser().login("bob", "/")
	u, _ := e.nx.User("gh-alice")
	logs := e.logs.String()
	for _, secret := range []string{u.Password, e.gh.ClientSecret, e.nx.AdminPassword, strings.Repeat("x", 32), "tok-"} {
		if strings.Contains(logs, secret) {
			t.Errorf("log contains secret %q", secret)
		}
	}
}

func TestStartupFailsOnMissingRole(t *testing.T) {
	gh := fakegithub.New(t)
	nx := fakenexus.New(t, "nx-admin")
	vars := map[string]string{
		"BASE_URL": "https://nexus.example.com", "NEXUS_URL": nx.URL, "NEXUS_ADMIN_USER": nx.AdminUser, "NEXUS_ADMIN_PASSWORD": nx.AdminPassword,
		"GITHUB_CLIENT_ID": "x", "GITHUB_CLIENT_SECRET": "y", "GITHUB_ORGS": "myorg", "ROLE_MAP": "myorg=nx-admin,myorg~dev=nx-missing",
		"SESSION_SECRET": strings.Repeat("x", 32), "NEXUS_STARTUP_TIMEOUT": "2s", "GITHUB_URL": gh.URL,
	}
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := vars[k]; return v, ok }, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := bridge.New(cfg, github.New(cfg.GitHubURL, cfg.GitHubAPIURL, "x", "y", cfg.GitHubOrgs), nexus.New(cfg.NexusURL, nx.AdminUser, nx.AdminPassword), slog.New(slog.DiscardHandler))
	if err := b.Startup(context.Background()); err == nil || !strings.Contains(err.Error(), "nx-missing") {
		t.Fatalf("err = %v", err)
	}

	vars["NEXUS_ADMIN_PASSWORD"] = "wrong"
	vars["NEXUS_STARTUP_TIMEOUT"] = "1500ms"
	cfg, _ = config.Load(func(k string) (string, bool) { v, ok := vars[k]; return v, ok }, nil)
	b = bridge.New(cfg, github.New(cfg.GitHubURL, cfg.GitHubAPIURL, "x", "y", cfg.GitHubOrgs), nexus.New(cfg.NexusURL, nx.AdminUser, "wrong"), slog.New(slog.DiscardHandler))
	if err := b.Startup(context.Background()); err == nil || !strings.Contains(err.Error(), "NEXUS_ADMIN_USER") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadiness(t *testing.T) {
	e := newEnv(t, nil)
	r := e.browser().do("GET", e.web.URL+"/_bridge/readyz", nil, nil)
	if r.StatusCode != http.StatusOK {
		t.Errorf("readyz = %d", r.StatusCode)
	}
	e.nx.Close()
	if r := e.browser().do("GET", e.web.URL+"/_bridge/readyz", nil, nil); r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("readyz with Nexus down = %d", r.StatusCode)
	}
	if r := e.browser().do("GET", e.web.URL+"/repository/x", nil, nil); r.StatusCode != http.StatusBadGateway {
		t.Errorf("proxy with Nexus down = %d", r.StatusCode)
	}
}

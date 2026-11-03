// Package fakegithub is an in-process stand-in for GitHub's OAuth and REST
// endpoints, used by tests only.
package fakegithub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type Email struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type Team struct {
	Org  string
	Slug string
}

type User struct {
	ID     int64
	Login  string
	Name   string
	Email  string // public email from /user
	Emails []Email
	Orgs   []string
	Teams  []Team
}

type Server struct {
	*httptest.Server
	ClientID, ClientSecret string
	PageSize               int

	mu     sync.Mutex
	users  map[string]User   // by login
	codes  map[string]string // code -> login
	tokens map[string]string // token -> login
	// verifiers checks PKCE: code -> code_challenge
	challenges map[string]string
}

func New(t testing.TB) *Server {
	s := NewUnstarted()
	s.Server = httptest.NewServer(s.Handler())
	t.Cleanup(s.Close)
	return s
}

// NewUnstarted returns a fake without a listener; serve Handler() yourself.
func NewUnstarted() *Server {
	return &Server{
		ClientID: "test-client", ClientSecret: "test-secret", PageSize: 2,
		users: map[string]User{}, codes: map[string]string{}, tokens: map[string]string{}, challenges: map[string]string{},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login/oauth/authorize", s.authorize)
	mux.HandleFunc("POST /login/oauth/access_token", s.token)
	mux.HandleFunc("GET /api/user", s.user)
	mux.HandleFunc("GET /api/user/emails", s.emails)
	mux.HandleFunc("GET /api/user/orgs", s.orgs)
	mux.HandleFunc("GET /api/user/teams", s.teams)
	return mux
}

func (s *Server) APIURL() string { return s.URL + "/api" }

func (s *Server) AddUser(u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Login] = u
}

// IssueToken returns a valid access token for login, bypassing the code flow.
func (s *Server) IssueToken(login string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := "tok-" + login + "-" + strconv.Itoa(len(s.tokens))
	s.tokens[tok] = login
	return tok
}

// authorize simulates a user who has already approved the app: it redirects
// straight back with a code. The user is chosen with the "login" query
// parameter, which tests append to the authorize URL.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != s.ClientID {
		http.Error(w, "bad client_id", http.StatusBadRequest)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE required", http.StatusBadRequest)
		return
	}
	login := q.Get("login")
	s.mu.Lock()
	_, ok := s.users[login]
	code := "code-" + strconv.Itoa(len(s.codes))
	if ok {
		s.codes[code] = login
		s.challenges[code] = q.Get("code_challenge")
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown test user "+login, http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("client_id") != s.ClientID || r.PostForm.Get("client_secret") != s.ClientSecret {
		http.Error(w, "bad client credentials", http.StatusUnauthorized)
		return
	}
	code := r.PostForm.Get("code")
	s.mu.Lock()
	login, ok := s.codes[code]
	challenge := s.challenges[code]
	delete(s.codes, code)
	s.mu.Unlock()
	if !ok || r.PostForm.Get("code_verifier") == "" || challenge == "" {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"error":"bad_verification_code"}`)
		return
	}
	if s256(r.PostForm.Get("code_verifier")) != challenge {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
		return
	}
	tok := s.IssueToken(login)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"access_token": tok, "token_type": "bearer", "scope": "read:user,user:email,read:org"})
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request) (User, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	defer s.mu.Unlock()
	login, ok := s.tokens[tok]
	if !ok {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return User{}, false
	}
	return s.users[login], true
}

func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	u, ok := s.auth(w, r)
	if !ok {
		return
	}
	var name, email any
	if u.Name != "" {
		name = u.Name
	}
	if u.Email != "" {
		email = u.Email
	}
	writeJSON(w, map[string]any{"id": u.ID, "login": u.Login, "name": name, "email": email})
}

func (s *Server) emails(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.auth(w, r); ok {
		s.paginate(w, r, toAny(u.Emails, func(e Email) any { return e }))
	}
}

func (s *Server) orgs(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.auth(w, r); ok {
		s.paginate(w, r, toAny(u.Orgs, func(o string) any { return map[string]any{"login": o} }))
	}
}

func (s *Server) teams(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.auth(w, r); ok {
		s.paginate(w, r, toAny(u.Teams, func(t Team) any {
			return map[string]any{"slug": t.Slug, "organization": map[string]any{"login": t.Org}}
		}))
	}
}

// paginate serves PageSize items per page with a GitHub-style Link header,
// ignoring the client's per_page so pagination is always exercised.
func (s *Server) paginate(w http.ResponseWriter, r *http.Request, items []any) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	start := (page - 1) * s.PageSize
	end := min(start+s.PageSize, len(items))
	if start > len(items) {
		start = len(items)
	}
	if end < len(items) {
		next := *r.URL
		q := next.Query()
		q.Set("page", strconv.Itoa(page+1))
		next.RawQuery = q.Encode()
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s>; rel="next"`, r.Host, next.RequestURI()))
	}
	writeJSON(w, items[start:end])
}

func toAny[T any](in []T, f func(T) any) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, f(v))
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

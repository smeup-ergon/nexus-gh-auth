// Package fakenexus is an in-process stand-in for Nexus Repository, used by
// tests only. It implements the security REST endpoints the bridge calls and,
// for every other path, echoes the request it received so tests can assert
// what the proxy forwarded.
package fakenexus

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/smeup-ergon/nexus-gh-auth/internal/nexus"
)

type Server struct {
	*httptest.Server
	AdminUser, AdminPassword string

	mu    sync.Mutex
	users map[string]nexus.User
	roles map[string]bool
	Calls []string // "METHOD path" of security API calls
}

// Echo is the JSON body returned for non-API requests.
type Echo struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Host    string      `json:"host"`
	Header  http.Header `json:"header"`
	BodyLen int         `json:"bodyLen"`
}

func New(t testing.TB, roles ...string) *Server {
	s := &Server{AdminUser: "github-bridge", AdminPassword: "bridge-pw", users: map[string]nexus.User{}, roles: map[string]bool{}}
	for _, r := range roles {
		s.roles[r] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /service/rest/v1/security/users", s.admin(s.listUsers))
	mux.HandleFunc("POST /service/rest/v1/security/users", s.admin(s.createUser))
	mux.HandleFunc("PUT /service/rest/v1/security/users/{id}", s.admin(s.updateUser))
	mux.HandleFunc("GET /service/rest/v1/security/roles", s.admin(s.listRoles))
	mux.HandleFunc("/", s.echo)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *Server) User(id string) (nexus.User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	return u, ok
}

func (s *Server) PutUser(u nexus.User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.Source == "" {
		u.Source = "default"
	}
	s.users[u.UserID] = u
}

func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != s.AdminUser || p != s.AdminPassword {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.mu.Lock()
		s.Calls = append(s.Calls, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		h(w, r)
	}
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	term := r.URL.Query().Get("userId")
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []nexus.User{}
	for id, u := range s.users {
		// Like Nexus, the filter is a prefix match, not exact.
		if strings.HasPrefix(id, term) {
			u.Password = ""
			out = append(out, u)
		}
	}
	writeJSON(w, out)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var u nexus.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil || !s.valid(w, u) {
		return
	}
	if u.Password == "" {
		http.Error(w, "password required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[u.UserID]; exists {
		http.Error(w, "exists", http.StatusBadRequest)
		return
	}
	u.Source = "default"
	s.users[u.UserID] = u
	u.Password = ""
	writeJSON(w, u)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var u nexus.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil || !s.valid(w, u) {
		return
	}
	if u.UserID != r.PathValue("id") {
		http.Error(w, "id mismatch", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[u.UserID]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	u.Password = old.Password // PUT never changes the password
	s.users[u.UserID] = u
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) valid(w http.ResponseWriter, u nexus.User) bool {
	if u.UserID == "" || u.FirstName == "" || u.LastName == "" || !strings.Contains(u.EmailAddress, "@") || u.Status == "" {
		http.Error(w, "missing required field", http.StatusBadRequest)
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, role := range u.Roles {
		if !s.roles[role] {
			http.Error(w, "unknown role "+role, http.StatusBadRequest)
			return false
		}
	}
	return true
}

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []map[string]string{}
	for id := range s.roles {
		out = append(out, map[string]string{"id": id, "source": "default"})
	}
	writeJSON(w, out)
}

func (s *Server) echo(w http.ResponseWriter, r *http.Request) {
	n, _ := io.Copy(io.Discard, r.Body)
	writeJSON(w, Echo{Method: r.Method, Path: r.URL.RequestURI(), Host: r.Host, Header: r.Header, BodyLen: int(n)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

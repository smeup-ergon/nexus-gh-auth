// Package nexus is a minimal client for the Nexus Repository security REST API.
package nexus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusLocked   = "locked"
)

// ErrUserNotActive is returned by Upsert when the existing user is disabled
// or locked in Nexus.
var ErrUserNotActive = errors.New("nexus user is not active")

type User struct {
	UserID        string   `json:"userId"`
	FirstName     string   `json:"firstName"`
	LastName      string   `json:"lastName"`
	EmailAddress  string   `json:"emailAddress"`
	Source        string   `json:"source"`
	Status        string   `json:"status"`
	ReadOnly      bool     `json:"readOnly"`
	Roles         []string `json:"roles"`
	ExternalRoles []string `json:"externalRoles"`
	// Password is only sent on create.
	Password string `json:"password,omitempty"`
}

type Client struct {
	base     *url.URL
	user     string
	password string
	http     *http.Client
}

func New(base *url.URL, user, password string) *Client {
	return &Client{base: base, user: user, password: password, http: &http.Client{Timeout: 30 * time.Second}}
}

// Desired is the state the bridge wants for a user.
type Desired struct {
	UserID       string
	FirstName    string
	LastName     string
	EmailAddress string
	Roles        []string
}

// Result describes what Upsert did.
type Result struct {
	Created      bool
	RolesAdded   []string
	RolesRemoved []string
}

// Upsert creates the user (with a random unusable password) or updates its
// name, email and roles. Status and password of an existing user are never
// changed.
func (c *Client) Upsert(ctx context.Context, d Desired, newPassword func() string) (Result, error) {
	existing, err := c.GetUser(ctx, d.UserID)
	if err != nil {
		return Result{}, err
	}
	if existing == nil {
		u := User{
			UserID: d.UserID, FirstName: d.FirstName, LastName: d.LastName, EmailAddress: d.EmailAddress,
			Status: StatusActive, Roles: d.Roles, Password: newPassword(),
		}
		if err := c.do(ctx, http.MethodPost, "/service/rest/v1/security/users", nil, u, nil); err != nil {
			return Result{}, err
		}
		return Result{Created: true, RolesAdded: slices.Clone(d.Roles)}, nil
	}
	if existing.Status != StatusActive {
		return Result{}, fmt.Errorf("%w (status %q)", ErrUserNotActive, existing.Status)
	}
	if existing.Source != "" && existing.Source != "default" {
		return Result{}, fmt.Errorf("nexus user %q belongs to source %q, not managed by the bridge", d.UserID, existing.Source)
	}
	res := Result{RolesAdded: diff(d.Roles, existing.Roles), RolesRemoved: diff(existing.Roles, d.Roles)}
	if existing.FirstName == d.FirstName && existing.LastName == d.LastName &&
		existing.EmailAddress == d.EmailAddress && len(res.RolesAdded) == 0 && len(res.RolesRemoved) == 0 {
		return res, nil
	}
	u := *existing
	u.FirstName, u.LastName, u.EmailAddress, u.Roles = d.FirstName, d.LastName, d.EmailAddress, d.Roles
	u.Source = "default"
	u.Password = ""
	if err := c.do(ctx, http.MethodPut, "/service/rest/v1/security/users/"+url.PathEscape(d.UserID), nil, u, nil); err != nil {
		return Result{}, err
	}
	return res, nil
}

// GetUser returns the local user with exactly this id, or nil.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	var users []User
	q := url.Values{"userId": {id}, "source": {"default"}}
	if err := c.do(ctx, http.MethodGet, "/service/rest/v1/security/users", q, nil, &users); err != nil {
		return nil, err
	}
	// The userId filter is a prefix/term search, so match exactly.
	for i := range users {
		if users[i].UserID == id {
			return &users[i], nil
		}
	}
	return nil, nil
}

// MissingRoles returns the role ids from want that do not exist in Nexus.
func (c *Client) MissingRoles(ctx context.Context, want []string) ([]string, error) {
	var roles []struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, "/service/rest/v1/security/roles", nil, nil, &roles); err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, r := range roles {
		have[r.ID] = true
	}
	var missing []string
	for _, r := range want {
		if !have[r] {
			missing = append(missing, r)
		}
	}
	return missing, nil
}

// Ping checks that Nexus answers and the credentials work, using only the
// privileges the bridge role already has (nx-users-read).
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.GetUser(ctx, c.user)
	return err
}

// HTTPError is a non-2xx response from Nexus.
type HTTPError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("nexus: %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = q.Encode()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("nexus: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &HTTPError{Method: method, Path: path, Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("nexus: %s %s: decoding response: %w", method, path, err)
	}
	return nil
}

func diff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

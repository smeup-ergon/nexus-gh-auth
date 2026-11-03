// Package github implements the GitHub (and GitHub Enterprise) provider.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/smeup-ergon/nexus-gh-auth/internal/provider"
	"golang.org/x/oauth2"
)

// Identity groups are "<org>" and "<org>~<team-slug>", lower-cased.
type Identity = provider.Identity

var _ provider.Provider = (*Provider)(nil)

type Provider struct {
	webURL      *url.URL
	apiURL      *url.URL
	clientID    string
	secret      string
	allowedOrgs map[string]bool
}

func New(webURL, apiURL *url.URL, clientID, secret string, orgs []string) *Provider {
	allowed := make(map[string]bool, len(orgs))
	for _, o := range orgs {
		allowed[strings.ToLower(o)] = true
	}
	return &Provider{webURL: webURL, apiURL: apiURL, clientID: clientID, secret: secret, allowedOrgs: allowed}
}

func (p *Provider) Name() string { return "github" }

func (p *Provider) Scopes() []string { return []string{"read:user", "user:email", "read:org"} }

// FallbackEmail returns GitHub's no-reply address for the user. GitHub
// Enterprise uses users.noreply.<hostname>.
func (p *Provider) FallbackEmail(id Identity) string {
	domain := "users.noreply.github.com"
	if h := p.webURL.Hostname(); h != "github.com" {
		domain = "users.noreply." + h
	}
	return strconv.FormatInt(id.ID, 10) + "+" + id.Login + "@" + domain
}

// OAuth2Config returns the code-flow configuration for the given redirect URI.
func (p *Provider) OAuth2Config(redirectURL string) *oauth2.Config {
	base := p.webURL.String()
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.secret,
		RedirectURL:  redirectURL,
		Scopes:       p.Scopes(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   base + "/login/oauth/authorize",
			TokenURL:  base + "/login/oauth/access_token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

type apiUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type apiEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type apiOrg struct {
	Login string `json:"login"`
}

type apiTeam struct {
	Slug         string `json:"slug"`
	Organization apiOrg `json:"organization"`
}

// Identify fetches the user's identity using an OAuth token. The token is not
// retained.
func (p *Provider) Identify(ctx context.Context, client *http.Client) (Identity, error) {
	var u apiUser
	if err := p.get(ctx, client, "/user", &u); err != nil {
		return Identity{}, err
	}
	if u.ID == 0 || u.Login == "" {
		return Identity{}, fmt.Errorf("github: /user returned no id or login")
	}

	email := strings.TrimSpace(u.Email)
	if email == "" {
		var emails []apiEmail
		if err := p.getAll(ctx, client, "/user/emails", func(raw json.RawMessage) error {
			var page []apiEmail
			err := json.Unmarshal(raw, &page)
			emails = append(emails, page...)
			return err
		}); err != nil {
			return Identity{}, err
		}
		email = selectEmail(emails)
	}

	groups, err := p.groups(ctx, client)
	if err != nil {
		return Identity{}, err
	}

	name := strings.TrimSpace(u.Name)
	if name == "" {
		name = u.Login
	}
	return Identity{
		Subject:     "github:" + strconv.FormatInt(u.ID, 10),
		ID:          u.ID,
		Login:       u.Login,
		DisplayName: name,
		Email:       email,
		Groups:      groups,
	}, nil
}

// selectEmail prefers the primary verified address, then any verified one.
func selectEmail(emails []apiEmail) string {
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email
		}
	}
	return ""
}

func (p *Provider) groups(ctx context.Context, client *http.Client) ([]string, error) {
	seen := map[string]bool{}
	var groups []string
	add := func(g string) {
		if !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
	}
	err := p.getAll(ctx, client, "/user/orgs", func(raw json.RawMessage) error {
		var page []apiOrg
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, o := range page {
			if org := strings.ToLower(o.Login); p.allowedOrgs[org] {
				add(org)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = p.getAll(ctx, client, "/user/teams", func(raw json.RawMessage) error {
		var page []apiTeam
		if err := json.Unmarshal(raw, &page); err != nil {
			return err
		}
		for _, t := range page {
			org := strings.ToLower(t.Organization.Login)
			if p.allowedOrgs[org] && t.Slug != "" {
				// Team membership implies org membership, even when the org
				// hides the user's membership from /user/orgs.
				add(org)
				add(org + "~" + strings.ToLower(t.Slug))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func (p *Provider) get(ctx context.Context, client *http.Client, path string, v any) error {
	resp, err := p.do(ctx, client, p.apiURL.String()+path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// maxPages bounds pagination so a misbehaving API cannot loop forever.
const maxPages = 50

func (p *Provider) getAll(ctx context.Context, client *http.Client, path string, page func(json.RawMessage) error) error {
	next := p.apiURL.String() + path + "?per_page=100"
	for i := 0; next != "" && i < maxPages; i++ {
		resp, err := p.do(ctx, client, next)
		if err != nil {
			return err
		}
		var raw json.RawMessage
		err = json.NewDecoder(resp.Body).Decode(&raw)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("github: decoding %s: %w", path, err)
		}
		if err := page(raw); err != nil {
			return fmt.Errorf("github: decoding %s: %w", path, err)
		}
		next = ""
		if m := nextLink.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			// Only follow links that stay on the configured API host.
			if u, err := url.Parse(m[1]); err == nil && u.Host == p.apiURL.Host {
				next = m[1]
			}
		}
	}
	return nil
}

func (p *Provider) do(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: GET %s: %w", req.URL.Path, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("github: GET %s: unexpected status %d", req.URL.Path, resp.StatusCode)
	}
	return resp, nil
}

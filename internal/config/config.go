// Package config loads and validates the bridge configuration from the
// environment. Every secret also accepts a <VAR>_FILE variant.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"
)

type RoleMapping struct {
	Group string // lower-cased "<org>" or "<org>~<team-slug>"
	Role  string
}

type Config struct {
	BaseURL      *url.URL
	WebListen    string
	DockerListen string

	NexusURL            *url.URL
	NexusDockerURL      *url.URL
	NexusUserHeader     string
	NexusAdminUser      string
	NexusAdminPassword  string
	NexusUserPrefix     string
	NexusStartupTimeout time.Duration

	GitHubClientID     string
	GitHubClientSecret string
	GitHubURL          *url.URL
	GitHubAPIURL       *url.URL
	GitHubOrgs         []string // lower-cased
	RoleMap            []RoleMapping

	SessionSecret []byte
	SessionTTL    time.Duration
	LogLevel      slog.Level
}

// Load reads the configuration using lookup (os.LookupEnv in production) and
// readFile (os.ReadFile in production). All problems are reported together.
func Load(lookup func(string) (string, bool), readFile func(string) ([]byte, error)) (*Config, error) {
	l := loader{lookup: lookup, readFile: readFile}
	c := &Config{
		BaseURL:             l.url("BASE_URL", "", true),
		WebListen:           l.str("WEB_LISTEN", ":8081", true),
		DockerListen:        l.optional("DOCKER_LISTEN", ":5000"),
		NexusURL:            l.url("NEXUS_URL", "http://nexus:8081", true),
		NexusDockerURL:      l.url("NEXUS_DOCKER_URL", "http://nexus:5000", false),
		NexusUserHeader:     l.str("NEXUS_USER_HEADER", "X-Forwarded-User", true),
		NexusAdminUser:      l.str("NEXUS_ADMIN_USER", "", true),
		NexusAdminPassword:  l.secret("NEXUS_ADMIN_PASSWORD"),
		NexusUserPrefix:     l.str("NEXUS_USER_PREFIX", "gh-", false),
		NexusStartupTimeout: l.duration("NEXUS_STARTUP_TIMEOUT", 5*time.Minute),
		GitHubClientID:      l.str("GITHUB_CLIENT_ID", "", true),
		GitHubClientSecret:  l.secret("GITHUB_CLIENT_SECRET"),
		GitHubURL:           l.url("GITHUB_URL", "https://github.com", true),
		GitHubAPIURL:        l.url("GITHUB_API_URL", "https://api.github.com", true),
		GitHubOrgs:          l.list("GITHUB_ORGS"),
		SessionTTL:          l.duration("SESSION_TTL", 8*time.Hour),
	}
	c.SessionSecret = []byte(l.secret("SESSION_SECRET"))
	if len(c.SessionSecret) > 0 && len(c.SessionSecret) < 32 {
		l.fail("SESSION_SECRET", "must be at least 32 bytes")
	}
	if c.DockerListen != "" && c.NexusDockerURL == nil {
		l.fail("NEXUS_DOCKER_URL", "is required when DOCKER_LISTEN is set")
	}
	if c.BaseURL != nil && c.BaseURL.Path != "" && c.BaseURL.Path != "/" {
		l.fail("BASE_URL", "must not contain a path")
	}
	if c.SessionTTL <= 0 {
		l.fail("SESSION_TTL", "must be positive")
	}
	c.RoleMap = l.roleMap("ROLE_MAP", c.GitHubOrgs)
	c.LogLevel = l.level("LOG_LEVEL")

	if len(l.errs) > 0 {
		return nil, errors.Join(l.errs...)
	}
	return c, nil
}

// FromEnv loads the configuration from the process environment.
func FromEnv() (*Config, error) { return Load(os.LookupEnv, os.ReadFile) }

type loader struct {
	lookup   func(string) (string, bool)
	readFile func(string) ([]byte, error)
	errs     []error
}

func (l *loader) getenv(name string) string {
	v, _ := l.lookup(name)
	return v
}

// optional returns def when name is unset, and the (possibly empty) value when
// it is set, so an explicitly empty value disables the feature.
func (l *loader) optional(name, def string) string {
	v, ok := l.lookup(name)
	if !ok {
		return def
	}
	return strings.TrimSpace(v)
}

func (l *loader) fail(name, msg string) {
	l.errs = append(l.errs, fmt.Errorf("%s %s", name, msg))
}

func (l *loader) str(name, def string, required bool) string {
	v := strings.TrimSpace(l.getenv(name))
	if v == "" {
		v = def
	}
	if v == "" && required {
		l.fail(name, "is required")
	}
	return v
}

func (l *loader) secret(name string) string {
	v := l.getenv(name)
	path := l.getenv(name + "_FILE")
	switch {
	case v != "" && path != "":
		l.fail(name, "and "+name+"_FILE are mutually exclusive")
		return ""
	case path != "":
		b, err := l.readFile(path)
		if err != nil {
			l.fail(name+"_FILE", "cannot be read: "+err.Error())
			return ""
		}
		v = strings.TrimRight(string(b), "\r\n")
	}
	if v == "" {
		l.fail(name, "(or "+name+"_FILE) is required")
	}
	return v
}

func (l *loader) url(name, def string, required bool) *url.URL {
	v := l.str(name, def, required)
	if v == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimRight(v, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		l.fail(name, "must be an absolute http(s) URL")
		return nil
	}
	return u
}

func (l *loader) duration(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(l.getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.fail(name, "must be a duration like 8h or 5m")
		return def
	}
	return d
}

func (l *loader) list(name string) []string {
	var out []string
	for _, p := range strings.Split(l.getenv(name), ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		l.fail(name, "is required")
	}
	return out
}

func (l *loader) roleMap(name string, orgs []string) []RoleMapping {
	raw := strings.TrimSpace(l.getenv(name))
	if raw == "" {
		l.fail(name, "is required")
		return nil
	}
	allowed := map[string]bool{}
	for _, o := range orgs {
		allowed[o] = true
	}
	var out []RoleMapping
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		group, role, ok := strings.Cut(pair, "=")
		group = strings.ToLower(strings.TrimSpace(group))
		role = strings.TrimSpace(role)
		if !ok || group == "" || role == "" {
			l.fail(name, fmt.Sprintf("entry %q must look like group=role", pair))
			continue
		}
		org, _, _ := strings.Cut(group, "~")
		if len(orgs) > 0 && !allowed[org] {
			l.fail(name, fmt.Sprintf("entry %q refers to org %q which is not in GITHUB_ORGS", pair, org))
			continue
		}
		out = append(out, RoleMapping{Group: group, Role: role})
	}
	return out
}

func (l *loader) level(name string) slog.Level {
	var lv slog.Level
	v := strings.TrimSpace(l.getenv(name))
	if v == "" {
		return slog.LevelInfo
	}
	if err := lv.UnmarshalText([]byte(v)); err != nil {
		l.fail(name, "must be one of debug, info, warn, error")
	}
	return lv
}

// SecureCookies reports whether cookies must carry the Secure flag.
func (c *Config) SecureCookies() bool { return c.BaseURL.Scheme == "https" }

// CallbackURL is the fixed OAuth redirect URI.
func (c *Config) CallbackURL() string { return c.BaseURL.String() + "/_bridge/callback" }

// RolesFor returns the deduplicated Nexus roles mapped from groups, in
// ROLE_MAP order.
func (c *Config) RolesFor(groups []string) []string {
	have := map[string]bool{}
	for _, g := range groups {
		have[strings.ToLower(g)] = true
	}
	seen := map[string]bool{}
	var roles []string
	for _, m := range c.RoleMap {
		if have[m.Group] && !seen[m.Role] {
			seen[m.Role] = true
			roles = append(roles, m.Role)
		}
	}
	return roles
}

// MappedRoles returns every distinct role referenced by ROLE_MAP.
func (c *Config) MappedRoles() []string {
	seen := map[string]bool{}
	var roles []string
	for _, m := range c.RoleMap {
		if !seen[m.Role] {
			seen[m.Role] = true
			roles = append(roles, m.Role)
		}
	}
	return roles
}

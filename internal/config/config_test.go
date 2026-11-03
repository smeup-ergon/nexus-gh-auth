package config

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func baseEnv() map[string]string {
	return map[string]string{
		"BASE_URL":             "https://nexus.example.com",
		"NEXUS_ADMIN_USER":     "github-bridge",
		"NEXUS_ADMIN_PASSWORD": "pw",
		"GITHUB_CLIENT_ID":     "cid",
		"GITHUB_CLIENT_SECRET": "csecret",
		"GITHUB_ORGS":          "MyOrg, other",
		"ROLE_MAP":             "myorg~Platform=nx-admin, myorg=nx-dev,other=nx-dev",
		"SESSION_SECRET":       strings.Repeat("s", 32),
	}
}

func load(env map[string]string, files map[string]string) (*Config, error) {
	return Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok }, func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	})
}

func TestLoadDefaults(t *testing.T) {
	c, err := load(baseEnv(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.WebListen != ":8081" || c.DockerListen != ":5000" || c.NexusUserHeader != "X-Forwarded-User" || c.NexusUserPrefix != "gh-" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.NexusURL.String() != "http://nexus:8081" || c.NexusDockerURL.String() != "http://nexus:5000" {
		t.Errorf("unexpected upstreams: %s %s", c.NexusURL, c.NexusDockerURL)
	}
	if c.SessionTTL != 8*time.Hour || c.NexusStartupTimeout != 5*time.Minute {
		t.Errorf("unexpected durations")
	}
	if !reflect.DeepEqual(c.GitHubOrgs, []string{"myorg", "other"}) {
		t.Errorf("orgs = %v", c.GitHubOrgs)
	}
	if c.CallbackURL() != "https://nexus.example.com/_bridge/callback" || !c.SecureCookies() {
		t.Errorf("callback = %s", c.CallbackURL())
	}
}

func TestRolesFor(t *testing.T) {
	c, err := load(baseEnv(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RolesFor([]string{"myorg", "myorg~platform"}); !reflect.DeepEqual(got, []string{"nx-admin", "nx-dev"}) {
		t.Errorf("RolesFor = %v", got)
	}
	if got := c.RolesFor([]string{"MyOrg~Platform"}); !reflect.DeepEqual(got, []string{"nx-admin"}) {
		t.Errorf("case-insensitive RolesFor = %v", got)
	}
	if got := c.RolesFor([]string{"myorg~other"}); got != nil {
		t.Errorf("unmapped = %v", got)
	}
	if got := c.MappedRoles(); !reflect.DeepEqual(got, []string{"nx-admin", "nx-dev"}) {
		t.Errorf("MappedRoles = %v", got)
	}
}

func TestSecretFile(t *testing.T) {
	env := baseEnv()
	delete(env, "NEXUS_ADMIN_PASSWORD")
	env["NEXUS_ADMIN_PASSWORD_FILE"] = "/run/secrets/nexus"
	c, err := load(env, map[string]string{"/run/secrets/nexus": "from-file\n"})
	if err != nil {
		t.Fatal(err)
	}
	if c.NexusAdminPassword != "from-file" {
		t.Errorf("password = %q", c.NexusAdminPassword)
	}
}

func TestErrorsNameTheVariable(t *testing.T) {
	cases := map[string]func(map[string]string){
		"BASE_URL is required":             func(e map[string]string) { delete(e, "BASE_URL") },
		"BASE_URL must not contain a path": func(e map[string]string) { e["BASE_URL"] = "https://x/nexus" },
		"BASE_URL must be an absolute":     func(e map[string]string) { e["BASE_URL"] = "nexus.example.com" },
		"SESSION_SECRET must be at least":  func(e map[string]string) { e["SESSION_SECRET"] = "short" },
		"GITHUB_CLIENT_SECRET (or":         func(e map[string]string) { delete(e, "GITHUB_CLIENT_SECRET") },
		"mutually exclusive":               func(e map[string]string) { e["GITHUB_CLIENT_SECRET_FILE"] = "/x" },
		"GITHUB_CLIENT_SECRET_FILE cannot": func(e map[string]string) {
			delete(e, "GITHUB_CLIENT_SECRET")
			e["GITHUB_CLIENT_SECRET_FILE"] = "/missing"
		},
		"not in GITHUB_ORGS":             func(e map[string]string) { e["ROLE_MAP"] = "stranger=nx-dev" },
		"must look like group=role":      func(e map[string]string) { e["ROLE_MAP"] = "myorg" },
		"SESSION_TTL must be a duration": func(e map[string]string) { e["SESSION_TTL"] = "forever" },
		"LOG_LEVEL must be one of":       func(e map[string]string) { e["LOG_LEVEL"] = "loud" },
		"GITHUB_ORGS is required":        func(e map[string]string) { e["GITHUB_ORGS"] = " , " },
	}
	for want, mutate := range cases {
		env := baseEnv()
		mutate(env)
		_, err := load(env, nil)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want error containing %q, got %v", want, err)
		}
	}
}

func TestAllErrorsReportedTogether(t *testing.T) {
	_, err := load(map[string]string{}, nil)
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) < 6 {
		t.Fatalf("expected many joined errors, got %v", err)
	}
}

func TestDockerListenerCanBeDisabled(t *testing.T) {
	env := baseEnv()
	env["DOCKER_LISTEN"] = ""
	c, err := load(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.DockerListen != "" {
		t.Errorf("DockerListen = %q", c.DockerListen)
	}
}

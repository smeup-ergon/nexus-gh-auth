package github

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/smeup-ergon/nexus-gh-auth/internal/testing/fakegithub"
	"golang.org/x/oauth2"
)

func setup(t *testing.T, u fakegithub.User) (*Provider, *http.Client) {
	t.Helper()
	gh := fakegithub.New(t)
	gh.AddUser(u)
	web, _ := url.Parse(gh.URL)
	api, _ := url.Parse(gh.APIURL())
	p := New(web, api, gh.ClientID, gh.ClientSecret, []string{"MyOrg"})
	tok := &oauth2.Token{AccessToken: gh.IssueToken(u.Login)}
	return p, oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(tok))
}

func TestIdentify(t *testing.T) {
	p, client := setup(t, fakegithub.User{
		ID: 42, Login: "Alice", Name: "Alice Liddell",
		Emails: []fakegithub.Email{{Email: "old@x", Verified: true}, {Email: "a@x", Primary: true, Verified: true}},
		Orgs:   []string{"stranger", "MyOrg", "another"},
		Teams: []fakegithub.Team{
			{Org: "MyOrg", Slug: "platform"}, {Org: "stranger", Slug: "ops"}, {Org: "myorg", Slug: "Docs"},
		},
	})
	id, err := p.Identify(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{
		Subject: "github:42", ID: 42, Login: "Alice", DisplayName: "Alice Liddell", Email: "a@x",
		Groups: []string{"myorg", "myorg~platform", "myorg~docs"},
	}
	if !reflect.DeepEqual(id, want) {
		t.Errorf("Identify =\n %+v\nwant\n %+v", id, want)
	}
}

func TestEmailSelection(t *testing.T) {
	cases := []struct {
		name   string
		public string
		emails []fakegithub.Email
		want   string
	}{
		{"public email wins", "pub@x", []fakegithub.Email{{Email: "p@x", Primary: true, Verified: true}}, "pub@x"},
		{"primary verified", "", []fakegithub.Email{{Email: "v@x", Verified: true}, {Email: "p@x", Primary: true, Verified: true}}, "p@x"},
		{"unverified primary skipped", "", []fakegithub.Email{{Email: "p@x", Primary: true}, {Email: "v@x", Verified: true}}, "v@x"},
		{"none verified", "", []fakegithub.Email{{Email: "p@x", Primary: true}}, ""},
		{"no emails", "", nil, ""},
		// Exercises pagination of /user/emails (page size 2).
		{"verified on page 2", "", []fakegithub.Email{{Email: "a@x"}, {Email: "b@x"}, {Email: "c@x", Verified: true}}, "c@x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, client := setup(t, fakegithub.User{ID: 1, Login: "u", Email: tc.public, Emails: tc.emails})
			id, err := p.Identify(context.Background(), client)
			if err != nil {
				t.Fatal(err)
			}
			if id.Email != tc.want {
				t.Errorf("email = %q, want %q", id.Email, tc.want)
			}
		})
	}
}

func TestDisplayNameFallback(t *testing.T) {
	p, client := setup(t, fakegithub.User{ID: 1, Login: "bob"})
	id, err := p.Identify(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if id.DisplayName != "bob" || id.Groups != nil {
		t.Errorf("got %+v", id)
	}
}

func TestBadToken(t *testing.T) {
	p, _ := setup(t, fakegithub.User{ID: 1, Login: "bob"})
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "nope"}))
	if _, err := p.Identify(context.Background(), client); err == nil {
		t.Fatal("expected error")
	}
}

func TestFallbackEmail(t *testing.T) {
	gh, _ := url.Parse("https://github.com")
	ghe, _ := url.Parse("https://git.corp.example")
	id := Identity{ID: 42, Login: "alice"}
	if got := New(gh, gh, "", "", nil).FallbackEmail(id); got != "42+alice@users.noreply.github.com" {
		t.Errorf("github.com fallback = %q", got)
	}
	if got := New(ghe, ghe, "", "", nil).FallbackEmail(id); got != "42+alice@users.noreply.git.corp.example" {
		t.Errorf("GHE fallback = %q", got)
	}
}

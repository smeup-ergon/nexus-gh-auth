package nexus_test

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"testing"

	"github.com/smeup-ergon/nexus-gh-auth/internal/nexus"
	"github.com/smeup-ergon/nexus-gh-auth/internal/testing/fakenexus"
)

func client(t *testing.T, fn *fakenexus.Server) *nexus.Client {
	u, _ := url.Parse(fn.URL)
	return nexus.New(u, fn.AdminUser, fn.AdminPassword)
}

func pw() string { return "random-pw" }

func TestUpsertCreatesThenUpdates(t *testing.T) {
	fn := fakenexus.New(t, "nx-admin", "nx-dev")
	c := client(t, fn)
	ctx := context.Background()

	d := nexus.Desired{UserID: "gh-alice", FirstName: "Alice", LastName: "(GitHub)", EmailAddress: "a@x", Roles: []string{"nx-dev"}}
	res, err := c.Upsert(ctx, d, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || !reflect.DeepEqual(res.RolesAdded, []string{"nx-dev"}) {
		t.Errorf("create result = %+v", res)
	}
	u, _ := fn.User("gh-alice")
	if u.Password != "random-pw" || u.Status != nexus.StatusActive {
		t.Errorf("created user = %+v", u)
	}

	d.Roles = []string{"nx-admin"}
	d.EmailAddress = "new@x"
	res, err = c.Upsert(ctx, d, func() string { t.Fatal("password generated on update"); return "" })
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || !reflect.DeepEqual(res.RolesAdded, []string{"nx-admin"}) || !reflect.DeepEqual(res.RolesRemoved, []string{"nx-dev"}) {
		t.Errorf("update result = %+v", res)
	}
	u, _ = fn.User("gh-alice")
	if u.Password != "random-pw" || u.EmailAddress != "new@x" || !reflect.DeepEqual(u.Roles, []string{"nx-admin"}) {
		t.Errorf("updated user = %+v", u)
	}
}

func TestUpsertNoChangeSkipsPut(t *testing.T) {
	fn := fakenexus.New(t, "nx-dev")
	c := client(t, fn)
	d := nexus.Desired{UserID: "gh-a", FirstName: "A", LastName: "(GitHub)", EmailAddress: "a@x", Roles: []string{"nx-dev"}}
	if _, err := c.Upsert(context.Background(), d, pw); err != nil {
		t.Fatal(err)
	}
	fn.Calls = nil
	if _, err := c.Upsert(context.Background(), d, pw); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fn.Calls, []string{"GET /service/rest/v1/security/users"}) {
		t.Errorf("calls = %v", fn.Calls)
	}
}

func TestUpsertExactMatchOnPrefixSearch(t *testing.T) {
	fn := fakenexus.New(t, "nx-dev")
	fn.PutUser(nexus.User{UserID: "gh-alice2", FirstName: "x", LastName: "y", EmailAddress: "x@y", Status: nexus.StatusDisabled})
	c := client(t, fn)
	res, err := c.Upsert(context.Background(), nexus.Desired{UserID: "gh-alice", FirstName: "A", LastName: "(GitHub)", EmailAddress: "a@x"}, pw)
	if err != nil || !res.Created {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestUpsertRefusesInactive(t *testing.T) {
	for _, status := range []string{nexus.StatusDisabled, nexus.StatusLocked} {
		fn := fakenexus.New(t, "nx-dev")
		fn.PutUser(nexus.User{UserID: "gh-a", FirstName: "A", LastName: "(GitHub)", EmailAddress: "a@x", Status: status})
		_, err := client(t, fn).Upsert(context.Background(), nexus.Desired{UserID: "gh-a", FirstName: "A", LastName: "(GitHub)", EmailAddress: "a@x", Roles: []string{"nx-dev"}}, pw)
		if !errors.Is(err, nexus.ErrUserNotActive) {
			t.Errorf("%s: err = %v", status, err)
		}
		if u, _ := fn.User("gh-a"); u.Status != status || u.Roles != nil {
			t.Errorf("%s: user modified: %+v", status, u)
		}
	}
}

func TestMissingRolesAndAuth(t *testing.T) {
	fn := fakenexus.New(t, "nx-admin")
	c := client(t, fn)
	missing, err := c.MissingRoles(context.Background(), []string{"nx-admin", "nx-dev"})
	if err != nil || !reflect.DeepEqual(missing, []string{"nx-dev"}) {
		t.Errorf("missing=%v err=%v", missing, err)
	}
	u, _ := url.Parse(fn.URL)
	var he *nexus.HTTPError
	if err := nexus.New(u, "x", "y").Ping(context.Background()); !errors.As(err, &he) || he.Status != 401 {
		t.Errorf("Ping with bad creds = %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping = %v", err)
	}
}

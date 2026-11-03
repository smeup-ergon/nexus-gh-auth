// Command fakegithub runs the fake GitHub as a standalone server for
// end-to-end checks against a real Nexus. Not for production use.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/smeup-ergon/nexus-gh-auth/internal/testing/fakegithub"
)

func main() {
	listen := flag.String("listen", ":9000", "listen address")
	users := flag.String("users", "alice:1:myorg/platform,bob:2:myorg/dev", "login:id:org/team,...")
	flag.Parse()
	s := fakegithub.NewUnstarted()
	for _, spec := range strings.Split(*users, ",") {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) != 3 {
			log.Fatalf("bad user spec %q", spec)
		}
		var id int64
		fmt.Sscan(parts[1], &id)
		org, team, _ := strings.Cut(parts[2], "/")
		s.AddUser(fakegithub.User{ID: id, Login: parts[0], Name: strings.ToUpper(parts[0][:1]) + parts[0][1:],
			Email: parts[0] + "@example.com", Orgs: []string{org}, Teams: []fakegithub.Team{{Org: org, Slug: team}}})
	}
	log.Printf("fake GitHub listening on %s (client id %s)", *listen, s.ClientID)
	log.Fatal(http.ListenAndServe(*listen, s.Handler()))
}

package bridge

import (
	"html/template"
	"net/http"
)

var pages = template.Must(template.New("layout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nexus sign-in</title>
<style>
body{font-family:system-ui,sans-serif;background:#f4f5f7;color:#1b1f23;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
main{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.15);padding:2rem 2.5rem;max-width:26rem;width:100%}
h1{font-size:1.25rem;margin:0 0 1rem}
p{line-height:1.45}
a.btn,button{display:block;width:100%;box-sizing:border-box;text-align:center;padding:.7rem 1rem;border-radius:6px;font-size:1rem;text-decoration:none;cursor:pointer;border:1px solid #d0d7de;background:#f6f8fa;color:#1b1f23;margin-top:.75rem}
a.primary{background:#24292f;color:#fff;border-color:#24292f}
.muted{color:#57606a;font-size:.9rem}
</style></head><body><main>{{template "body" .}}</main></body></html>`))

var loginPage = template.Must(template.Must(pages.Clone()).Parse(`{{define "body"}}
<h1>Sign in to Nexus</h1>
{{if .User}}<p>Signed in as <strong>{{.User}}</strong>.</p>
<a class="btn primary" href="{{.Return}}">Continue to Nexus</a>
<form method="post" action="/_bridge/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Sign out</button></form>
{{else if .Local}}<p>Local-account mode is active: the Nexus sign-in form is used instead of GitHub.</p>
<a class="btn primary" href="/">Continue to Nexus</a>
<form method="post" action="/_bridge/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Leave local-account mode</button></form>
{{else}}<a class="btn primary" href="/_bridge/auth?rd={{.Return}}">Sign in with GitHub</a>
<a class="btn" href="/_bridge/local">Sign in with a local account</a>
<p class="muted">Build tools and Docker clients keep using local Nexus users.</p>
{{end}}{{end}}`))

var errorPage = template.Must(template.Must(pages.Clone()).Parse(`{{define "body"}}
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<a class="btn primary" href="/_bridge/login">Back to sign-in</a>
{{end}}`))

type loginView struct {
	User   string
	Local  bool
	CSRF   string
	Return string
}

type errorView struct {
	Title   string
	Message string
}

// refusal is a user-facing reason for refusing a login. The detailed cause
// goes to the audit log only.
type refusal struct {
	reason  string // machine-readable, used in audit lines
	status  int
	title   string
	message string
}

var (
	refuseState    = refusal{"bad_state", http.StatusBadRequest, "Sign-in expired", "The sign-in attempt expired or was started in another browser. Please try again."}
	refuseDenied   = refusal{"github_denied", http.StatusForbidden, "Sign-in cancelled", "GitHub did not authorize the sign-in."}
	refuseGitHub   = refusal{"github_error", http.StatusBadGateway, "GitHub is not reachable", "Your GitHub identity could not be read. Please try again later."}
	refuseOrg      = refusal{"not_in_org", http.StatusForbidden, "Access denied", "Your GitHub account is not a member of an organization that may use this Nexus. If you recently joined, an organization owner may need to approve this application."}
	refuseNoRole   = refusal{"no_mapped_role", http.StatusForbidden, "Access denied", "None of your GitHub teams grants access to this Nexus. Ask an administrator to add you to the right team."}
	refuseDisabled = refusal{"nexus_user_inactive", http.StatusForbidden, "Account disabled", "Your Nexus account has been disabled by an administrator."}
	refuseNexus    = refusal{"nexus_error", http.StatusBadGateway, "Nexus is not reachable", "Your Nexus account could not be updated. Please try again later."}
)

func (b *Bridge) render(w http.ResponseWriter, status int, t *template.Template, v any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := t.Execute(w, v); err != nil {
		b.log.Error("rendering page", "err", err)
	}
}

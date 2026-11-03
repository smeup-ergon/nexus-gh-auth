# Specification: GitHub Login Proxy for Nexus Repository (Community)

**Status:** v3.1 (supersedes v2 "OAuth→LDAP bridge"; updated after verification against Nexus 3.97 CE)
**Scope:** A small reverse proxy, deployed as a Docker Compose service next to
Nexus Repository Community Edition, that lets people sign in to the Nexus web
UI with GitHub. Build tools keep using local Nexus users.

---

## 1. Purpose

Nexus Community has no GitHub/OIDC/SAML login. It does have the **Rut Auth**
(Remote User Token) realm, which trusts a username passed in an HTTP header.

The bridge:
1. signs users in with GitHub (OAuth 2.0 authorization-code flow);
2. creates or updates a matching **local Nexus user** through the Nexus REST
   API, with roles mapped from GitHub org/team membership;
3. proxies every request to Nexus, setting the trusted username header only
   for requests carrying a valid bridge session.

## 2. Goals / Non-goals

**Goals**
- G1. One container, one static binary, **no persistent state** (no volume).
- G2. GitHub (incl. GitHub Enterprise) login for the Nexus web UI.
- G3. Roles in Nexus derived from GitHub org/team membership via config.
- G4. Build tools and Docker clients keep working unchanged with local Nexus
  users, including the Docker registry on port 5000.
- G5. The bridge is the only network path to Nexus, so the trusted header
  cannot be forged.
- G6. A local-account escape route for the Nexus UI (GitHub outage, admin
  recovery).

**Non-goals**
- N1. LDAP, SQLite, or any directory/database of our own.
- N2. TLS: an external reverse proxy terminates TLS in front of the bridge.
- N3. Admin UI or CLI in the bridge; Nexus' own UI manages users.
- N4. Deleting or disabling Nexus users; background sync of GitHub membership.
- N5. Other identity providers in v1 (a thin `Provider` seam is kept, §4.2).
- N6. Nexus Pro features (SAML/OIDC, Docker subdomain connector).

## 3. Architecture

```
            TLS (external reverse proxy)
                 │                │
         :443 → bridge:8081   :5000 → bridge:5000
                 │                │
        ┌────────┴────────────────┴───────┐
        │ bridge                          │
        │  web proxy  (GitHub login,      │──► GitHub (OAuth + API)
        │             sets user header)   │
        │  docker proxy (pass-through,    │
        │               strips header)    │
        └────────┬────────────────┬───────┘
                 │                │        ──► Nexus REST API (user upsert)
            nexus:8081       nexus:5000
             (no published ports)
```

- **Nexus publishes no ports.** It is reachable only from the bridge over the
  Compose network.
- The external reverse proxy forwards the public hostname to `bridge:8081`,
  and the registry port to `bridge:5000`.

## 4. GitHub login

### 4.1 Flow
1. A request without a session hits rule 3 (§5.2) → `302` to
   `/_bridge/login?rd=<original path>`; the login page has
   "Sign in with GitHub" and "Sign in with a local account".
2. `/_bridge/auth` redirects to `${GITHUB_URL}/login/oauth/authorize` with
   `state` (CSRF, bound to a short-lived cookie that also holds `rd` and the
   PKCE verifier), PKCE S256, scopes `read:user user:email read:org`, and
   `redirect_uri = BASE_URL + /_bridge/callback`.
3. `/_bridge/callback` validates `state`, exchanges the code, fetches the
   identity (§4.3), applies access rules (§4.4), upserts the Nexus user
   (§6), sets the session cookie (§7) and redirects to `rd`
   (only same-origin relative paths are accepted; otherwise `/`).
4. The GitHub token is used only inside the callback request and then
   discarded; it is never stored or logged.

### 4.2 Provider seam
```go
type Provider interface {
    Name() string
    Endpoint() oauth2.Endpoint
    Scopes() []string
    Identify(ctx context.Context, tok *oauth2.Token) (Identity, error)
}

type Identity struct {
    Subject     string   // "github:<id>"
    Login       string   // GitHub login
    DisplayName string
    Email       string   // may be empty
    Groups      []string // already filtered by GITHUB_ORGS
}
```
GitHub is the only implementation.

### 4.3 GitHub identity
- `GET ${GITHUB_API_URL}/user` → `id`, `login`, `name`, `email`.
- **Email selection**, in order:
  1. `email` from `/user` (the user's public email), if non-empty;
  2. otherwise `GET /user/emails`: the first entry with `primary && verified`;
  3. otherwise the first entry with `verified`;
  4. otherwise empty (Nexus fallback in §6.2).
- Groups: `GET /user/orgs` and `GET /user/teams` (all pages). Only orgs in
  `GITHUB_ORGS` are kept. Names: `<org>` and `<org>~<team-slug>`, compared
  case-insensitively.

### 4.4 Access rules
A login is refused (clear page + audit line) when:
- the user belongs to none of the `GITHUB_ORGS`;
- the user's groups match no entry of `ROLE_MAP`;
- the Nexus user upsert fails.

## 5. Proxying

### 5.1 Common behavior (both listeners)
- The trusted header (`NEXUS_USER_HEADER`, default `X-Forwarded-User`) is
  **always removed** from incoming requests before any other processing.
- The original `Host` and the `X-Forwarded-Proto/Host/For` headers from the
  external reverse proxy are passed through unchanged.
- The bridge cookies (§7) are removed from requests forwarded to Nexus.
- Streaming bodies (large uploads/downloads) are proxied without buffering;
  no request/response size limits are imposed by the bridge.

### 5.2 Web listener (`:8081` → `nexus:8081`)
Paths under `/_bridge/` are served by the bridge and never forwarded.
For every other request, in order:

1. **Local-mode cookie present** (§5.3) → forward without the header.
2. **Valid session whose Nexus user is still active** (§6.4) → set
   `NEXUS_USER_HEADER: <nexus user id>` and forward.
   `DELETE /service/rapture/session` (Nexus "Sign out") additionally clears
   the bridge session. If the user is no longer active the session is
   cleared and the request continues with rule 3.
3. **`Authorization` header present** (basic auth, tokens, Docker token flow)
   → forward without the header; Nexus authenticates the local user.
4. **Browser navigation**: `GET`/`HEAD` with `Accept` containing `text/html`
   → `302` to `/_bridge/login?rd=<path+query>`.
5. **Anything else** → forward without the header (Nexus applies its
   anonymous-access settings).

### 5.3 Local-account escape route
- `/_bridge/local` sets a `_bridge_local` cookie (1 h, renewed while in
  use) and redirects to `/`, where the normal Nexus login form is used. It
  also clears any GitHub session.
- While it is present, no trusted header is ever set. `/_bridge/logout` and
  Nexus "Sign out" clear it.

### 5.4 Docker listener (`:5000` → `nexus:5000`)
- Pure pass-through: strips the trusted header and bridge cookies; never
  redirects, never sets the header.
- Docker clients authenticate with local Nexus users (Docker Bearer Token
  Realm in Nexus).

## 6. Nexus user management

### 6.1 Bridge service account
A dedicated local Nexus user (e.g. `github-bridge`) with a custom role holding
only: `nx-users-read`, `nx-users-create`, `nx-users-update`, `nx-roles-read`.
Credentials: `NEXUS_ADMIN_USER` + `NEXUS_ADMIN_PASSWORD(_FILE)`.

### 6.2 Upsert on every login
- User id: `NEXUS_USER_PREFIX + login` (default prefix `gh-`), so a GitHub
  login can never map onto an existing local account such as `admin`.
- Fields:
  - `firstName` = GitHub `name`, fallback `login`
  - `lastName` = `(GitHub)` (fixed marker)
  - `emailAddress` = selected email (§4.3), fallback
    `<id>+<login>@users.noreply.github.com`
  - `roles` = union of roles mapped from the user's groups (authoritative:
    replaces any manual role edits)
  - `source` = `default`
- **Create** (`POST /service/rest/v1/security/users`): `status=active`,
  `password` = 32 random bytes (base64url), never stored, logged or shown.
- **Update** (`PUT /service/rest/v1/security/users/{id}`): name, email, roles.
  `status` and `password` are never changed. If the existing user is not
  `active`, the login is refused and nothing is modified.
- The bridge never deletes users. GitHub renames create a new `gh-<newlogin>`
  user; the old one remains until an admin removes it.

### 6.3 Role mapping
- `ROLE_MAP`: comma-separated `group=role` pairs, e.g.
  `myorg~platform=nx-admin,myorg=nx-developer`. A group may appear several
  times; roles are unioned.
- At config load every group's org must be in `GITHUB_ORGS`. At startup the
  bridge checks every mapped role exists
  (`GET /service/rest/v1/security/roles`); a missing role is fatal. If Nexus
  is unreachable or rejects the credentials (e.g. on first deployment, before
  the service account exists), the check retries with backoff for up to
  `NEXUS_STARTUP_TIMEOUT` (default 5 min) before exiting. GitHub callbacks are
  refused until the check has passed.

### 6.4 User status enforcement
Verified on Nexus 3.97 CE: the Rut Auth realm authenticates a header user
**regardless of its status** (disabled and locked users keep their roles).
The bridge therefore enforces status itself:
- at login (§6.2);
- on every request with a session: the user's status is read through the
  REST API and cached for 30 s. A non-active or missing user loses the
  session (`session_revoked` audit line). Lookup errors fail closed for that
  request (no header) without ending the session.

## 7. Sessions

- Stateless signed (HMAC-SHA256, `SESSION_SECRET`) cookie `_bridge_session`
  containing user id, issue time and a random nonce. No server-side store.
- Lifetime 8 h absolute. Expiry → normal re-login (GitHub skips consent for
  an already-authorized app). Roles refresh at each login.
- Cookie flags: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` when
  `BASE_URL` is `https`.
- Logout: `/_bridge/logout` (POST, with CSRF token) and Nexus' own sign-out
  clear the cookie. Because sessions are stateless, a stolen cookie stays
  valid until expiry; rotating `SESSION_SECRET` invalidates all sessions.

## 8. Bridge endpoints

| Route | Purpose |
|---|---|
| `GET /_bridge/login` | Login page: GitHub / local account |
| `GET /_bridge/auth` | Start GitHub flow |
| `GET /_bridge/callback` | Complete GitHub flow |
| `GET /_bridge/local` | Enable local-account mode |
| `POST /_bridge/logout` | Clear session and local-mode cookies |
| `GET /_bridge/healthz` | Liveness |
| `GET /_bridge/readyz` | Readiness: startup role check passed and the bridge account can read users |

Bridge pages are server-rendered with `html/template` and send
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
Proxied Nexus responses are not modified.

## 9. Configuration

Environment variables; every secret also accepts `<VAR>_FILE` (Compose
`secrets:`). Missing/invalid required values abort startup with a message
naming the variable.

| Variable | Default | Description |
|---|---|---|
| `BASE_URL` | — (required) | Public URL of Nexus, e.g. `https://nexus.example.com` |
| `WEB_LISTEN` | `:8081` | Web proxy listener |
| `DOCKER_LISTEN` | `:5000` | Docker pass-through listener; empty disables |
| `NEXUS_URL` | `http://nexus:8081` | Upstream for web + REST API |
| `NEXUS_DOCKER_URL` | `http://nexus:5000` | Upstream for Docker |
| `NEXUS_USER_HEADER` | `X-Forwarded-User` | Must match the Rut Auth capability |
| `NEXUS_ADMIN_USER` | — (required) | Bridge service account |
| `NEXUS_ADMIN_PASSWORD(_FILE)` | — (required) | |
| `NEXUS_USER_PREFIX` | `gh-` | Prefix for bridge-managed user ids |
| `NEXUS_STARTUP_TIMEOUT` | `5m` | Wait for Nexus at startup |
| `GITHUB_CLIENT_ID` | — (required) | OAuth app client id |
| `GITHUB_CLIENT_SECRET(_FILE)` | — (required) | |
| `GITHUB_URL` | `https://github.com` | OAuth host (GHE) |
| `GITHUB_API_URL` | `https://api.github.com` | API host (GHE) |
| `GITHUB_ORGS` | — (required) | Comma list of allowed orgs |
| `ROLE_MAP` | — (required) | `group=role,…` |
| `SESSION_SECRET(_FILE)` | — (required) | ≥ 32 bytes |
| `SESSION_TTL` | `8h` | Session lifetime |
| `LOG_LEVEL` | `info` | |

## 10. Security requirements

- S1. The trusted header is stripped from every incoming request on every
  listener and set only from a valid session.
- S2. Nexus has no published ports; documentation states that exposing any
  Nexus port directly allows impersonating any user.
- S3. OAuth: `state` + PKCE S256; fixed redirect URI; same-origin-only `rd`.
- S4. No GitHub tokens, Nexus passwords or session secrets in logs.
- S5. Bridge-managed user ids are prefixed, so they cannot collide with local
  accounts.
- S6. Audit lines (JSON to stdout, `"type":"audit"`): login success/refusal
  (with reason), Nexus user created/updated (with role diff), local-mode
  enabled, logout.
- S7. Container runs as non-root on a distroless image.

## 11. Observability
Structured JSON logs to stdout (`log/slog`); `/_bridge/healthz`,
`/_bridge/readyz`. Proxied requests are not access-logged by default
(`LOG_LEVEL=debug` enables it).

## 12. Operational requirements
- O1. Image `gcr.io/distroless/static:nonroot`, `CGO_ENABLED=0`, < 20 MB.
- O2. No volume. Restarting signs nobody out (stateless cookies).
- O3. Graceful shutdown on SIGTERM: stop accepting, drain for up to 30 s
  (long-running uploads), exit.

## 13. Technology
| Choice | Rationale |
|---|---|
| Go (current stable) | Single static binary; `net/http/httputil.ReverseProxy` |
| `golang.org/x/oauth2` | Code flow, PKCE |
| stdlib only otherwise | `html/template`, `log/slog`, `crypto/hmac` |

## 14. Nexus setup (documented in README)
0. Accept the Community Edition EULA (otherwise no components are served).
1. Create the bridge role and service account (§6.1).
2. Create the roles referenced by `ROLE_MAP`.
3. Capabilities → create **Rut Auth** with header `X-Forwarded-User`.
4. Realms: Rut Auth Realm active; Local Authenticating Realm and
   Docker Bearer Token Realm active.
5. Docker hosted/group repository with an HTTP connector on port 5000.
6. Base URL capability = `BASE_URL`.
7. Compose: Nexus with no `ports:`; bridge publishes 8081/5000 to the
   external reverse proxy only.
8. GitHub OAuth app: callback `BASE_URL/_bridge/callback`; org admins approve
   the app if third-party access restrictions are enabled.

## 15. Testing
- **Unit:** routing rules (§5.2) as a table test, header stripping, email
  selection (§4.3), group filtering/naming, role mapping, cookie
  signing/expiry, `rd` validation, config validation.
- **Integration (CI):** bridge + fake GitHub + fake Nexus (records REST calls
  and echoes received headers). Covers login, upsert create/update, refusals,
  sign-out interception, local mode, Docker pass-through, header forgery
  attempts on both listeners.
- **End-to-end (`e2e/run.sh`):** real Nexus Community in Compose + bridge
  image + fake GitHub; bootstraps Nexus via REST and checks §16 including
  `docker login`/`push`/`pull` through port 5000.
- **Manual checklist (README):** real GitHub OAuth app.

## 16. Acceptance criteria
1. A member of an allowed org with a mapped team opens Nexus, is sent to
   GitHub, and lands in Nexus signed in as `gh-<login>` with the mapped roles.
2. Changing the user's GitHub team and signing in again updates the Nexus
   roles.
3. A user in no allowed org, or with no mapped group, is refused with a clear
   page and an audit line.
4. A request with a forged `X-Forwarded-User` and no session, on either
   listener, reaches Nexus without that header.
5. `docker login`/`push`/`pull` against port 5000 with a local user works.
6. Maven/npm with basic auth for a local user works through port 8081
   without GitHub redirects.
7. `/_bridge/local` lets `admin` sign in through the Nexus login form.
8. Nexus "Sign out" ends the bridge session; the next page load goes to
   GitHub login.
9. Disabling `gh-alice` in Nexus ends her existing session within 30 s and
   refuses new GitHub logins.
10. No GitHub tokens, passwords or secrets appear in logs.

## 17. Future work
- Other providers (generic OIDC) via the `Provider` seam.
- Server-side session revocation.

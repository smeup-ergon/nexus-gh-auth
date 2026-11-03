# nexus-gh-auth

Sign in to **Nexus Repository Community Edition** with **GitHub**.

A small reverse proxy that runs next to Nexus in Docker Compose. Browsers are
sent through GitHub's OAuth login. The proxy then creates or updates a local
Nexus user (`gh-<login>`) with roles mapped from GitHub org/team membership,
and forwards requests with a trusted header that Nexus' **Rut Auth** realm
accepts. Build tools and Docker clients keep using local Nexus users and are
never redirected.

It stores nothing: no database, no volume. See [SPEC.md](SPEC.md) for the
full design.

```
 browser ─┐                          ┌─► GitHub (OAuth + API)
          ├─► reverse proxy (TLS) ─► bridge :8081 ─► nexus:8081
 docker  ─┘                          bridge :5000 ─► nexus:5000
```

> [!WARNING]
> Nexus trusts the username header on **every** port it listens on. Nexus
> must not be reachable by anything except the bridge: publish **no** Nexus
> ports and route the Docker connector through the bridge's port 5000.
> Anyone who can reach Nexus directly can impersonate any user, including
> `admin`.

## How requests are routed

| Request to the bridge's web port | What happens |
|---|---|
| Local-account mode cookie (`/_bridge/local`) | Forwarded untouched; Nexus' own login form is used |
| Valid GitHub session | Forwarded with `X-Forwarded-User: gh-<login>` |
| Has an `Authorization` header (Maven, npm, curl, Docker token flow) | Forwarded untouched; Nexus authenticates the local user |
| Browser page load (`GET` with `Accept: text/html`) | Redirected to GitHub sign-in |
| Anything else | Forwarded untouched (Nexus' anonymous access rules apply) |

The trusted header is always removed from incoming requests first, on both
ports. The Docker port is a plain pass-through.

## Setup

### 1. GitHub OAuth app

In your organization: **Settings → Developer settings → OAuth Apps → New**.

- Homepage URL: `https://nexus.example.com`
- Authorization callback URL: `https://nexus.example.com/_bridge/callback`

Keep the client ID and generate a client secret. If the organization
restricts third-party application access, an org owner must approve the app,
otherwise members' org/team data is hidden and they are refused.

### 2. Nexus

All steps are in the Nexus UI as `admin` (or the REST API; see
[`e2e/run.sh`](e2e/run.sh) for scripted equivalents).

1. **Accept the EULA** (Community Edition serves no components until it is
   accepted).
2. **Capabilities → Create → Rut Auth**, HTTP header: `X-Forwarded-User`.
3. **Security → Realms**: active realms must include *Rut Auth Realm*,
   *Local Authenticating Realm* and *Docker Bearer Token Realm*.
4. **Security → Roles → Create role** `github-bridge` with privileges
   `nx-users-read`, `nx-users-create`, `nx-users-update`, `nx-roles-read`.
5. **Security → Users → Create** local user `github-bridge` with that role
   and a strong password.
6. Create the roles you will reference in `ROLE_MAP` (e.g. `nx-developer`).
7. Docker hosted/group repository: **HTTP connector on port 5000**.
8. **Capabilities → Base URL** = your public URL.

Build tools and CI use ordinary local users (e.g. `ci`), as before.

### 3. Compose

Start from [`compose.example.yml`](compose.example.yml):

```sh
mkdir -p secrets
printf '%s' 'the-github-bridge-password' > secrets/nexus_admin_password
printf '%s' 'the-oauth-client-secret'    > secrets/github_client_secret
openssl rand -base64 48 | tr -d '\n'     > secrets/session_secret
chmod 600 secrets/*
docker compose -f compose.example.yml up -d
```

Point your TLS-terminating reverse proxy at `bridge:8081` (web) and
`bridge:5000` (Docker registry). Forward `X-Forwarded-Proto`/`-Host`/`-For`;
the bridge passes them to Nexus unchanged, together with the original `Host`.

## Configuration

Every `*_PASSWORD`/`*_SECRET` variable also accepts a `_FILE` variant for
Compose secrets. Invalid configuration stops startup with a message naming the
variable.

| Variable | Default | |
|---|---|---|
| `BASE_URL` | required | Public URL, e.g. `https://nexus.example.com` (no path) |
| `GITHUB_CLIENT_ID` | required | OAuth app client ID |
| `GITHUB_CLIENT_SECRET(_FILE)` | required | OAuth app client secret |
| `GITHUB_ORGS` | required | Comma list of orgs allowed to sign in |
| `ROLE_MAP` | required | `group=role,…` where group is `<org>` or `<org>~<team-slug>` |
| `NEXUS_ADMIN_USER` | required | The bridge's Nexus account (`github-bridge`) |
| `NEXUS_ADMIN_PASSWORD(_FILE)` | required | Its password |
| `SESSION_SECRET(_FILE)` | required | ≥ 32 bytes; rotating it signs everyone out |
| `NEXUS_URL` | `http://nexus:8081` | Web/API upstream |
| `NEXUS_DOCKER_URL` | `http://nexus:5000` | Docker connector upstream |
| `WEB_LISTEN` | `:8081` | |
| `DOCKER_LISTEN` | `:5000` | Set to empty to disable the Docker listener |
| `NEXUS_USER_HEADER` | `X-Forwarded-User` | Must match the Rut Auth capability |
| `NEXUS_USER_PREFIX` | `gh-` | Prefix for GitHub-managed Nexus users |
| `NEXUS_STARTUP_TIMEOUT` | `5m` | How long to wait for Nexus and the role check |
| `GITHUB_URL` / `GITHUB_API_URL` | github.com / api.github.com | GitHub Enterprise hosts |
| `SESSION_TTL` | `8h` | |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Example: `ROLE_MAP=myorg~platform=nx-admin,myorg=nx-developer` gives every
member of `myorg` the `nx-developer` role, and members of the `platform` team
`nx-admin` as well.

## Behavior worth knowing

- **Roles are authoritative.** Each sign-in replaces the user's roles with the
  mapped set; manual edits to a `gh-*` user's roles are undone at their next
  sign-in. A user whose teams map to no role is refused.
- **Disable, don't delete.** The bridge never changes a user's status. Disable
  `gh-alice` in Nexus to block her: her session stops working within 30
  seconds and new sign-ins are refused. (Nexus' Rut Auth realm itself ignores
  the user status, so the bridge checks it.) A deleted user is simply
  recreated at their next GitHub sign-in.
- **Removing someone from the GitHub org** takes effect at their next sign-in,
  at the latest after `SESSION_TTL`. Disable them in Nexus for immediate
  effect.
- **Email:** the public GitHub email, else the primary verified email, else
  any verified email, else `<id>+<login>@users.noreply.github.com`.
- **GitHub renames** create a new `gh-<newlogin>` user; remove the old one
  manually.
- **Local accounts in the browser:** use "Sign in with a local account" on the
  sign-in page (`/_bridge/local`), for `admin` or during a GitHub outage. It
  lasts one hour of inactivity or until you sign out of Nexus.
- **Sessions are stateless signed cookies.** A stolen cookie stays valid until
  it expires; rotate `SESSION_SECRET` to sign everyone out.
- **Audit:** JSON lines with `"type":"audit"` on stdout (`login`,
  `login_refused` with a reason, `nexus_user_created`,
  `nexus_user_roles_changed`, `session_revoked`, `local_mode_enabled`,
  `logout`).

## Endpoints

`/_bridge/login`, `/_bridge/auth`, `/_bridge/callback`, `/_bridge/local`,
`/_bridge/logout` (POST), `/_bridge/healthz` (liveness),
`/_bridge/readyz` (Nexus reachable and role mapping verified). The image's
Docker `HEALTHCHECK` uses `healthz`.

## Development

```sh
go test -race ./...   # unit + integration tests with fake GitHub and fake Nexus
e2e/run.sh            # real Nexus CE + bridge + fake GitHub in Compose (~2 min)
```

`e2e/run.sh` bootstraps a fresh Nexus through its REST API and checks every
acceptance criterion in SPEC.md §16, including `docker login`/`push`/`pull`
through port 5000. Docker must allow `127.0.0.1:25000` as an insecure registry
(Docker Desktop allows `127.0.0.0/8` by default).

## Manual check with real GitHub

1. Register the OAuth app (above) and deploy with your real org and roles.
2. Open Nexus in a private window → GitHub → back in Nexus as `gh-<you>`
   with the expected roles (**Security → Users**).
3. Sign out of Nexus → next page load goes to GitHub sign-in.
4. `/_bridge/local` → sign in as `admin` with the Nexus form.
5. `docker login nexus.example.com:5000 -u ci`, push and pull an image.
6. `mvn deploy` (or `curl -u ci:… -T file …/repository/…`) with a local user.
7. Disable your `gh-` user in Nexus → within 30 s you are signed out and a new
   sign-in is refused.

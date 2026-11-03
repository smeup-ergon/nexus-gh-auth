#!/usr/bin/env bash
# End-to-end acceptance test: real Nexus Community + bridge + fake GitHub.
# Requires docker (with compose), curl and python3. Takes ~2 minutes.
#   e2e/run.sh          run and tear down
#   KEEP=1 e2e/run.sh   leave the stack running afterwards
set -euo pipefail
cd "$(dirname "$0")"

B=http://127.0.0.1:28081        # bridge (web)
R=127.0.0.1:25000               # bridge (docker registry)
N=http://127.0.0.1:18081        # Nexus, loopback only, for bootstrapping
GH_PUBLIC=127.0.0.1:19000       # fake GitHub as seen by the "browser"
ADMIN_PW=e2e-admin-password
TMP=$(mktemp -d)
FAILED=0

compose() { docker compose -f compose.yml "$@"; }
cleanup() {
  if [[ "${KEEP:-}" != 1 ]]; then compose down -v --remove-orphans >/dev/null 2>&1 || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
check() { # name expected actual
  if [[ "$3" == "$2" ]]; then pass "$1"; else fail "$1 (want $2, got $3)"; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

nx() { # method path [json] -- as Nexus admin; fails loudly
  local out status
  out=$(curl -s -w '\n%{http_code}' -u "admin:$ADMIN_PW" -H 'Content-Type: application/json' -X "$1" "$N/service/rest$2" ${3:+-d "$3"})
  status=${out##*$'\n'}
  if [[ $status != 2* ]]; then
    echo "Nexus $1 $2 failed with $status: ${out%$'\n'*}" >&2
    return 1
  fi
  printf '%s' "${out%$'\n'*}"
}

echo "== starting stack"
compose up -d --build --quiet-pull >/dev/null

echo "== waiting for Nexus"
for _ in $(seq 1 90); do
  [[ $(code "$N/service/rest/v1/status") == 200 ]] && break
  sleep 3
done
for _ in $(seq 1 30); do
  compose exec -T nexus test -f /nexus-data/admin.password && break
  sleep 2
done

echo "== bootstrapping Nexus"
INITIAL=$(compose exec -T nexus cat /nexus-data/admin.password)
check "admin password changed" 204 "$(code -u "admin:$INITIAL" -H 'Content-Type: text/plain' -X PUT \
  "$N/service/rest/v1/security/users/admin/change-password" --data "$ADMIN_PW")"
# Nexus CE serves no components until the EULA is accepted (test fixture only;
# in a real deployment an administrator accepts it once).
nx POST /v1/system/eula "$(nx GET /v1/system/eula | python3 -c 'import json,sys; d=json.load(sys.stdin); d["accepted"]=True; print(json.dumps(d))')" >/dev/null
nx PUT /v1/security/anonymous '{"enabled":false,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' >/dev/null
nx POST /v1/capabilities '{"type":"rutauth","notes":"","enabled":true,"properties":{"httpHeader":"X-Forwarded-User"}}' >/dev/null
nx PUT /v1/security/realms/active '["rutauth-realm","NexusAuthenticatingRealm","DockerToken"]'
nx POST /v1/security/roles '{"id":"github-bridge","name":"github-bridge","description":"GitHub login proxy","privileges":["nx-users-read","nx-users-create","nx-users-update","nx-roles-read"],"roles":[]}' >/dev/null
nx POST /v1/security/users '{"userId":"github-bridge","firstName":"GitHub","lastName":"Bridge","emailAddress":"bridge@example.com","password":"bridge-password","status":"active","roles":["github-bridge"]}' >/dev/null
nx POST /v1/repositories/docker/hosted '{"name":"docker-hosted","online":true,"storage":{"blobStoreName":"default","strictContentTypeValidation":true,"writePolicy":"allow"},"docker":{"v1Enabled":false,"forceBasicAuth":true,"httpPort":5000}}'
nx POST /v1/security/roles '{"id":"nx-developer","name":"nx-developer","description":"Developers","privileges":["nx-repository-view-*-*-browse","nx-repository-view-*-*-read","nx-repository-view-docker-docker-hosted-*"],"roles":[]}' >/dev/null
nx POST /v1/security/users '{"userId":"ci","firstName":"CI","lastName":"Bot","emailAddress":"ci@example.com","password":"ci-password","status":"active","roles":["nx-developer"]}' >/dev/null

echo "== waiting for the bridge"
for _ in $(seq 1 60); do
  [[ $(code "$B/_bridge/readyz") == 200 ]] && break
  sleep 1
done
check "bridge ready" 200 "$(code "$B/_bridge/readyz")"

# login <github-login> <cookie-jar>: drives the browser flow, prints the
# callback status.
login() {
  local jar=$2 loc
  rm -f "$jar"
  curl -s -o /dev/null -b "$jar" -c "$jar" -H 'Accept: text/html' "$B/" >/dev/null
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$jar" -c "$jar" "$B/_bridge/auth?rd=%2F")
  loc=${loc/fakegithub:9000/$GH_PUBLIC}
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$loc&login=$1")
  curl -s -o "$TMP/callback.html" -w '%{http_code}' -b "$jar" -c "$jar" "$loc"
}
ui_user() { # Nexus' view of the UI user for a cookie jar
  curl -s -b "$1" -H 'Content-Type: application/json' -H 'X-Nexus-UI: true' -X POST "$B/service/extdirect" \
    -d '{"action":"rapture_Security","method":"getUser","data":null,"type":"rpc","tid":1}' |
    python3 -c 'import json,sys; d=json.load(sys.stdin)["result"]["data"]; print(d["id"] if d and d.get("authenticated") else "-")'
}
user_field() { # user field
  nx GET "/v1/security/users?userId=$1" | python3 -c "import json,sys; u=[u for u in json.load(sys.stdin) if u['userId']=='$1']; print(u[0]['$2'] if u else '-')"
}

echo "== AC1 GitHub login creates the Nexus user with mapped roles"
check "alice callback redirects" 302 "$(login alice "$TMP/alice")"
check "gh-alice roles" "['nx-admin']" "$(user_field gh-alice roles)"
check "gh-alice email" "alice@example.com" "$(user_field gh-alice emailAddress)"
check "gh-alice last name marker" "(GitHub)" "$(user_field gh-alice lastName)"
check "Nexus sees gh-alice in the UI" gh-alice "$(ui_user "$TMP/alice")"
check "gh-alice has admin API access" 200 "$(code -b "$TMP/alice" "$B/service/rest/v1/security/users")"
check "bob callback redirects" 302 "$(login bob "$TMP/bob")"
check "gh-bob lacks admin API access" 403 "$(code -b "$TMP/bob" "$B/service/rest/v1/security/users")"

echo "== AC4 forged header is stripped"
check "forged admin header, no session" 401 "$(code -H 'X-Forwarded-User: admin' "$B/service/rest/v1/security/users")"
check "forged admin header on docker port" 401 "$(code -H 'X-Forwarded-User: admin' "http://$R/v2/")"
check "bob cannot become admin by header" 403 "$(code -b "$TMP/bob" -H 'X-Forwarded-User: admin' "$B/service/rest/v1/security/users")"

echo "== AC6 build tools use local users without GitHub"
check "ci basic auth, REST" 200 "$(code -u ci:ci-password "$B/service/rest/v1/repositories")"
check "ci basic auth, browser Accept: no redirect" 200 "$(code -u ci:ci-password -H 'Accept: text/html' "$B/service/rest/repository/browse/docker-hosted/")"

echo "== AC5 docker registry on port 5000"
if docker image inspect busybox:latest >/dev/null 2>&1 || docker pull -q busybox:latest >/dev/null 2>&1; then
  if ! grep -q "$R" <(docker info 2>/dev/null); then
    echo "  (note: $R must be an insecure registry in the Docker daemon; on Docker Desktop 127.0.0.0/8 is allowed by default)"
  fi
  docker tag busybox:latest "$R/e2e/busybox:1"
  check "docker login as ci" 0 "$(echo ci-password | docker login "$R" -u ci --password-stdin >/dev/null 2>&1; echo $?)"
  check "docker push" 0 "$(docker push -q "$R/e2e/busybox:1" >/dev/null 2>&1; echo $?)"
  docker rmi -f "$R/e2e/busybox:1" >/dev/null
  check "docker pull" 0 "$(docker pull -q "$R/e2e/busybox:1" >/dev/null 2>&1; echo $?)"
  docker rmi -f "$R/e2e/busybox:1" >/dev/null 2>&1 || true
  docker logout "$R" >/dev/null 2>&1 || true
else
  fail "could not pull busybox for the docker test"
fi

echo "== AC2 roles are recomputed at every login"
nx PUT "/v1/security/users/gh-bob" "$(nx GET '/v1/security/users?userId=gh-bob' | python3 -c 'import json,sys; u=json.load(sys.stdin)[0]; u["roles"]=["nx-admin"]; print(json.dumps(u))')"
check "manual role edit present" "['nx-admin']" "$(user_field gh-bob roles)"
login bob "$TMP/bob" >/dev/null
check "bridge is authoritative for roles" "['nx-developer']" "$(user_field gh-bob roles)"

echo "== AC8 Nexus 'Sign out' ends the bridge session"
check "sign-out" 204 "$(code -b "$TMP/alice" -c "$TMP/alice" -H 'X-Nexus-UI: true' -X DELETE "$B/service/rapture/session")"
check "next page goes to login" 302 "$(code -b "$TMP/alice" -H 'Accept: text/html' "$B/")"
check "no longer authenticated" - "$(ui_user "$TMP/alice")"

echo "== AC7 local-account escape route"
rm -f "$TMP/local"
curl -s -o /dev/null -b "$TMP/local" -c "$TMP/local" "$B/_bridge/local"
check "Nexus UI served in local mode" 200 "$(code -b "$TMP/local" -H 'Accept: text/html' "$B/")"
check "admin form login" 204 "$(code -b "$TMP/local" -c "$TMP/local" -H 'X-Nexus-UI: true' \
  --data-urlencode "username=$(printf admin | base64)" --data-urlencode "password=$(printf %s "$ADMIN_PW" | base64)" "$B/service/rapture/session")"
CSRF=$(awk '$6=="NX-ANTI-CSRF-TOKEN"{print $7}' "$TMP/local")
if [[ -z "$CSRF" ]]; then CSRF=e2e; printf '127.0.0.1\tFALSE\t/\tFALSE\t0\tNX-ANTI-CSRF-TOKEN\t%s\n' "$CSRF" >>"$TMP/local"; fi
check "Nexus sees admin" admin "$(curl -s -b "$TMP/local" -H "NX-ANTI-CSRF-TOKEN: $CSRF" -H 'Content-Type: application/json' -H 'X-Nexus-UI: true' -X POST "$B/service/extdirect" \
  -d '{"action":"rapture_Security","method":"getUser","data":null,"type":"rpc","tid":1}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["data"]["id"])')"

echo "== AC9 disabling a user in Nexus blocks them"
login bob "$TMP/bob" >/dev/null
nx PUT "/v1/security/users/gh-bob" "$(nx GET '/v1/security/users?userId=gh-bob' | python3 -c 'import json,sys; u=json.load(sys.stdin)[0]; u["status"]="disabled"; print(json.dumps(u))')"
echo "  (waiting 31s for the bridge's status cache)"
sleep 31
check "existing session revoked" 302 "$(code -b "$TMP/bob" -H 'Accept: text/html' "$B/")"
check "fresh login refused" 403 "$(login bob "$TMP/bob2")"
check "status still disabled" disabled "$(user_field gh-bob status)"

echo "== AC10 no secrets in bridge logs"
LOGS=$(compose logs bridge 2>&1)
for s in bridge-password test-secret e2e-session-secret tok-; do
  if grep -q -- "$s" <<<"$LOGS"; then fail "logs contain $s"; else pass "logs free of $s"; fi
done

echo
if [[ $FAILED == 0 ]]; then echo "ALL PASSED"; else echo "SOME CHECKS FAILED"; exit 1; fi

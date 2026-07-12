# pickle-proxy-agent

Reverse-proxy control agent for Pickle. A small Go daemon that runs inside the
`reverse-proxy` LXC (100, 172.30.1.10) and turns the desired routing state pushed by
pickle-api into live nginx vhosts and TLS certificates. Routing truth lives in
PostgreSQL; nginx config is a derived artifact.

## Contract

The daemon is the **server** side of Link 2 in `docs/api/internal.md` (pickle-api →
proxy-agent). All three endpoints require the shared bearer token
(`PICKLE_PROXY_AGENT_TOKEN`) and a source IP on the allowlist (default pickle-api,
172.30.1.20); everything fails closed. Reachable only on the internal bridge vmbr1.

- `POST /apply` — full desired state for one FQDN
  `{fqdn, desiredState: PRESENT|ABSENT, generation, targetIp, targetPort, certRef}`.
  Renders/removes the vhost, validates with `nginx -t`, reloads. A monotonic
  per-FQDN `generation` is persisted; a request with `generation ≤ applied` is a
  `409` no-op, so a late retry can never resurrect an old vhost onto a reused IP.
  `200 {applied, generation}` / `409` (stale) / `422 {applied:false, error}`.
- `POST /sync-all` — authoritative full snapshot `{snapshotGeneration, routes[]}`.
  Renders the whole set, `nginx -t`, atomic swap, **prunes** agent-managed vhost
  files absent from the manifest, reloads.
- `GET /status` — health, last apply/sync, per-FQDN applied generations, and
  custom-domain certificate state (issuance/renewal failures surface here).

The agent owns exactly `/etc/nginx/pickle.d/*.conf` (one file per FQDN) and never
touches anything else in the nginx tree (the `opus.pusan.ac.kr` config is inviolable).
All mutations run through a single serialized queue — one render → `nginx -t` → swap
→ reload cycle at a time; any failure restores the previous file state, so a failed
apply leaves the live config exactly as it was.

## Templates & certificates

Two vhost shapes (`docs/plan/06-domains-tls.md`):

- **platform subdomains** (`certRef == origin-wildcard`): HTTPS on the internal
  `127.0.0.1:8443` tier using the Cloudflare Origin CA wildcard.
- **custom domains** (any other `certRef`): per-domain Let's Encrypt cert. Rendering
  is two-phase — a challenge-only `:80` vhost until certbot (webroot HTTP-01)
  issues the cert, then the full `:80`-redirect + `:8443`-HTTPS vhost. Issuance
  failures are reported on `/status` and do not fail the apply. Renewals run via
  certbot's systemd timer; `scripts/deploy.sh` installs a renewal deploy-hook
  (`/etc/letsencrypt/renewal-hooks/deploy/pickle-nginx-reload.sh`) that reloads
  nginx after each successful renewal so the renewed cert goes live immediately.

Both proxy_pass to `http://<vm-ip>:<port>` with a shared, websocket-upgrade-aware
proxy snippet (`Connection $connection_upgrade`, resolved via the map in
`scripts/nginx/pickle-base.conf`).

## Layout

```
cmd/proxy-agent/      entrypoint (env config -> wire -> serve)
internal/config/      env-sourced configuration (fails closed on empty token)
internal/model/       wire types shared with pickle-api (frozen contract shapes)
internal/render/      vhost template rendering + input validation
internal/nginx/       `nginx -t` / `nginx -s reload` runner (interface + exec impl)
internal/certbot/     webroot HTTP-01 issuance (interface + certbot exec impl)
internal/state/       per-FQDN generation + cert state, persisted JSON
internal/manager/     serialized apply/sync-all: render->test->swap->reload->rollback
internal/server/      HTTP server, fail-closed auth, per-key rate limiting
internal/fake/        test doubles for nginx/certbot (not compiled into the daemon)
scripts/deploy.sh     build + install binary/unit/base-nginx on LXC 100 (authored,
                      not auto-run); scripts/proxy-agent.service systemd unit
```

## Build & verify

```bash
scripts/setup-hooks.sh   # once: install git hooks
scripts/verify.sh        # shellcheck + go vet + go build + go test
```

Go 1.26 (see `go.mod`); standard library only, no third-party dependencies.

Design: `docs/plan/06-domains-tls.md`, `01-architecture.md`, and the internal API
contract `docs/api/internal.md` (not the public `openapi.yaml`).

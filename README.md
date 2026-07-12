# pickle-proxy-agent

Reverse-proxy control agent for Pickle. A small Go daemon that runs inside the
`reverse-proxy` LXC (100) and turns the desired routing state pushed by pickle-api
into live nginx vhosts and TLS certificates:

- `POST /apply` — receives the full desired state for one FQDN
  `{fqdn, target_ip, target_port, cert_ref}`, renders an nginx vhost from a
  template, validates with `nginx -t`, reloads nginx, and reports the applied
  state back. Desired-state (not delta) → re-applying is idempotent; a `sync-all`
  admin action rebuilds every vhost from the DB.
- certbot (webroot, HTTP-01) for user custom domains; renewal-failure reporting.
- Authenticated with a shared token, reachable only on the internal bridge (vmbr1).

Routing truth lives in PostgreSQL; nginx config is a derived artifact. This keeps a
future migration to request-time dynamic routing (e.g. OpenResty + shared dict)
possible without changing the API/DB interface.

Design: `docs/plan/06-domains-tls.md` and `01-architecture.md` in `pickle-docs`;
the internal API contract lives in `docs/api/internal.md` (not the public
`openapi.yaml`). Promoted from `infra/proxy-agent/` to its own repo in M4 for
symmetry with `sshgw` (both are standalone Go daemons with independent build/verify).

Implementation lands in milestone M4. Until then this repo holds the deployment
skeleton and configuration research.

```bash
scripts/setup-hooks.sh   # once: install git hooks
scripts/verify.sh        # shellcheck (+ go vet/build once code exists)
```

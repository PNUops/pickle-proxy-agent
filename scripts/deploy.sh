#!/usr/bin/env bash
# Deploy the proxy-agent to the reverse-proxy LXC (100, 172.30.1.10).
#
# AUTHORED, NOT AUTO-RUN. Cross-compiles a static Linux binary and installs it plus
# the systemd unit and base nginx wiring on the target. Run it deliberately from a
# build host that can reach the target over SSH; it never runs itself.
#
# It is idempotent: re-running upgrades the binary and restarts the service. It does
# NOT touch the opus.pusan.ac.kr config and only creates the agent-owned paths.
#
# Prerequisites on the target (provisioned separately, see infra runbooks): nginx with
# `include` of /etc/nginx/pickle.d/*.conf and the map from pickle-base.conf, certbot,
# the Origin CA wildcard cert under /etc/nginx/certs/origin, and worker_shutdown_timeout.
set -euo pipefail

TARGET="${TARGET:-root@172.30.1.10}"
SSH_OPTS="${SSH_OPTS:-}"
REMOTE_BIN="/usr/local/bin/pickle-proxy-agent"
ENV_DIR="/etc/pickle-proxy-agent"

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"

echo "==> building static linux/amd64 binary"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o "$out/pickle-proxy-agent" ./cmd/proxy-agent

echo "==> ensuring target directories"
# $ENV_DIR etc. are local constants; client-side expansion is intended.
# shellcheck disable=SC2086,SC2029
ssh $SSH_OPTS "$TARGET" "install -d -m 0755 /etc/nginx/pickle.d \
  && install -d -m 0755 /var/www/certbot \
  && install -d -m 0750 /var/lib/pickle-proxy-agent \
  && install -d -m 0700 $ENV_DIR"

echo "==> copying binary, systemd unit, base nginx include"
# shellcheck disable=SC2086
scp $SSH_OPTS "$out/pickle-proxy-agent" "$TARGET:$REMOTE_BIN.new"
# shellcheck disable=SC2086
scp $SSH_OPTS scripts/proxy-agent.service "$TARGET:/etc/systemd/system/pickle-proxy-agent.service"
# shellcheck disable=SC2086
scp $SSH_OPTS scripts/nginx/pickle-base.conf "$TARGET:/etc/nginx/conf.d/pickle-base.conf"

echo "==> installing env file if absent (token must be filled in by the operator)"
# shellcheck disable=SC2086,SC2029
ssh $SSH_OPTS "$TARGET" "test -f $ENV_DIR/agent.env || printf '%s\n' \
  '# Filled in by the operator. Source: docs/credentials.md' \
  'PICKLE_PROXY_AGENT_TOKEN=CHANGME' \
  'PICKLE_PROXY_AGENT_LISTEN=172.30.1.10:9443' \
  > $ENV_DIR/agent.env && chmod 0600 $ENV_DIR/agent.env"

echo "==> atomically swapping binary and restarting"
# shellcheck disable=SC2086,SC2029
ssh $SSH_OPTS "$TARGET" "chmod 0755 $REMOTE_BIN.new && mv $REMOTE_BIN.new $REMOTE_BIN \
  && systemctl daemon-reload \
  && nginx -t \
  && systemctl reload nginx \
  && systemctl enable --now pickle-proxy-agent \
  && systemctl restart pickle-proxy-agent \
  && systemctl --no-pager --lines=5 status pickle-proxy-agent"

echo "==> done. Verify: curl -sf -H 'Authorization: Bearer <token>' http://172.30.1.10:9443/status"

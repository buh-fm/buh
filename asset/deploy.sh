#!/usr/bin/env bash
#
# Deploy one buh node on the local host (run as root on the target).
#
# buh has no central control plane, so this installs a single self-contained node: the binaries,
# a hardened systemd service, the firewalld opening for BUH_NODE_PORT, and a
# rendered /etc/buh/config.toml. It then has the node generate its own CA and prints the
# fingerprint to share with peers. There is deliberately NO step-ca, NO central database
# bootstrap, and NO secret material to provision.
#
# Configuration values are taken from the environment (see DEFAULTS below) so this script stays a
# readable, dependency-free renderer; the committed manifest.yml documents the intended values per
# environment. Override any of them inline, e.g.:
#
#   sudo BLOB_ENABLED=false PKI_SANS='["relay.example.com"]' ./deploy.sh
#
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "deploy.sh must run as root on the target node" >&2
  exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Configuration (override via environment) --------------------------------------------------
: "${BIN_DIR:=/usr/local/bin}"
: "${CONFIG_DIR:=/etc/buh}"
: "${STATE_DIR:=/var/lib/buh}"

: "${BIND:=127.0.0.1:8080}"
: "${DB_PATH:=${STATE_DIR}/relay.db}"
: "${LOG_FORMAT:=json}"

: "${DEFAULT_TTL_SECONDS:=604800}"
: "${MAX_TTL_SECONDS:=2592000}"
: "${MAX_PAYLOAD_BYTES:=262144}"
: "${MAX_PULL_LIMIT:=100}"
: "${MAX_WAIT_SECONDS:=30}"
: "${SWEEP_INTERVAL_SECONDS:=3600}"

: "${BLOB_ENABLED:=true}"
: "${BLOB_BACKEND:=fs}"
: "${BLOB_FS_ROOT:=${STATE_DIR}/blobs}"
: "${MAX_BLOB_BYTES:=67108864}"
: "${S3_ENDPOINT:=}"
: "${S3_REGION:=us-east-1}"
: "${S3_ACCESS_KEY:=}"
: "${S3_SECRET_KEY:=}"

: "${PKI_ENABLED:=true}"
: "${PKI_DIR:=${STATE_DIR}/pki}"
: "${NODE_BIND:=0.0.0.0:31415}"
: "${PKI_SANS:=[\"localhost\"]}"
: "${LEAF_TTL_HOURS:=48}"
: "${ROTATE_EVERY_HOURS:=24}"

: "${ADMIN_ENABLED:=true}"
: "${ADMIN_BIND:=127.0.0.1:8081}"   # loopback only — no auth

echo "==> Installing service account"
install -m 0644 "${here}/systemd/buh.sysusers.conf" /usr/lib/sysusers.d/buh.conf
systemd-sysusers

echo "==> Creating state tree ${STATE_DIR}"
install -d -m 0700 -o buh -g buh "${STATE_DIR}"

echo "==> Rendering ${CONFIG_DIR}/config.toml"
install -d -m 0755 "${CONFIG_DIR}"
render() {
  local out="$1"
  sed \
    -e "s|{{BIND}}|${BIND}|g" \
    -e "s|{{DB_PATH}}|${DB_PATH}|g" \
    -e "s|{{LOG_FORMAT}}|${LOG_FORMAT}|g" \
    -e "s|{{DEFAULT_TTL_SECONDS}}|${DEFAULT_TTL_SECONDS}|g" \
    -e "s|{{MAX_TTL_SECONDS}}|${MAX_TTL_SECONDS}|g" \
    -e "s|{{MAX_PAYLOAD_BYTES}}|${MAX_PAYLOAD_BYTES}|g" \
    -e "s|{{MAX_PULL_LIMIT}}|${MAX_PULL_LIMIT}|g" \
    -e "s|{{MAX_WAIT_SECONDS}}|${MAX_WAIT_SECONDS}|g" \
    -e "s|{{SWEEP_INTERVAL_SECONDS}}|${SWEEP_INTERVAL_SECONDS}|g" \
    -e "s|{{BLOB_ENABLED}}|${BLOB_ENABLED}|g" \
    -e "s|{{BLOB_BACKEND}}|${BLOB_BACKEND}|g" \
    -e "s|{{BLOB_FS_ROOT}}|${BLOB_FS_ROOT}|g" \
    -e "s|{{MAX_BLOB_BYTES}}|${MAX_BLOB_BYTES}|g" \
    -e "s|{{S3_ENDPOINT}}|${S3_ENDPOINT}|g" \
    -e "s|{{S3_REGION}}|${S3_REGION}|g" \
    -e "s|{{S3_ACCESS_KEY}}|${S3_ACCESS_KEY}|g" \
    -e "s|{{S3_SECRET_KEY}}|${S3_SECRET_KEY}|g" \
    -e "s|{{PKI_ENABLED}}|${PKI_ENABLED}|g" \
    -e "s|{{PKI_DIR}}|${PKI_DIR}|g" \
    -e "s|{{NODE_BIND}}|${NODE_BIND}|g" \
    -e "s|{{PKI_SANS}}|${PKI_SANS}|g" \
    -e "s|{{LEAF_TTL_HOURS}}|${LEAF_TTL_HOURS}|g" \
    -e "s|{{ROTATE_EVERY_HOURS}}|${ROTATE_EVERY_HOURS}|g" \
    -e "s|{{ADMIN_ENABLED}}|${ADMIN_ENABLED}|g" \
    -e "s|{{ADMIN_BIND}}|${ADMIN_BIND}|g" \
    "${here}/config/config.toml.tmpl" > "${out}"
}
render "${CONFIG_DIR}/config.toml"
chmod 0640 "${CONFIG_DIR}/config.toml"
chgrp buh "${CONFIG_DIR}/config.toml"

echo "==> Installing systemd unit"
install -m 0644 "${here}/systemd/buh-node.service" /etc/systemd/system/buh-node.service
systemctl daemon-reload

if [[ "${PKI_ENABLED}" == "true" ]]; then
  echo "==> Opening BUH_NODE_PORT in firewalld"
  install -m 0644 "${here}/firewalld/buh-node.xml" /etc/firewalld/services/buh-node.xml
  firewall-cmd --reload
  firewall-cmd --permanent --add-service=buh-node
  firewall-cmd --reload

  echo "==> Initialising the node CA"
  runuser -u buh -- "${BIN_DIR}/buh-cli" --db-path "${DB_PATH}" --pki-dir "${PKI_DIR}" ca init
fi

echo "==> Enabling the node service"
systemctl enable --now buh-node.service

echo
echo "buh node deployed."
if [[ "${PKI_ENABLED}" == "true" ]]; then
  echo "Share this CA fingerprint so peers/clients can pin you:"
  runuser -u buh -- "${BIN_DIR}/buh-cli" --pki-dir "${PKI_DIR}" ca show
  echo "Trust a peer with: buh-cli --db-path ${DB_PATH} peer trust <their-ca-fp>"
fi

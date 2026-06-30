#!/usr/bin/env bash
#
# One-time setup for the gitea_ci deploy-user on every host that
# .gitea/workflows/deploy.yml targets (currently just the buh node host):
#   - create the gitea_ci system user (if missing)
#   - install the runner's pubkey into ~gitea_ci/.ssh/authorized_keys
#   - add gitea_ci to the systemd-journal group (so the workflow can capture
#     `journalctl -u buh-node.service` without a sudoers entry)
#   - install the host-appropriate /etc/sudoers.d/buh_node_gitea_ci drop-in,
#     verified with `visudo -cf` so a typo can't lock the host out
#
# Run this from a workstation with ssh + sudo access to the host, once per host,
# before the deploy workflow can succeed. Idempotent — safe to re-run. It skips
# past an unreachable host so one offline node doesn't block the rest.
#
# buh ships NO application config or secrets here: the workflow renders
# /etc/buh/config.toml from infra truth on every deploy, the datastore is an
# embedded Turso file, and the node mints its own CA on first start (so there is
# also no host mTLS cert to provision — unlike the postgres-mTLS apps).

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_path="$(cd "${script_dir}/.." && pwd)"

# Testnet node hosts (mirrors the deploy matrix in .gitea/workflows/deploy.yml).
# The same host-agnostic sudoers drop-in is installed on each — it pins commands
# and paths, not hostnames. Run this from a machine that can reach the host
# (different nodes may live on different meshes).
node_hosts=(
    slartibartfast.kosherinata.internal   # testnet.buh.fm
    oci.hanzalova.internal                # t2.buh.fm
)
node_sudoers="${repo_path}/asset/sudoers.d/node-host.conf"

pubkey="${HOME}/.ssh/id_gitea_ci.pub"
if [[ ! -f "${pubkey}" ]]; then
    echo "fatal: ${pubkey} not found" >&2
    echo "  generate with: ssh-keygen -t ed25519 -f ${pubkey%.pub} -C gitea_ci" >&2
    echo "  then add the matching private key as the RSYNC_SSH_KEY Gitea secret" >&2
    exit 1
fi

# Create gitea_ci, install its authorized_keys, and grant journal read access.
provision_user() {
    local host="$1"
    echo "==> ${host}: provisioning gitea_ci"
    if ! ssh "${host}" '
        set -eu
        if id -u gitea_ci >/dev/null 2>&1; then
            echo "  gitea_ci user already present"
        else
            sudo useradd --system --create-home \
                --home-dir /var/lib/gitea_ci --shell /bin/bash gitea_ci
            echo "  gitea_ci user created"
        fi
        # `install -o` does its own fresh user lookup, avoiding the brief NSS
        # cache lag that makes `sudo -u gitea_ci` fail right after useradd.
        sudo install -d -o gitea_ci -g gitea_ci -m 0700 /var/lib/gitea_ci/.ssh
        sudo usermod -aG systemd-journal gitea_ci
    '; then
        echo "  failed to provision gitea_ci — skipping ${host}"
        return 1
    fi

    if rsync --archive --compress \
        --chown gitea_ci:gitea_ci --chmod 0600 \
        --rsync-path 'sudo rsync' \
        "${pubkey}" \
        "${host}:/var/lib/gitea_ci/.ssh/authorized_keys"; then
        echo "  authorized_keys synced"
    else
        echo "  failed to sync authorized_keys to ${host}"
        return 1
    fi
}

# Install the sudoers drop-in and verify it parses, so a typo can't lock out.
install_sudoers() {
    local host="$1" template="$2" name="$3"
    local dest="/etc/sudoers.d/${name}"
    echo "==> ${host}: installing ${dest}"
    if ! rsync --archive --compress \
        --chown root:root --chmod 0440 \
        --rsync-path 'sudo rsync' \
        "${template}" \
        "${host}:${dest}"; then
        echo "  failed to sync ${template##*/}"
        return 1
    fi
    if ssh "${host}" "sudo visudo -cf ${dest}" >/dev/null; then
        echo "  installed and verified"
    else
        echo "  WARNING: visudo rejected the installed file — review on ${host}"
        return 1
    fi
}

setup_host() {
    local host="$1" sudoers="$2" name="$3"
    provision_user "${host}" && install_sudoers "${host}" "${sudoers}" "${name}" \
        || { echo "  ${host}: setup incomplete"; return 1; }
}

rc=0
for h in "${node_hosts[@]}"; do
    setup_host "${h}" "${node_sudoers}" buh_node_gitea_ci || rc=1
done

echo "==> done."
echo "    Gitea repo secrets to set (Settings -> Actions -> Secrets):"
echo "        RSYNC_SSH_KEY   private key matching ${pubkey}"
echo "    (buh has no app secrets — the node mints its own CA and uses an embedded datastore.)"

exit "${rc}"

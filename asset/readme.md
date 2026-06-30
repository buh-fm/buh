# buh deployment assets

Ops files for running a buh node on a real host. **Not CI-tested** — kept minimal and honest.
A buh node runs on an untrusted, third-party machine, so these assets assume **no central control
plane, no shared database, and no central PKI**:

- `manifest.yml` — per-node deployment descriptor (relay + optional blob role, PQ-mTLS settings)
  for the `prod` and `dev` environments. It is a descriptor, not a fleet topology.
- `config/config.toml.tmpl` — the rendered `buh-api`/`buh-cli` config. No secrets: the datastore
  is an embedded Turso file and the node generates its own CA.
- `systemd/buh-node.service` — hardened unit (`generic.md` §8). **No `*.path` cert-reload unit**:
  the node is its own CA and rotates its TLS leaf *in process* — that is the decentralised-CA
  deviation. Nothing external watches or reloads a certificate.
- `systemd/buh-node-sweep.{service,timer}` — periodic TTL sweep of expired envelopes.
- `systemd/buh.sysusers.conf` — the unprivileged `buh` service account.
- `firewalld/buh-node.xml` — opens **`BUH_NODE_PORT` (8443)**, the single PQ-mTLS ingress port.
  The plain loopback health port is never exposed.
- `deploy.sh` — installs the above on the local host, renders the config, has the node generate
  its CA, and prints the CA fingerprint to share with peers.

## Quick start (on the target node, as root)

```sh
# build + install the binaries first
cargo build --release --features s3   # drop --features s3 for an fs-only blob node
install -m0755 target/release/buh-api target/release/buh-cli /usr/local/bin/

# then deploy (override any value via the environment — see deploy.sh DEFAULTS)
sudo PKI_SANS='["node1.example.com"]' ./asset/deploy.sh
```

## Trust between nodes

Each node pins peers by CA fingerprint — there is no shared root.

```sh
buh-cli ca show                       # print my fingerprint to hand to a peer
buh-cli peer trust <their-ca-fp>      # accept that peer over PQ-mTLS
buh-cli peer distrust <their-ca-fp>   # refuse them on the next handshake
buh-cli peer list                     # who I currently trust
```

# buh testnet — peering guide

How to stand up a buh node, join it to the testnet, and establish a peering with
another node. buh is an **anti-hub**: there is no central server, no shared root
CA, and no registry. A "testnet" is just a set of nodes that have chosen to trust
each other's certificate authorities.

## Trust model in one paragraph

Every node is **its own CA**. On first start it generates a CA (`ca.cert.der` +
`ca.key.pem` under its pki dir) and rotates a short-lived TLS leaf from it in
process. Its identity is the **CA fingerprint** — the lowercase hex SHA-256 of the
CA certificate DER (`:` separators are accepted on input but not required). Two
nodes talk over **mutual** PQ-mTLS (X25519MLKEM768): a handshake succeeds only
when **each side has pinned the other's CA fingerprint**. Trust is therefore
explicit, pairwise, and symmetric — there is nothing to "join", only peers to
exchange fingerprints with. Removing trust (`peer distrust`) takes effect on the
peer's **next handshake**, with no restart.

## The staked port: 31415

buh standardises on **`BUH_NODE_PORT = 31415/tcp`** — the single PQ-mTLS ingress
port a node exposes (chosen to avoid the crowded `8443`/`9443`/`6443` space; it is
unassigned in IANA and below the Linux ephemeral range, so it is safe to forward).
Everything else stays local:

| Port | Bind | Purpose | Exposed? |
|------|------|---------|----------|
| `31415` | `0.0.0.0:31415` | PQ-mTLS relay/blob API (peers + clients) | **yes — forward from the edge** |
| `8081`  | `127.0.0.1:8081` | operator admin API (peer-trust mgmt) | no — loopback only, no auth |
| `8080`  | `127.0.0.1:8080` | plain health/debug (only when pki is off) | no |

Forward `31415/tcp` from your edge (OPNsense/router) to the node host. Peers reach
you at `your-edge-hostname:31415`.

## Testnet roster

Record each node's reachable address and CA fingerprint here as it joins.

| Node | Edge address | CA fingerprint | Role |
|------|--------------|----------------|------|
| `testnet.buh.fm` | `testnet.buh.fm:31415` | `3c8f125861f3c39f849a469cb32ef599000c71896ea1ccc8a5baaad7419ef808` | relay + blob (fs) |
| `t2.buh.fm` | `t2.buh.fm:31415` | `cc78d40009b2577eec2431aea316384814749317a73a130a818fdf1a32ae9ab5` | relay + blob (fs) |

> The two seed nodes above mutually trust each other — cross-site PQ-mTLS peering
> is verified live (`peer ping` succeeds both directions over the public FQDNs).

> Re-keying a node (`buh-cli ca rotate --force`) changes its fingerprint — update
> this table and every peer must re-pin.

## Join the testnet

### 1. Stand up your node

Either model from `asset/readme.md`:

- **CI** — push to a buh checkout whose `.gitea/workflows/deploy.yml` targets your
  host (the dogfood node uses this).
- **Manual** — `sudo PKI_SANS='["your-node.example"]' ./asset/deploy.sh` on the host.

#### Set the leaf SANs to *your* node's FQDN

The node stamps its TLS leaf with the subject alternative names (SANs) you give it
in `[pki].sans` — set these to **the public FQDN other operators use to reach you**
(the host part of your `host:31415` edge address), e.g. `["your-node.example"]`. Use
an IP-literal SAN (`["203.0.113.10"]`) if you have no DNS. Where you set it:

- **CI:** the `NODE_SANS` env in your `deploy.yml` (a TOML array string).
- **Manual:** `PKI_SANS` to `deploy.sh`, or `[pki].sans` in `/etc/buh/config.toml`.

Why bother, given buh peers pin by **CA fingerprint** and ignore the hostname? Two
reasons: a standards-compliant TLS client (a browser, `curl`, future tooling) that
*does* validate the hostname will reject a leaf whose SAN doesn't match the name it
dialed; and it keeps your certificate honest about who it claims to be. Changing
`sans` re-issues the leaf on the next deploy/rotation — the CA fingerprint peers
pinned is unaffected, so no one needs to re-pin.

Confirm it is healthy (on the host, via the loopback admin API):

```sh
curl -fsS http://127.0.0.1:8081/admin/info
# {"ca_fingerprint":"…","trusted_peers":N}
```

### 2. Learn your CA fingerprint

```sh
buh-cli ca show          # prints this node's CA fingerprint
```

This is the value you hand to peers. Exchange fingerprints **out of band** (signal,
in person, an existing secure channel) — buh deliberately has no fingerprint
directory to lie to you.

### 3. Trust your peer, and have them trust you

Peering is symmetric — **both** sides run a `trust`:

```sh
# on YOUR node — pin the peer's CA
buh-cli peer trust 3c8f125861f3c39f849a469cb32ef599000c71896ea1ccc8a5baaad7419ef808 \
        --note "testnet.buh.fm"

# on the PEER node — they pin YOUR CA
buh-cli peer trust <your-ca-fingerprint> --note "my-node"
```

`peer` commands talk to the running node's loopback admin API, so trust changes are
live — they apply on the next handshake without a restart. (With the daemon
stopped, the CLI falls back to opening the datastore directly.) Review with:

```sh
buh-cli peer list
```

### 4. Verify the peering

```sh
buh-cli peer ping <peer-edge-host>:31415
```

`peer ping` performs a real mutual PQ-mTLS handshake and reports the peer's
advertised CA fingerprint + health. It **succeeds only when both directions of
trust are in place** — if it fails, the usual cause is that one side hasn't pinned
the other yet (or the fingerprints don't match what was exchanged).

## Operations

- **Revoke a peer:** `buh-cli peer distrust <ca-fp>` — refused on their next
  handshake, no restart.
- **Re-key this node:** `buh-cli ca rotate --force` — destructive; generates a new
  CA (old one backed up to `*.bak`), so **every** peer must re-pin the new
  fingerprint and the roster must be updated.
- **Keep the admin API loopback:** it has no auth; the daemon refuses a
  non-loopback `[admin].bind`, and it must never be opened in firewalld.
- **Changing the port:** `BUH_NODE_PORT` is repo-side only — edit
  `NODE_PORT`/`node_bind` and `asset/firewalld/buh-node.xml`; the firewalld rules
  are keyed on the service name, and the node runs unconfined (no SELinux port
  label needed), so no host re-provisioning is required. Re-point edge forwarding
  to the new port.

## End-to-end message check

A node's reason to exist is the client messaging path: a sender seals a message,
pushes it to the recipient's queue, the recipient pulls and opens it. `buh-e2e`
(`crates/buh-e2e`) drives that path against a *live* node and verifies the round-trip.

> **Single-node, not federated (yet).** A message pushed to a queue on node A is
> retrievable only from node A — buh does **not** forward envelopes between nodes.
> Peering / `peer trust` exists for mutual PQ-mTLS auth (today its only consumer is
> `peer ping`); generic node-to-node forwarding is deferred to the mailbox-redundancy
> work (`doc/design.md` §10). So a conversation runs entirely against **one** node,
> and the harness targets a single node accordingly.

The `:31415` port is mutual-TLS with no anonymous path, so the harness client must
present a leaf whose CA the node trusts:

```sh
# 1. mint a throwaway client CA; print its fingerprint
fp=$(cargo run -q -p buh-e2e -- mint --out /tmp/e2e-ca)

# 2. trust it on the target node (on the node host, or via its loopback admin API)
buh-cli peer trust "$fp" --note buh-e2e

# 3. run the sealed round-trip against the live node, then clean up
cargo run -q -p buh-e2e -- send \
    --client-ca /tmp/e2e-ca \
    --node testnet.buh.fm:31415 \
    --node-ca-fp <node-ca-fingerprint>
buh-cli peer distrust "$fp"
```

`send` generates two identities, runs PQXDH + double-ratchet to seal a message,
`POST`s the first flight to a random queue over PQ-mTLS, pulls it back, opens it,
asserts the plaintext matches, then acks and confirms the queue drains. A green run
exercises the whole stack on real infra: X25519MLKEM768 mutual TLS + the
post-quantum ratchet + the relay's enqueue/pull/ack semantics.

## Reference

- CA fingerprint = lowercase hex SHA-256 of the CA cert DER (`buh-cli ca show`).
- State: `/var/lib/buh` (`relay.db`, `pki/`, `blobs/`); config: `/etc/buh/config.toml`.
- CLI talks to a running node via `--admin-url` (default `http://127.0.0.1:8081`,
  env `BUH_ADMIN_URL`).

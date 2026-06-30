-- Peer-CA trust registry (Phase 6 / doc/design.md §5.1, the decentralised per-node-CA deviation).
--
-- The set of peer-node CA fingerprints this node will accept on a PQ-mTLS handshake. Trust is
-- per-CA: a fingerprint is pinned (lowercase hex SHA-256 of the peer CA cert DER), never a shared
-- root. There is deliberately no peer identity, address, or social graph here — only the opaque
-- fingerprints an operator has chosen to trust, and an optional human note.

CREATE TABLE IF NOT EXISTS peer_trust (
    ca_fingerprint  TEXT    PRIMARY KEY,   -- lowercase hex SHA-256 of the peer CA cert DER
    note            TEXT,                  -- optional operator note (who/what this CA is)
    trusted_at      INTEGER NOT NULL       -- epoch milliseconds
);

-- buh relay/mailbox schema (Turso / SQLite-compatible).
--
-- The relay stores ONLY queue_id -> envelope_refs, TTL/expiry, and delivery receipts. There
-- are deliberately no users / queues / ownership tables: the relay never learns identities
-- and cannot enumerate a social graph (doc/design.md §3.1). queue_id is an opaque 32-byte
-- capability; envelope payloads are opaque sealed ciphertext.
--
-- Timestamps are epoch milliseconds (INTEGER).

CREATE TABLE IF NOT EXISTS envelopes (
    id            INTEGER PRIMARY KEY,
    queue_id      BLOB    NOT NULL,
    envelope_id   TEXT    NOT NULL,
    payload       BLOB    NOT NULL,
    received_at   INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    delivered_at  INTEGER
);

-- Primary access path: live (undelivered) envelopes for a queue, oldest first.
CREATE INDEX IF NOT EXISTS idx_envelopes_queue_live
    ON envelopes (queue_id, delivered_at, received_at);

-- TTL sweep path.
CREATE INDEX IF NOT EXISTS idx_envelopes_expiry
    ON envelopes (expires_at);

-- One row per (queue, envelope) — idempotent push / safe ack.
CREATE UNIQUE INDEX IF NOT EXISTS idx_envelopes_uniq
    ON envelopes (queue_id, envelope_id);

CREATE TABLE IF NOT EXISTS delivery_receipts (
    id           INTEGER PRIMARY KEY,
    queue_id     BLOB    NOT NULL,
    envelope_id  TEXT    NOT NULL,
    pulled_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_queue
    ON delivery_receipts (queue_id, pulled_at);

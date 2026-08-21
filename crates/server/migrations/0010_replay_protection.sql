-- Replay protection for signed requests.
--
-- # The gap this migration closes
--
-- Until now a signed request stayed replayable for the whole clock-tolerance window — sixty
-- seconds. The README listed it as a known limitation, judging the impact bounded: a duplicate
-- envelope is rejected by the MLS client, the message key no longer being available.
--
-- That argument held for envelopes, and only for them. A replayed KeyPackage upload fills the
-- stock with duplicates; a replayed claim drains someone else's stock. Nothing catastrophic,
-- but "it has no effect" was only true on one path.
--
-- # Why an explicit nonce, and not the signature itself
--
-- Remembering the signature would have avoided touching the signed format, and it is tempting.
-- **It is wrong**: Ed25519 is deterministic. Two identical requests — same method, same path,
-- same body, same second — produce exactly the same signature, and one is a replay while the
-- other is perfectly legitimate. Claiming two KeyPackages back to back is enough to hit it.
--
-- The nonce therefore enters the signed message, and the format changes: see
-- `auth::signing_payload`.
--
-- # Why the key carries the device
--
-- A nonce is drawn at random by each client, without coordination. Two devices can draw the
-- same one without either replaying anything; uniqueness only makes sense per device. Same
-- structure as `posting_nonces` in 0007, for the same reason.
--
-- # Why `UNLOGGED`
--
-- The contents of this table **have no value beyond sixty seconds**: past the tolerance
-- window, a request is refused on its timestamp anyway. Losing the table on restart is
-- therefore harmless, and writing its WAL would be paying for a durability nobody needs — on a
-- table that takes one write per authenticated request.
CREATE UNLOGGED TABLE request_nonces (
    device_id TEXT NOT NULL,
    nonce     BYTEA NOT NULL,
    seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (device_id, nonce),
    CONSTRAINT request_nonce_len CHECK (octet_length(nonce) = 16)
);

-- No foreign key to `devices`, deliberately: it would impose a referential check on the
-- latency path of every request, when the caller has just been authenticated — so the device
-- necessarily exists. Cleanup happens by age, not by cascade.
--
-- This index serves the purge, and nothing else. Reads go through the primary key.
CREATE INDEX request_nonces_seen_at_idx ON request_nonces (seen_at);

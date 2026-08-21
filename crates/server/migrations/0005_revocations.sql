-- Revocation certificates: making device removal verifiable without trusting the server.
--
-- Migration 0003 took away the server's power to ADD a device to an account. It left it the
-- power to REMOVE one: `revoked_at` was a plain column, authenticated by nothing.
--
-- That power is not harmless. Removing a device means an MLS commit, and that commit is
-- issued by ANOTHER account — if Alice loses her phone, Bob, who is in the group, evicts it.
-- Bob has only the server's word for it, and a lying server gets devices of its choosing
-- excluded: censorship, targeted and lasting.
--
-- Every revocation now carries an account signature (domain `wac-revoke-v1`, see the `attest`
-- crate). The server can still WITHHOLD a revocation; it can no longer INVENT one.

-- Demo database: earlier revocations have no certificate and nobody can forge one for them
-- retroactively. We cancel them rather than let them violate the constraint below.
UPDATE devices SET revoked_at = NULL WHERE revoked_at IS NOT NULL;

ALTER TABLE devices
    ADD COLUMN revocation BYTEA,

    ADD CONSTRAINT revocation_is_ed25519
        CHECK (revocation IS NULL OR octet_length(revocation) = 64),

    -- The point of this migration. A revocation without a certificate is exactly the power we
    -- deny the server: the database makes it impossible instead of relying on application-code
    -- discipline. The equivalence in both directions also rules out the reverse case, a
    -- certificate stored without taking effect.
    ADD CONSTRAINT revocation_matches_revoked_at
        CHECK ((revoked_at IS NULL) = (revocation IS NULL));

-- Revoked devices are now SERVED to clients along with their certificate: otherwise a client
-- could not tell a revocation from an omission, and omission is precisely what the server can
-- still do. Since the existing index covers active devices only, we add one for reading a
-- whole account.
CREATE INDEX devices_handle_all_idx ON devices (handle);

-- Pseudonymous accounts and attested device enrolment.
--
-- What this migration changes in the threat model: until now the server could not lie, having
-- nothing to say — a device was its own contact. As soon as an account groups several
-- devices, the server becomes the source of that list, and a list it composes freely lets it
-- slip in a device it controls.
--
-- Hence `attestation`: an account signature the server cannot produce. It can still OMIT a
-- device from the list (censorship, detectable by a user whose messages never arrive), never
-- ADD one (eavesdropping, undetectable). That asymmetry is what justifies the whole
-- migration.

CREATE TABLE accounts (
    -- Pseudonym, in the clear. The server sees it, and so does every member of a group — the
    -- MLS credential already carries the device name in the clear in the public tree.
    -- Attach no phone number, no e-mail, nothing real: see the README's limitations.
    handle       TEXT PRIMARY KEY,
    -- Account Ed25519 public key (AIK). Derived client-side from the recovery phrase; the
    -- server only ever sees the public half and can sign nothing.
    identity_key BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT handle_not_empty CHECK (handle <> '' AND octet_length(handle) <= 64),
    CONSTRAINT identity_key_is_ed25519 CHECK (octet_length(identity_key) = 32)
);

-- Pre-existing devices have no account and cannot be granted one: nobody holds the key that
-- would attest them. Demo database, disposable data. A real deployment would need a
-- transition period with a nullable `handle`.
DELETE FROM devices;

ALTER TABLE devices
    ADD COLUMN handle      TEXT NOT NULL REFERENCES accounts(handle) ON DELETE CASCADE,
    -- MLS signature public key. Attested AT THE SAME TIME as `auth_key`: attesting them
    -- separately would allow recombining a legitimate device's attestation with a hostile
    -- device's MLS key.
    ADD COLUMN mls_key     BYTEA NOT NULL,
    ADD COLUMN attestation BYTEA NOT NULL,
    -- Soft revocation. Deleting the row would break `group_members` foreign keys and erase the
    -- device from conversations it really took part in; the goal is to stop it being added
    -- elsewhere, not to rewrite the past.
    ADD COLUMN revoked_at  TIMESTAMPTZ,

    ADD CONSTRAINT attestation_is_ed25519 CHECK (octet_length(attestation) = 64);

-- The index covers active devices only: that is the only list we serve.
CREATE INDEX devices_handle_idx ON devices (handle) WHERE revoked_at IS NULL;

-- Drop box for QR-code pairing.
--
-- The server only sees a blob sealed under an X25519 secret whose two public halves travelled
-- through the QR code — out of its reach. It is merely an asynchronous relay between two
-- devices that cannot talk to each other directly.
CREATE TABLE pairings (
    id         BYTEA PRIMARY KEY,
    payload    BYTEA NOT NULL,
    -- The blob expires fast: it contains enough to take over the account. A short window
    -- limits the value of a stolen database.
    expires_at TIMESTAMPTZ NOT NULL,
    -- Single read. A second successful read would signal that a third party grabbed the blob.
    claimed_at TIMESTAMPTZ,

    CONSTRAINT pairing_id_len CHECK (octet_length(id) = 16)
);

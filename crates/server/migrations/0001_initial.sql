-- Blind mailbox schema.
--
-- Guiding principle: the server must not be able to decrypt anything, and every column added
-- "for convenience" (last-message preview, unread counter, typing status) is a permanent
-- metadata leak. Any new column must be justified by routing or cleanup, never by the UI.

-- A device, not a user. In MLS the unit of group membership is the device: a user with three
-- phones is three members.
CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    -- Ed25519 public key used to authenticate HTTP requests.
    --
    -- Deliberately distinct from the MLS signature key. Reusing one key across two protocols
    -- is a classic mistake: messages signed in one can become valid signatures in the other
    -- if the formats overlap.
    auth_key    BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT auth_key_is_ed25519 CHECK (octet_length(auth_key) = 32)
);

-- Stock of KeyPackages published ahead of time, so we can be added to a group while offline.
--
-- Each KeyPackage is SINGLE USE: its init key must serve only once. OpenMLS does not enforce
-- this (checked by the test `key_package_reuse_must_be_prevented_by_the_server`), so the
-- server must guarantee atomic removal on first consumption.
CREATE TABLE key_packages (
    id         BIGSERIAL PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    payload    BYTEA NOT NULL
);

CREATE INDEX key_packages_device_idx ON key_packages (device_id, id);

-- An MLS group. The server knows neither its keys nor its content; it only holds the counter
-- that guarantees a total order over messages.
--
-- That order is not cosmetic: MLS requires every member to apply commits in the same order.
-- Two members whose epochs diverge can no longer read each other.
CREATE TABLE groups (
    id        BYTEA PRIMARY KEY,
    next_seq  BIGINT NOT NULL DEFAULT 0
);

-- Who may read which mailbox.
--
-- ACCEPTED METADATA LEAK: this table tells the server who talks to whom. It is the same
-- trade-off WhatsApp makes. Avoiding it takes anonymous group identifiers and zero-knowledge
-- credentials (Signal's Private Group System) — out of scope.
--
-- Without this table any authenticated device could read any group by guessing its
-- identifier. A random identifier is not an access control.
CREATE TABLE group_members (
    group_id   BYTEA NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    PRIMARY KEY (group_id, device_id)
);

-- The mailbox itself. `payload` is an opaque MLS blob.
--
-- The test `the_server_only_sees_ciphertext` reads this table directly in SQL and checks that
-- no plaintext shows through.
CREATE TABLE envelopes (
    group_id    BYTEA NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    -- Assigned by the server, strictly increasing per group. Doubles as the fetch cursor and
    -- imposes the total order.
    seq         BIGINT NOT NULL,
    payload     BYTEA NOT NULL,
    -- Only for purging delivered messages. This is temporal metadata: it reveals when each
    -- person speaks. No other feature may lean on it.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, seq)
);

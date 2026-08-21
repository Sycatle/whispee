-- An account is identified by a key, not by a name.
--
-- # What was wrong
--
-- The handle was the primary key of `accounts`, the foreign key of every table that referenced
-- an account, the prefix of every device id, and — outside this database — the subject of the
-- MLS credential and of every attestation the account had ever signed. It was not a label on an
-- identity. It *was* the identity.
--
-- So a rename was never an UPDATE. It was a new credential in every conversation, and MLS does
-- what it is built to do with a new credential: it reports an identity change. The
-- fingerprint-changed banner would rise on every correspondent's screen for a cosmetic edit.
--
-- # What replaces it
--
-- `accounts.id`: the fingerprint of the account's genesis identity key, 128 bits, 32 lowercase
-- hexadecimal characters. Derived, never assigned — see `crates/attest/src/lib.rs::account_id`
-- for the argument, of which the short form is that a server which mints ids can forge and
-- reassign them, and a server which merely lists them cannot, because the id is checkable
-- against key material inside the credential being verified.
--
-- `handles`: an alias table. A handle points at an account, is unique among live handles, and
-- can be released.
--
-- # Why handles are never re-issued
--
-- A released handle keeps its row, with `released_at` set and `account` cleared. It is a
-- tombstone and it is load-bearing.
--
-- If `@bob` could be released and re-registered, every stale reference to it — a bookmark, a
-- screenshot, a mention in a message written last year — would name somebody else. That is an
-- impersonation nobody had to mount: it arrives on its own, on a schedule the attacker chooses
-- by waiting. Quarantine was considered and refused; it protects only the inattentive, and the
-- row costs nothing.
--
-- The account is cleared rather than kept. The server holds the rename graph anyway, in its
-- write-ahead log if nowhere else, but a column that spells it out is a column that gets
-- SELECTed — and "who used to be called this" is not a question this table needs to be able to
-- answer to do its job, which is to stop the name coming back.
--
-- # The data is dropped, deliberately
--
-- Every account in this database is keyed by a name and attested under `wac-attest-v1`. There is
-- no derivation that turns one into an id — the id is a hash of a key the server has, but the
-- attestations are signed over the old field and cannot be re-signed without the account's
-- secret, which lives on the client. A migration would produce accounts nobody can verify.
--
-- The development database is disposable, which is what makes the clean cut affordable, and it
-- is precisely why this change is worth making now rather than later: every account created
-- after today is an account that would have to be thrown away later instead.

DELETE FROM devices;
DELETE FROM accounts;

-- ---------------------------------------------------------------------------
-- accounts, rekeyed
-- ---------------------------------------------------------------------------

-- Dropping the primary key CASCADEs into every foreign key that pointed at a handle, which is
-- exactly what is wanted: those columns are about to be repointed at the id, and a constraint
-- naming a column that no longer exists cannot be repaired, only replaced.
ALTER TABLE accounts DROP CONSTRAINT accounts_pkey CASCADE;
ALTER TABLE accounts DROP COLUMN handle;

ALTER TABLE accounts
    ADD COLUMN id TEXT NOT NULL,
    -- The key the id was derived from, kept beside the key that is current.
    --
    -- `identity_key` moves on rotation; this one never does. Without it the server cannot check
    -- that an id it is handed matches the account claiming it — it would be storing a hash whose
    -- preimage it had thrown away — and a client asking "is this really the account behind that
    -- id" would have nothing to be answered with but the server's word, which is the thing this
    -- whole design exists to stop relying on.
    ADD COLUMN genesis_key BYTEA NOT NULL,
    ADD CONSTRAINT genesis_key_is_ed25519 CHECK (octet_length(genesis_key) = 32),
    -- Lowercase hex, fixed width. One representation, so two rows cannot disagree about the same
    -- account — the reasoning `handle_is_canonical` applied to names, applied to what replaced
    -- them.
    ADD CONSTRAINT account_id_is_canonical CHECK (id ~ '^[0-9a-f]{32}$'),
    ADD PRIMARY KEY (id);

-- ---------------------------------------------------------------------------
-- handles, the alias
-- ---------------------------------------------------------------------------

CREATE TABLE handles (
    handle      TEXT PRIMARY KEY,
    -- NULL means a tombstone: the name was used, was given up, and is never coming back.
    account     TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    claimed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at TIMESTAMPTZ,

    -- The same rule `0013_handle_format.sql` argued for, moved to where handles now live. Its
    -- reasoning is unchanged and worth re-reading: the authority is `crate::handle::validate`,
    -- this is the belt that makes a future insert path fail loudly rather than quietly widen the
    -- format.
    CONSTRAINT handle_is_canonical CHECK (handle ~ '^[a-z0-9_]{3,32}$'),
    -- A live handle has an account; a released one has neither an account nor a way back.
    CONSTRAINT tombstones_are_unowned CHECK ((released_at IS NULL) = (account IS NOT NULL))
);

-- One live name per account.
--
-- Not a plain UNIQUE on `account`: tombstones share the NULL that a plain constraint would let
-- accumulate, and an account is allowed to have released any number of names. What may not
-- happen is an account answering to two names at once, which is what a reader comparing two
-- screens would experience as two people.
CREATE UNIQUE INDEX handles_live_account_idx ON handles (account) WHERE released_at IS NULL;

-- ---------------------------------------------------------------------------
-- Everything that referenced an account by name
-- ---------------------------------------------------------------------------

DROP INDEX IF EXISTS devices_handle_idx;
DROP INDEX IF EXISTS devices_handle_all_idx;
ALTER TABLE devices RENAME COLUMN handle TO account;
ALTER TABLE devices
    ADD CONSTRAINT devices_account_fkey FOREIGN KEY (account) REFERENCES accounts(id) ON DELETE CASCADE;
CREATE INDEX devices_account_idx ON devices (account) WHERE revoked_at IS NULL;
CREATE INDEX devices_account_all_idx ON devices (account);

DROP INDEX IF EXISTS vault_entries_read_idx;
ALTER TABLE vault_entries RENAME COLUMN handle TO account;
ALTER TABLE vault_entries
    ADD CONSTRAINT vault_entries_account_fkey FOREIGN KEY (account) REFERENCES accounts(id) ON DELETE CASCADE;
CREATE INDEX vault_entries_read_idx ON vault_entries (account, group_id, seq);

DROP INDEX IF EXISTS log_entries_handle_idx;
ALTER TABLE log_entries RENAME COLUMN handle TO account;
ALTER TABLE log_entries
    ADD CONSTRAINT log_entries_account_fkey FOREIGN KEY (account) REFERENCES accounts(id) ON DELETE CASCADE;
CREATE INDEX log_entries_account_idx ON log_entries (account, seq DESC);

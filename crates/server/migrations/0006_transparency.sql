-- Auditable log of account keys.
--
-- What this migration changes in the threat model: until now the server could not add a device
-- to an account (attestations) nor invent a revocation (certificates). It could still lie
-- about the account key itself **on first contact** — when Alice asks for Bob's account for
-- the first time, she has nothing to compare against.
--
-- Every published key now enters an append-only Merkle tree. The server signs a head (STH)
-- and provides, on request, proof that a key is in the tree and that today's log extends
-- yesterday's.
--
-- What this does not fix, and must be said: the server can keep TWO logs and serve one to
-- each party. Every victim sees a perfectly consistent log. Only comparing heads between
-- clients — outside the database, inside encrypted messages — catches that fork.

CREATE TABLE log_entries (
    -- The index in the tree. `BIGSERIAL` guarantees strict growth; insertion order defines the
    -- tree and must never be reordered.
    seq          BIGSERIAL PRIMARY KEY,
    handle       TEXT NOT NULL REFERENCES accounts(handle) ON DELETE CASCADE,
    identity_key BYTEA NOT NULL,
    -- Pre-computed leaf hash. Recomputing it for every proof would be correct but would make a
    -- formula mismatch silent: pinned here, it becomes observable.
    leaf         BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT log_identity_key_is_ed25519 CHECK (octet_length(identity_key) = 32),
    CONSTRAINT log_leaf_is_sha256 CHECK (octet_length(leaf) = 32)
);

-- An account may appear several times: that is the whole point of an append-only log. A
-- rotation adds an entry, it replaces none.
CREATE INDEX log_entries_handle_idx ON log_entries (handle, seq DESC);

-- Log signing key.
--
-- It lives in the database because this project has a single process. **That is the structural
-- weakness of the scheme**: the log is signed by the same party it watches. A serious
-- deployment would hand the log to a distinct operator, or to several, none of them the
-- messaging server. See the README's limitations.
CREATE TABLE log_key (
    id          BOOLEAN PRIMARY KEY DEFAULT TRUE,
    signing_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Only one row possible: two log keys would sign two logs.
    CONSTRAINT log_key_unique CHECK (id),
    CONSTRAINT log_signing_key_is_ed25519 CHECK (octet_length(signing_key) = 32)
);

-- Backfilling already-created accounts happens **in Rust at startup**, not here.
--
-- Recomputing the leaf hash in SQL would mean rewriting the formula (domain prefix,
-- length-prefixed fields) in a second language. Two definitions that differ by one byte
-- produce rejected proofs — or, far worse, proofs accepted for a different tree. That is
-- exactly the problem the `transparency` crate exists to remove; reintroducing it in a
-- migration would be absurd.

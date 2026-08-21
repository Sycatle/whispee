-- The rotation chain, published where the keys already are.
--
-- # What the log already proved, and what it did not
--
-- `log_entries` records every identity key an account has ever published, in an append-only tree
-- with inclusion and consistency proofs. So the *sequence* of keys was already public and already
-- unforgeable: a rotation adds an entry, it replaces none, and a client can prove any entry it
-- was served is in the tree the server signed.
--
-- What it could not show is that each step was **authorised**. `Account::rotate` signs a claim
-- with the outgoing key naming the incoming one — that signature existed, was verified once by
-- the server at `POST /rotate`, and was then thrown away. Every client afterwards had to take the
-- server's word that the key change was the account's own doing.
--
-- That gap became load-bearing with `0014_account_identity.sql`. An account is now named by the
-- fingerprint of its **genesis** key, and the chain is what ties that name to whatever key is
-- current. Without the links published, a server could serve a rotation nobody signed and an
-- account would silently become somebody else's — under an id that still looked right, because
-- the id is computed from the first key and the first key did not change.
--
-- # Why here rather than in a table of its own
--
-- Because the thing that needs to be append-only is the sequence of keys, and it already is. A
-- separate `rotations` table would be a second ordering to keep in step with the first, and the
-- failure mode of two orderings disagreeing is precisely the fork this log exists to detect.
--
-- # Why the signature is not in the leaf hash
--
-- The leaf commits to `(account, identity_key)` and that is enough. A signature is
-- self-authenticating — it verifies against the previous key or it does not — so a server serving
-- the wrong one produces a chain that fails to verify, which is the same outcome as serving none.
-- Putting it in the leaf would change the tree's formula for a property the bytes already have.
--
-- What the server can still do is **withhold** a link. That is visible: a chain with a hole does
-- not verify, and the client says so rather than assuming continuity. Omission stays possible and
-- stays detectable, which is the asymmetry this whole project is built on.

ALTER TABLE log_entries
    -- Signed by the key of the **previous** entry, over `wac-rotate-v2`. NULL on the genesis
    -- entry, which has no predecessor to be authorised by — its authority is that its fingerprint
    -- *is* the account id, which the client checks directly.
    ADD COLUMN rotation   BYTEA,
    -- The instant the signature covers. Inside the signed message, so the server can neither
    -- backdate a rotation nor invent a fresh one from an old signature.
    ADD COLUMN rotated_at BIGINT,

    ADD CONSTRAINT log_rotation_is_ed25519 CHECK (rotation IS NULL OR octet_length(rotation) = 64),
    -- Both or neither: a signature with no timestamp cannot be verified, since the timestamp is
    -- part of what was signed. Half a link is worse than none — it looks like evidence.
    ADD CONSTRAINT log_rotation_is_whole CHECK ((rotation IS NULL) = (rotated_at IS NULL));

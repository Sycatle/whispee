-- Recovery escrow. **Optional, and disabled by default.**
--
-- What this table changes in the threat model, said before the columns rather than after: until
-- it existed, the account root secret had never been on this server in any form. The twelve-word
-- phrase was generated on a device, shown once, and never transmitted. A stolen database gave an
-- attacker envelopes they could not read and public keys they could not use.
--
-- A row here is the account seed, encrypted under a key derived from something its owner carries
-- — a password, or a WebAuthn PRF secret. **Whoever obtains this table can attack that password
-- offline**: the operator, a SQL dump, a backup tape. Argon2id at 256 MiB makes each attempt
-- expensive; it does not make a guessable password safe. And because the history vault's key
-- derives from the same seed (`wac-vault-v1`), winning that attack also opens every row of
-- `vault_entries`, retroactively.
--
-- That is the whole price of an account that survives losing every device without a phrase
-- written on paper, and it is why nothing here is created unless the user asks for it.
--
-- # Why the primary key is a hash and not the account
--
-- A device recovering an account holds nothing: no device key, no seed, no signature to offer.
-- The route that serves these rows is therefore **unauthenticated**, and a table keyed by
-- account or by handle would let anybody download anybody's ciphertext — turning the offline
-- attack above from "the operator" into "everyone".
--
-- So the row is named by a value only its owner can compute: `SHA-256` of a key derived, in the
-- same expensive step as the sealing key, from the secret itself. Presenting it already requires
-- knowing the password. The server compares and nothing more; it cannot enumerate, and it cannot
-- go from a row back to the secret that names it.
--
-- Two consequences, both deliberate:
--
--   * A wrong password and an account with no escrow are the same answer, so this route is not
--     an oracle for which accounts exist or which have recovery enabled.
--   * A failed attempt names **no account**, so there is nothing to lock after N tries. The
--     bound is a per-address rate limit and only that, which is weaker than a per-account
--     counter would be and is the price of not being enumerable. See `crate::throttle`.

CREATE TABLE recovery_escrows (
    -- SHA-256 of the lookup key. The pre-image never leaves the client.
    lookup     BYTEA PRIMARY KEY CHECK (octet_length(lookup) = 32),

    -- Which account the seed belongs to. Returned by a successful lookup — a recovering client
    -- needs it, and it cannot derive it before opening the seal. Also what makes `ON DELETE
    -- CASCADE` do the right thing when an account goes.
    account    TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,

    -- 'password' or 'passkey'. One account may hold one of each, never two of a kind: a second
    -- password would be a second guess for an attacker and a forgotten one for its owner.
    kind       TEXT NOT NULL CHECK (kind IN ('password', 'passkey')),

    -- The KDF parameters the seal was made under, opaque here and covered by the ciphertext's
    -- AAD on the client. Stored so a future build recognises an older escrow; a server that
    -- rewrites them produces a decryption failure, not a weaker derivation.
    params     BYTEA NOT NULL CHECK (octet_length(params) = 13),

    -- AES-256-GCM over the 64-byte account seed: 12-byte nonce, 64 bytes of plaintext, 16-byte
    -- tag. Fixed length, so a row cannot be padded into a storage channel.
    sealed     BYTEA NOT NULL CHECK (octet_length(sealed) = 92),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (account, kind)
);

-- For the authenticated side: listing which factors an account has, and deleting them on
-- rotation. The lookup path uses the primary key.
CREATE INDEX recovery_escrows_account_idx ON recovery_escrows (account);

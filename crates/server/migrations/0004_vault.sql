-- History backup vault. **Optional, and disabled by default.**
--
-- What this table changes in the threat model, and why it is not on by default: MLS destroys
-- its keys as it goes, which makes history unreadable to anyone who gets hold of the
-- transport after the fact — including the user, on a new device. That is forward secrecy,
-- and it is a real protection.
--
-- The vault deliberately gives it up for history: entries are encrypted under a key derived
-- from the recovery phrase, so **stable over time**. If that phrase ever leaks, everything
-- backed up leaks with it, retroactively. That is the price of a history that survives losing
-- every device, and the user must accept it explicitly.
--
-- The server only ever sees blobs: it does not hold the phrase and can derive nothing.

CREATE TABLE vault_entries (
    -- Each account has its own vault, encrypted under ITS key. A message from a two-person
    -- conversation is therefore stored twice, once per participant. Sharing a vault key
    -- between accounts would give one the power to read the other's backups long after the
    -- conversation ended.
    handle     TEXT NOT NULL REFERENCES accounts(handle) ON DELETE CASCADE,
    group_id   BYTEA NOT NULL,
    -- Sequence number of the original envelope. Doubles as the cursor and deduplicates
    -- concurrent uploads from two devices of the same account.
    seq        BIGINT NOT NULL,
    payload    BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (handle, group_id, seq)
);

-- ACCEPTED METADATA LEAK: the server learns how many messages each account archives, and
-- when. It already knew who talks to whom (`group_members`); this adds a volume and a
-- timeline. Avoiding it would take padding and decoy uploads — out of scope, documented in
-- the README.
CREATE INDEX vault_entries_read_idx ON vault_entries (handle, group_id, seq);

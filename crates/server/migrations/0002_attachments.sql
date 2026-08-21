-- Attachments.
--
-- The server stores blobs already encrypted by the client, under a key it never receives: the
-- key travels inside the MLS message. The server cannot decrypt a file even though it stores
-- the whole thing.
--
-- Nothing about the file itself is kept — no name, no type, no fingerprint. That is content,
-- and it travels encrypted in the message. All the server learns is that some member of a
-- given group deposited that many bytes at that time.
CREATE TABLE attachments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id    BYTEA NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    payload     BYTEA NOT NULL,
    -- For purging orphaned attachments. Same caveat as on `envelopes`: temporal metadata, no
    -- feature may lean on it.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX attachments_group_idx ON attachments (group_id);

-- Partitioning the mailbox by group.
--
-- # Why now, while the table is still small
--
-- That is the only argument that holds. The immediate gain is modest: less contention on a
-- single index, a `VACUUM` that can work partition by partition. What is not modest is the
-- cost of not doing it — PostgreSQL cannot convert a table into a partitioned one in place,
-- the whole thing must be copied. Copying a few thousand rows is instant; copying hundreds of
-- gigabytes needs a maintenance window a messaging service does not have.
--
-- # Why HASH(group_id) and not RANGE(created_at)
--
-- Time-based splitting is the reflex answer, and it is the wrong one here, for two reasons.
--
-- **It would never be pruned.** Every envelope read carries `group_id = $1` and a cursor on
-- `seq`; none mentions `created_at`. The planner would have to visit every partition on every
-- fetch. Hashing on `group_id` prunes perfectly: one query, one partition.
--
-- **It would cost the primary key.** PostgreSQL requires the partition key to appear in every
-- unique constraint. Partitioning on `created_at` would force a PK of
-- `(group_id, seq, created_at)`, and the uniqueness of `(group_id, seq)` — the total order MLS
-- depends on — would then rest on `groups.next_seq` discipline alone. That is not nothing:
-- `next_seq` is incremented in the same transaction as the insert, so the guarantee holds, but
-- it would hang by a single thread. Since `group_id` is already part of the key, hashing costs
-- none of that.
--
-- It is also a faithful transposition of what Discord does: their partition key is
-- `(channel_id, bucket)` — the channel first, time-based splitting being only a sub-split
-- against partitions grown too large. That sub-split remains the next step here, the day a
-- conversation warrants it, and the primary-key price described above will then have to be
-- accepted.
--
-- # What this migration does NOT do: purge
--
-- The header of 0001 justifies `created_at` by "purging delivered messages", and it is
-- tempting to cash that in. It must not be: `crate::stream` already says why. Each envelope
-- consumes a generation of the MLS application ratchet, and a gap prevents decrypting what
-- follows. The server also has no notion of "delivered" — giving it one would take read
-- receipts, precisely the metadata this schema refuses to keep.
--
-- An age-based purge would therefore delete the messages of a device left offline too long,
-- silently breaking its conversation. The index below exists for the operator who will one day
-- have to intervene by hand, not for an automated job.

-- 16 partitions: enough to spread the load without multiplying files, and a power of two so a
-- future doubling can be done by splitting rather than by full redistribution.
CREATE TABLE envelopes_partitioned (
    group_id    BYTEA NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    seq         BIGINT NOT NULL,
    payload     BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, seq)
) PARTITION BY HASH (group_id);

DO $$
BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format(
            'CREATE TABLE envelopes_p%s PARTITION OF envelopes_partitioned
             FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            lpad(i::text, 2, '0'), i
        );
    END LOOP;
END $$;

-- The copy fits inside the migration transaction: `envelopes` is not yet big enough for that
-- to be a problem, and that is exactly why this is done now.
INSERT INTO envelopes_partitioned (group_id, seq, payload, created_at)
SELECT group_id, seq, payload, created_at FROM envelopes;

DROP TABLE envelopes;

ALTER TABLE envelopes_partitioned RENAME TO envelopes;

-- Global index on the partitioned table: PostgreSQL creates a local one per partition.
--
-- It serves **no** server query, and that is accepted — see the note on purging above. It
-- exists so that a manual intervention on a database grown large does not have to scan
-- sixteen partitions.
CREATE INDEX envelopes_created_at_idx ON envelopes (created_at);

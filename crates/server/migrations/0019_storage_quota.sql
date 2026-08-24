-- A stored-bytes quota per account: the bound `throttle.rs` has named since it was written.
--
-- # Why a counter and not a SUM
--
-- The check has to happen before every write, and `SUM(octet_length(payload))` over an account's
-- vault is an aggregation whose cost grows with exactly the quantity being bounded. A maintained
-- counter is O(1) to read and O(1) to move.
--
-- What that costs is drift: every path that deletes must credit, or an account is refused writes
-- for bytes that no longer exist. `crates/server/tests/storage.rs` reconciles the counter against
-- the recomputed SUM after writes, purges and deletions, so a forgotten credit fails a test
-- rather than becoming an incident nobody can reconstruct.
--
-- # Why the row is created with the account
--
-- So that charging is an UPDATE and never an upsert. `UPDATE … WHERE bytes + $1 <= ceiling` says
-- "refuse if this crosses the ceiling" in one statement, which is what makes the check safe under
-- concurrency. `INSERT … ON CONFLICT DO UPDATE` cannot express the refusal: the conflicting
-- insert has already happened by the time the condition is evaluated.
--
-- The row is created by `register_account`, in the same transaction as the account itself, and
-- not by a trigger: this schema has never used PL/pgSQL and one route inserts accounts. What
-- happens if a second insertion path is ever added and forgets this: the `UPDATE` matches no row,
-- `charge` returns false, and that account can store nothing until somebody notices. A loud
-- failure rather than a silent bypass, which is the right way round for a quota.
--
-- # What this does not bound
--
-- Envelopes. A sealed post carries no device id — that is the point of sealed sender — so the
-- account behind it cannot be charged without recording the sender of every post. The answer is
-- anonymous byte tokens, specified in `docs/specs/2026-08-24-posting-allowance.md` and not
-- implemented here.

CREATE TABLE account_storage (
    account TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    bytes   BIGINT NOT NULL DEFAULT 0,

    -- A credit larger than what was charged is a bug in a deletion path. This makes it fail
    -- loudly the first time rather than round itself away silently every time afterwards.
    CONSTRAINT bytes_not_negative CHECK (bytes >= 0)
);

-- Every account that already exists, with what it already stores. A deployment upgrading
-- mid-life starts from a true occupancy; starting from zero would hand every existing account a
-- fresh ceiling on top of what it already holds.
INSERT INTO account_storage (account, bytes)
SELECT a.id,
       COALESCE((SELECT SUM(octet_length(v.payload))
                   FROM vault_entries v
                  WHERE v.account = a.id), 0)
  FROM accounts a
    ON CONFLICT (account) DO NOTHING;

-- ACCEPTED METADATA LEAK, and the only one this migration introduces: the server now records
-- **who** uploaded which attachment into which group. It already learned it — an upload is a
-- signed request — but it did not keep it. Charging the uploader means keeping it.
--
-- The alternative was charging the group, which leaves the heaviest write the server accepts
-- (`MAX_ATTACHMENT_BYTES`, twenty-five mebibytes) outside any personal bound and lets one member
-- exhaust a ceiling shared with people who wrote nothing. See `docs/THREAT-MODEL.md` and
-- `docs/specs/2026-08-24-storage-quota.md`.
--
-- Nullable, and null means *predates this migration*: rows uploaded before it have no owner to
-- retrofit, and inventing one would be worse than admitting the hole. They age out under
-- `ATTACHMENT_RETENTION_DAYS`, after which the hole closes by itself.
--
-- ON DELETE SET NULL rather than CASCADE: a deleted account must not silently delete attachments
-- the other members of its groups are still fetching.
ALTER TABLE attachments
    ADD COLUMN account TEXT REFERENCES accounts(id) ON DELETE SET NULL;

-- The credit path groups by owner when a purge deletes.
CREATE INDEX attachments_account_idx ON attachments (account);

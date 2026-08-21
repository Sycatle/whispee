-- Presence: the register the previous migrations refused to keep.
--
-- The header of 0001 forbids columns added "for convenience" — and that header cannot be
-- amended: sqlx checks the checksum of every applied migration, so the text of 0001 is
-- immutable in the literal sense. The rule stays written there as is, and the exception is
-- declared here, one single named exception: `last_seen_at`. It does not work around the
-- rule, it knowingly breaks it, because no cryptographic construction lets you display that
-- an account is online. For that to be known, someone has to know it; that someone is the
-- server, and what it learns in the process is everyone's sleep schedule, time zone and
-- absences.
--
-- What bounds the leak, and is the real content of this migration:
--
--  * the column is on the DEVICE, but is never served per device to a third party — only the
--    per-account MAX leaves the server. Serving the detail would say how many devices a
--    person owns and which one they use at what hour;
--  * it is written only by identity-authenticated paths. Anonymous posts (0007) never touch
--    it: the server does not know who posted, and presence derived from a post would tell it;
--  * it is truncated to the minute. The server sees the exact request time anyway; truncation
--    does not protect it from itself, it only stops broadcasting a second-accurate clock to
--    every correspondent;
--  * there is NO history. A `presence_log` table would be a movement journal. Overwriting is
--    the feature, not an implementation shortcut.

ALTER TABLE devices
    -- Nullable, no DEFAULT: a device never seen since this migration must be
    -- indistinguishable from an offline one. `DEFAULT now()` would declare the entire fleet
    -- online at deployment time — a lie, and the first one clients would display.
    ADD COLUMN last_seen_at TIMESTAMPTZ;

-- Deliberately NO index on `last_seen_at`.
--
-- Not an oversight: an indexed column rules out HOT updates, so every heartbeat would rewrite
-- an index entry on top of the row. The MAX runs over an account's handful of devices, which
-- the partial index `devices_handle_idx` already narrows down.
--
-- The index that is genuinely missing is elsewhere: the primary key of `group_members` is
-- (group_id, device_id), so any lookup BY DEVICE scans the table. The presence access check —
-- "do we share a group?" — would do that on every read.
CREATE INDEX group_members_device_idx ON group_members (device_id);

-- Presence opt-out, reciprocal.
--
-- Honoured ON WRITE, in `presence::touch`: nothing is recorded for that account. A setting
-- that merely filtered on read would let the server keep the register anyway, and a purely
-- client-side checkbox would be a lie on screen.
--
-- Reciprocal, like disabling read receipts: no longer broadcasting your presence also means
-- no longer seeing others'. Without that symmetry the setting would allow seeing without
-- being seen, which is exactly what it claims to prevent.
ALTER TABLE accounts
    ADD COLUMN presence_optout BOOLEAN NOT NULL DEFAULT false;

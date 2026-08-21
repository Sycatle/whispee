-- The cooldown counts renames, not the age of a name.
--
-- # The defect
--
-- `rename_account` measured how long the account had held its current handle and refused if that
-- was under a day. That reads correctly and is wrong on the one case that matters most: the
-- **first** rename. A handle claimed at sign-up is minutes old, so somebody who has just been
-- given `@bob5194` and wants `@robert` is told they renamed too recently — when they have never
-- renamed at all.
--
-- The rule was always about frequency: renaming freely is how somebody escapes a block, or grinds
-- through names until they land on one that reads like somebody else's. Frequency is measured
-- between *changes*, and the first change has no previous one.
--
-- # Why a flag and not a count of tombstones
--
-- Counting an account's released names would be the obvious source, and it is unavailable on
-- purpose: `0014_account_identity.sql` clears `account` on release, so a tombstone reserves the
-- name without recording whose it was. That was a deliberate choice about what this table is
-- allowed to answer, and reversing it to implement a rate limit would trade a privacy property
-- for a convenience.
--
-- A boolean on the live row says exactly what the rule needs and nothing more: whether this name
-- arrived by a rename. `claimed_at` then dates the change rather than the account.

ALTER TABLE handles
    -- True when this name was taken by `rename_account`, false when it was the one claimed at
    -- sign-up. Only the first kind is subject to the cooldown.
    ADD COLUMN from_rename BOOLEAN NOT NULL DEFAULT false;

-- Who may start a conversation with an account.
--
-- # Why this is server-side when almost nothing else is
--
-- The same test `0008_presence.sql` applied to the presence opt-out: a setting belongs here when
-- the server is the one that *executes* it. Being added to a group is a transport act — a row in
-- `group_members` — and the server is the only party that can decline to write it. A client-side
-- version would be a checkbox that lets the envelopes arrive and then declines to read them,
-- which is what `blocked` already is and says it is.
--
-- That distinction is the whole reason this column exists. `apps/web/src/lib/storage.ts` says of
-- `blocked` that it hides rather than prevents, and names this as the half that would prevent.
-- Until now that half was a claim: the field was written, read back and tested on the client, and
-- there was no column, no route and no mention of a contact policy anywhere in `crates/`.
--
-- # What the server learns by enforcing it
--
-- Nothing it did not already hold. The check reads `group_members`, which it maintains, and the
-- account of the caller, which it authenticated. It answers "do these two already meet
-- somewhere", a question it could already answer at any moment. The only new fact on this server
-- is the policy itself, and that is the fact the account is asking it to act on.
--
-- # The three values, and why the middle one means what the server can see
--
--   open    anybody may add this account to a group
--   known   only an account that already shares a group with it
--   closed  nobody new; existing conversations are untouched
--
-- `known` is deliberately not "verified". Verification is compared out of band and lives in the
-- client; teaching the server who has verified whom would hand it a social graph finer than the
-- one it already has, to enforce a rule it could enforce more coarsely without. What the server
-- can see is whether two accounts already meet, so that is what the word means here, and the
-- interface has to say so rather than let it be assumed.
--
-- # Not retroactive, and it cannot be
--
-- `closed` refuses new additions. It does not remove anybody from a group they are already in,
-- and no column could: the membership that matters is the MLS tree, which this server cannot
-- read. A setting that emptied a distribution list would break every conversation the account
-- already had while leaving its members holding the keys.
ALTER TABLE accounts
    ADD COLUMN contact_policy TEXT NOT NULL DEFAULT 'open';

-- Checked in the schema and not only in Rust. `presence_optout` is a boolean and cannot be wrong;
-- this one is a string, and a typo in a future migration or a hand-run UPDATE would produce a
-- policy no code branch matches — which would fail open, silently, on the setting whose entire
-- purpose is to refuse.
ALTER TABLE accounts
    ADD CONSTRAINT contact_policy_is_known
    CHECK (contact_policy IN ('open', 'known', 'closed'));

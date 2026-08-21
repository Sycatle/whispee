-- Waking sleeping devices, and what it costs.
--
-- # What this table degrades, before what it brings
--
-- All the rest of this schema aims at a server that knows as little as possible. This table
-- goes the other way, and that has to be said first.
--
-- For a sleeping phone to learn a message is waiting, someone has to wake it. On Android and
-- iOS that someone can only be Google or Apple: the system refuses to let an application hold
-- a background connection, and no trick works around that for long. The server must therefore
-- tell a third party "wake this device, now" — and that third party learns, with every
-- message, the **rhythm** of the conversations of a device it can otherwise tie to a Google or
-- Apple account.
--
-- The content stays encrypted, nobody touches it. What leaks is activity metadata: when, how
-- often, and for which device. That is irreducible — it is the very principle of push, not an
-- implementation flaw.
--
-- # Hence the three limits
--
--  * **Optional.** No row is the normal state. An account that does not want push keeps a
--    fully functional application: it fetches while open, as it does today. The choice belongs
--    to the device, never to the server.
--
--  * **Inert without configuration.** A self-hosted deployment that refuses to talk to Apple
--    and Google must work in full. Tokens register there without anything being sent: it is
--    the sender that is absent, not the table.
--
--  * **Empty.** The wake-up carries no text, no sender, no group identifier. Nothing but "wake
--    up". The application then fetches through the normal path, decrypts, and composes the
--    notification locally. Doing otherwise would show Apple, Google and the lock screen who
--    writes to whom — precisely what this whole project tries not to disclose.
--
-- # The token is a routing secret
--
-- Whoever holds it can buzz the phone at will. It decrypts nothing and proves no identity, but
-- it designates a device stably: treat it as a private address, not a public identifier. Hence
-- the absence of any index that would make it enumerable, and uniqueness carried by the device.

CREATE TABLE push_tokens (
    -- One device, one token. Replacement is the rule, not the exception: providers rotate
    -- their tokens without warning, and keeping the old ones would accumulate dead addresses
    -- whose only use is to keep a record of them.
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,

    -- `fcm` or `apns`. Stored because the same server serves both platforms and routing
    -- differs; it says nothing more than the token's own shape already gives away.
    provider TEXT NOT NULL,

    token TEXT NOT NULL,

    -- Used to spot abandoned tokens. No history: a table keeping successive registrations
    -- would say when a device is reinstalled, updated or changes hands — a life journal of the
    -- device, for zero benefit.
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

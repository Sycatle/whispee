-- The deployment's VAPID key pair, for Web Push.
--
-- # Why the server generates it instead of being handed it
--
-- Because the alternative is worse in a way that is easy to miss. A `VAPID_PRIVATE_KEY` variable
-- means every operator has to produce a P-256 key in the one encoding this server accepts, which
-- in practice means an `openssl` incantation copied from somewhere, and a private key travelling
-- through a shell history and an environment file on its way in. It also means a deployment that
-- rotates the key by accident silently invalidates every subscription it ever handed out, with no
-- error anywhere — the push services simply start refusing.
--
-- `log_key` in `0006_transparency.sql` already solved this shape: a key the server needs, creates
-- once, and never twice. The same table, for the same reason.
--
-- # What is stored, and what is not
--
-- The private scalar, thirty-two bytes. The public half is derived from it on demand rather than
-- stored beside it: two copies of one key pair is one copy that can be wrong, and the derivation
-- costs a multiplication on a path that runs once per push service per few hours.
--
-- # This table existing does not turn push on
--
-- The key is created on every start, like the log's, because a key that appears only once
-- configuration is present is a key that appears on a path nobody tested. What turns push on is
-- `VAPID_SUBJECT`: with no subject the waker stays `Silent` and this row is unused. That is the
-- second of the three limits written into `0011_push.sql` — inert without configuration — and it
-- is enforced in `crate::push`, not here.
CREATE TABLE vapid_key (
    id          BOOLEAN PRIMARY KEY DEFAULT TRUE,
    signing_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- One row, always. The same guard `log_key` carries: two keys would mean two identities
    -- offered to the same push service, and subscriptions minted under the older one would start
    -- being refused with nothing to say why.
    CONSTRAINT vapid_key_is_singleton CHECK (id IS TRUE),
    -- A P-256 private scalar. A wrong length here is a key that cannot sign, and finding that out
    -- at the first wake-up means finding it out on a path nobody is watching.
    CONSTRAINT vapid_signing_key_is_p256 CHECK (octet_length(signing_key) = 32)
);

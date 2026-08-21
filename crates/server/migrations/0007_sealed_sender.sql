-- Sealed sender: taking knowledge of the sender away from the server.
--
-- What the server saw until now, and it is far from harmless: every envelope carried the
-- sending device's signature. The content was encrypted, but "who writes to whom, when, how
-- often" was readable in the clear — and that is often more revealing than the content.
--
-- # The idea: prove membership, not identity
--
-- The server has no need to know WHO posts. It needs to know the poster is a member of the
-- group, so as not to be an open mailbox. Those are two different things, and the second one
-- suffices.
--
-- Each group therefore carries a posting key, shared by all its members and known to the
-- server. Posting requires a MAC under that key: the server checks it comes from a member,
-- without being able to say which one.
--
-- # What this does not hide, and must be said
--
-- The IP address, the timing, and the fact that a message was posted to THIS group. A server
-- watching the network correlates all of it easily. Hiding that would take a third-party
-- relay — out of scope.
--
-- The server holds the key, so it can post itself: it can only produce noise, being unable to
-- encrypt under MLS, but it can pollute. That is the price of a symmetric MAC; zero-knowledge
-- tokens would avoid it, at the cost of vastly more machinery.

ALTER TABLE groups
    -- Nullable: existing groups keep using signed posting. Making the key mandatory would
    -- silence every ongoing conversation.
    ADD COLUMN posting_key BYTEA,
    ADD CONSTRAINT posting_key_is_256_bits
        CHECK (posting_key IS NULL OR octet_length(posting_key) = 32);

-- Replay protection.
--
-- Without it, anyone who intercepts an anonymous post can replay it forever: the MAC stays
-- valid, since it depends on no timestamp. The uniqueness constraint is the protection — not
-- application code, which would have a race window between the SELECT and the INSERT.
CREATE TABLE posting_nonces (
    group_id BYTEA NOT NULL,
    nonce    BYTEA NOT NULL,
    used_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, nonce),
    CONSTRAINT posting_nonce_len CHECK (octet_length(nonce) = 16)
);

-- Nonces of a deleted group serve no purpose any more.
CREATE INDEX posting_nonces_used_at_idx ON posting_nonces (used_at);

-- Pièces jointes.
--
-- Le serveur stocke des blobs déjà chiffrés par le client, avec une clé qui ne lui parvient
-- jamais : elle voyage à l'intérieur du message MLS. Le serveur ne peut donc pas déchiffrer
-- un fichier, même en le stockant intégralement.
--
-- Rien n'est conservé sur le fichier lui-même — ni nom, ni type, ni empreinte. Ces
-- informations sont du contenu, et voyagent chiffrées dans le message. La seule chose que
-- le serveur apprend est qu'un membre de tel groupe a déposé tant d'octets à tel moment.
CREATE TABLE attachments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id    BYTEA NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    payload     BYTEA NOT NULL,
    -- Pour la purge des pièces jointes orphelines. Même réserve que sur `envelopes` :
    -- c'est une métadonnée temporelle, aucune fonctionnalité ne doit s'y adosser.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX attachments_group_idx ON attachments (group_id);

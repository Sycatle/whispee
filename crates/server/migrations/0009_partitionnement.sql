-- Partitionnement de la boîte aux lettres par groupe.
--
-- # Pourquoi maintenant, alors que la table est petite
--
-- C'est le seul argument qui tienne. Le gain immédiat est modeste : moins de contention sur un
-- index unique, un `VACUUM` qui peut travailler partition par partition. Ce qui n'est pas
-- modeste, c'est le coût de ne pas le faire — PostgreSQL ne convertit pas une table en table
-- partitionnée sur place, il faut la recopier intégralement. Recopier quelques milliers de
-- lignes est instantané ; recopier plusieurs centaines de gigaoctets demande une fenêtre de
-- maintenance qu'un service de messagerie n'a pas.
--
-- # Pourquoi par HASH(group_id) et non par RANGE(created_at)
--
-- Le découpage temporel est la réponse réflexe, et c'est la mauvaise ici, pour deux raisons.
--
-- **Il ne serait jamais élagué.** Toutes les lectures d'enveloppes portent `group_id = $1` et
-- un curseur sur `seq` ; aucune ne mentionne `created_at`. Le planificateur devrait donc
-- visiter chaque partition à chaque relève. Le hash sur `group_id`, lui, est éliminé
-- parfaitement : une requête, une partition.
--
-- **Il coûterait la clé primaire.** PostgreSQL exige que la clé de partitionnement figure dans
-- toute contrainte unique. Partitionner sur `created_at` imposerait une PK
-- `(group_id, seq, created_at)`, et l'unicité de `(group_id, seq)` — l'ordre total dont MLS
-- dépend — ne serait plus garantie que par la discipline de `groups.next_seq`. Ce n'est pas
-- rien : `next_seq` est bien incrémenté dans la même transaction que l'insertion, donc la
-- garantie tient, mais elle ne tiendrait plus qu'à un seul fil. `group_id` faisant déjà partie
-- de la clé, le hash ne coûte rien de tout cela.
--
-- C'est aussi la transposition fidèle de ce que fait Discord : leur clé de partition est
-- `(channel_id, bucket)` — le canal d'abord, le découpage temporel n'étant qu'un
-- sous-découpage contre les partitions devenues trop grosses. Ce sous-découpage reste l'étape
-- suivante ici, le jour où une conversation le justifiera, et il faudra alors accepter le prix
-- sur la clé primaire décrit ci-dessus.
--
-- # Ce que cette migration ne fait PAS : purger
--
-- L'en-tête de 0001 justifie `created_at` par « la purge des messages livrés », et il serait
-- tentant d'en profiter. Il ne faut pas, et `crate::stream` le dit déjà : chaque enveloppe
-- consomme une génération du ratchet applicatif MLS, et un trou empêche le déchiffrement de la
-- suite. Le serveur n'a par ailleurs aucune notion de « livré » — la lui donner demanderait des
-- accusés de réception, c'est-à-dire précisément la métadonnée que ce schéma refuse de tenir.
--
-- Une purge par âge supprimerait donc les messages d'un appareil resté hors ligne trop
-- longtemps, et lui casserait sa conversation en silence. L'index ci-dessous est créé pour
-- l'opérateur qui devra un jour intervenir à la main, pas pour une tâche automatique.

-- 16 partitions : assez pour répartir sans multiplier les fichiers, et une puissance de deux
-- pour qu'un doublement futur puisse se faire par découpage plutôt que par redistribution
-- complète.
CREATE TABLE envelopes_partitionnees (
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
            'CREATE TABLE envelopes_p%s PARTITION OF envelopes_partitionnees
             FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            lpad(i::text, 2, '0'), i
        );
    END LOOP;
END $$;

-- La recopie tient dans la transaction de la migration : `envelopes` n'est pas encore assez
-- grosse pour que cela pose problème, et c'est exactement la raison de faire ceci maintenant.
INSERT INTO envelopes_partitionnees (group_id, seq, payload, created_at)
SELECT group_id, seq, payload, created_at FROM envelopes;

DROP TABLE envelopes;

ALTER TABLE envelopes_partitionnees RENAME TO envelopes;

-- Index global sur la table partitionnée : PostgreSQL en crée un local par partition.
--
-- Il ne sert **aucune** requête du serveur, et c'est assumé — voir la note sur la purge
-- ci-dessus. Il existe pour qu'une intervention manuelle sur une base devenue grosse n'ait pas
-- à balayer seize partitions.
CREATE INDEX envelopes_created_at_idx ON envelopes (created_at);

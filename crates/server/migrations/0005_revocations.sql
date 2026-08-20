-- Certificats de révocation : rendre le retrait d'un appareil vérifiable sans le serveur.
--
-- La migration 0003 a retiré au serveur le pouvoir d'AJOUTER un appareil à un compte. Elle
-- lui laissait celui d'en RETIRER un : `revoked_at` était une simple colonne, que rien
-- n'authentifiait.
--
-- Ce pouvoir n'est pas anodin. Un retrait d'appareil se traduit par un commit MLS, et ce
-- commit est posé par un AUTRE compte — si Alice perd son téléphone, c'est Bob, présent dans
-- le groupe, qui l'évince. Bob n'a donc que la parole du serveur, et un serveur qui ment
-- fait exclure les appareils de son choix : de la censure, ciblée et durable.
--
-- Désormais chaque révocation porte une signature du compte (domaine `wac-revoke-v1`, voir
-- la crate `attest`). Le serveur peut toujours TAIRE une révocation ; il ne peut plus en
-- INVENTER une.

-- Base de démonstration : les révocations antérieures n'ont pas de certificat et personne ne
-- peut leur en fabriquer un rétroactivement. On les annule plutôt que de les laisser violer
-- la contrainte ci-dessous.
UPDATE devices SET revoked_at = NULL WHERE revoked_at IS NOT NULL;

ALTER TABLE devices
    ADD COLUMN revocation BYTEA,

    ADD CONSTRAINT revocation_is_ed25519
        CHECK (revocation IS NULL OR octet_length(revocation) = 64),

    -- Le point important de cette migration. Une révocation sans certificat est exactement le
    -- pouvoir qu'on refuse au serveur : la base le rend impossible, plutôt que de s'en
    -- remettre à la discipline du code applicatif. L'équivalence dans les deux sens interdit
    -- aussi le cas inverse, un certificat déposé sans prise d'effet.
    ADD CONSTRAINT revocation_accompagne_revoked_at
        CHECK ((revoked_at IS NULL) = (revocation IS NULL));

-- Les appareils révoqués sont désormais SERVIS aux clients, avec leur certificat : sans quoi
-- un client ne pourrait pas distinguer une révocation d'une omission, et l'omission est
-- précisément ce que le serveur peut encore faire. L'index existant ne couvrant que les
-- appareils actifs, on en ajoute un sur la lecture complète d'un compte.
CREATE INDEX devices_handle_all_idx ON devices (handle);

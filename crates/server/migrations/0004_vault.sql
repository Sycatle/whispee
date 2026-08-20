-- Coffre de sauvegarde de l'historique. **Optionnel, et désactivé par défaut.**
--
-- Ce que cette table change dans le modèle de menace, et pourquoi elle n'est pas activée
-- d'office : MLS détruit ses clés au fur et à mesure, ce qui rend l'historique illisible pour
-- quiconque met la main sur le transport après coup — y compris pour l'utilisateur lui-même
-- sur un appareil neuf. C'est la forward secrecy, et c'est une protection réelle.
--
-- Le coffre y renonce délibérément pour l'historique : les entrées sont chiffrées sous une clé
-- dérivée de la phrase de récupération, donc **stable dans le temps**. Si cette phrase fuit un
-- jour, tout le passé sauvegardé fuit avec elle, rétroactivement. C'est le prix d'un historique
-- qui survit à la perte de tous les appareils, et l'utilisateur doit l'accepter explicitement.
--
-- Le serveur, lui, ne voit que des blobs : il ne détient pas la phrase et ne peut rien dériver.

CREATE TABLE vault_entries (
    -- Chaque compte a son propre coffre, chiffré sous SA clé. Un message d'une conversation à
    -- deux est donc stocké deux fois, une par participant. Partager une clé de coffre entre
    -- comptes reviendrait à donner à l'un le pouvoir de lire les sauvegardes de l'autre bien
    -- après la fin de la conversation.
    handle     TEXT NOT NULL REFERENCES accounts(handle) ON DELETE CASCADE,
    group_id   BYTEA NOT NULL,
    -- Numéro de séquence de l'enveloppe d'origine. Sert de curseur et dédoublonne les dépôts
    -- concurrents de deux appareils du même compte.
    seq        BIGINT NOT NULL,
    payload    BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (handle, group_id, seq)
);

-- FUITE DE MÉTADONNÉE ASSUMÉE : le serveur apprend combien de messages chaque compte archive
-- et quand. Il savait déjà qui parle à qui (`group_members`) ; ceci ajoute un volume et une
-- chronologie. Éviter cela demanderait du padding et des dépôts factices — hors périmètre,
-- documenté dans le README.
CREATE INDEX vault_entries_lecture_idx ON vault_entries (handle, group_id, seq);

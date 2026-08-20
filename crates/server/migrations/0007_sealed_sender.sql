-- Sealed sender : retirer au serveur la connaissance de l'expéditeur.
--
-- Ce que le serveur voyait jusqu'ici, et qui n'a rien d'anodin : chaque enveloppe portait la
-- signature de l'appareil émetteur. Le contenu était chiffré, mais « qui écrit à qui, quand,
-- à quelle fréquence » était lisible en clair — et c'est souvent plus révélateur que le
-- contenu lui-même.
--
-- # L'idée : prouver l'appartenance, pas l'identité
--
-- Le serveur n'a aucun besoin de savoir QUI poste. Il a besoin de savoir que le posteur est
-- membre du groupe, pour ne pas servir de boîte aux lettres ouverte. Ce sont deux choses
-- différentes, et la seconde suffit.
--
-- Chaque groupe porte donc une clé de dépôt, partagée par tous ses membres et connue du
-- serveur. Poster demande un MAC sous cette clé : le serveur vérifie qu'il vient d'un membre,
-- sans pouvoir dire lequel.
--
-- # Ce que cela ne cache pas, et qu'il faut dire
--
-- L'adresse IP, l'horaire, et le fait qu'un message soit déposé dans CE groupe. Un serveur qui
-- observe le réseau recoupe sans peine. Le masquer demanderait un relais tiers — hors périmètre.
--
-- Le serveur détient la clé, donc il peut poster lui-même : il ne produira que du bruit, faute
-- de pouvoir chiffrer sous MLS, mais il peut polluer. C'est le prix d'un MAC symétrique ; des
-- jetons à divulgation nulle l'éviteraient, au prix d'une machinerie sans commune mesure.

ALTER TABLE groups
    -- Nullable : les groupes existants continuent d'utiliser le dépôt signé. Imposer la clé
    -- rendrait muettes toutes les conversations en cours.
    ADD COLUMN posting_key BYTEA,
    ADD CONSTRAINT posting_key_is_256_bits
        CHECK (posting_key IS NULL OR octet_length(posting_key) = 32);

-- Anti-rejeu.
--
-- Sans elle, quiconque intercepte un dépôt anonyme peut le rejouer indéfiniment : le MAC reste
-- valide, puisqu'il ne dépend d'aucun horodatage. La contrainte d'unicité est la protection —
-- pas le code applicatif, qui aurait une fenêtre de concurrence entre le SELECT et l'INSERT.
CREATE TABLE posting_nonces (
    group_id BYTEA NOT NULL,
    nonce    BYTEA NOT NULL,
    used_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, nonce),
    CONSTRAINT posting_nonce_len CHECK (octet_length(nonce) = 16)
);

-- Les nonces d'un groupe supprimé n'ont plus d'objet.
CREATE INDEX posting_nonces_used_at_idx ON posting_nonces (used_at);

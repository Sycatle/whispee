-- Schéma de la boîte aux lettres aveugle.
--
-- Principe directeur : le serveur ne doit rien pouvoir déchiffrer, et chaque colonne
-- ajoutée « pour le confort » (aperçu du dernier message, compteur de non-lus, statut de
-- frappe) est une fuite de métadonnées permanente. Toute nouvelle colonne doit être
-- justifiée par un besoin de routage ou de nettoyage, jamais par l'UI.

-- Un appareil, pas un utilisateur. En MLS l'unité d'appartenance à un groupe est l'appareil :
-- un utilisateur avec trois téléphones est trois membres.
CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    -- Clé Ed25519 publique servant à authentifier les requêtes HTTP.
    --
    -- Délibérément distincte de la clé de signature MLS. Réutiliser une même clé pour
    -- deux protocoles est une erreur classique : les messages signés dans l'un peuvent
    -- devenir des signatures valides dans l'autre si les formats se recouvrent.
    auth_key    BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT auth_key_is_ed25519 CHECK (octet_length(auth_key) = 32)
);

-- Stock de KeyPackages publiés à l'avance, pour qu'on puisse être ajouté à un groupe
-- pendant qu'on est hors ligne.
--
-- Chaque KeyPackage est à USAGE UNIQUE : sa clé d'initialisation ne doit servir qu'une
-- fois. OpenMLS ne l'empêche pas (vérifié par le test
-- `la_reutilisation_de_key_package_doit_etre_empechee_par_le_serveur`) : c'est donc au
-- serveur de garantir le retrait atomique à la première consommation.
CREATE TABLE key_packages (
    id         BIGSERIAL PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    payload    BYTEA NOT NULL
);

CREATE INDEX key_packages_device_idx ON key_packages (device_id, id);

-- Un groupe MLS. Le serveur n'en connaît ni les clés ni le contenu ; il ne tient que le
-- compteur qui garantit un ordre total des messages.
--
-- Cet ordre n'est pas cosmétique : MLS exige que tous les membres appliquent les commits
-- dans le même ordre. Deux membres qui divergent d'epoch ne peuvent plus se lire.
CREATE TABLE groups (
    id        BYTEA PRIMARY KEY,
    next_seq  BIGINT NOT NULL DEFAULT 0
);

-- Qui a le droit de lire quelle boîte.
--
-- FUITE DE MÉTADONNÉE ASSUMÉE : cette table dit au serveur qui parle avec qui. C'est le
-- même compromis que WhatsApp. L'éviter demande des identifiants de groupe anonymes et des
-- credentials à divulgation nulle (le Private Group System de Signal) — hors périmètre.
--
-- Sans cette table, n'importe quel appareil authentifié pourrait lire n'importe quel groupe
-- en devinant son identifiant. Un identifiant aléatoire n'est pas un contrôle d'accès.
CREATE TABLE group_members (
    group_id   BYTEA NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,

    PRIMARY KEY (group_id, device_id)
);

-- La boîte aux lettres elle-même. `payload` est un blob MLS opaque.
--
-- Le test `le_serveur_ne_voit_que_du_chiffre` lit cette table directement en SQL et vérifie
-- qu'aucun clair n'y transparaît.
CREATE TABLE envelopes (
    group_id    BYTEA NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    -- Attribué par le serveur, strictement croissant par groupe. Sert de curseur de
    -- récupération et impose l'ordre total.
    seq         BIGINT NOT NULL,
    payload     BYTEA NOT NULL,
    -- Uniquement pour la purge des messages livrés. C'est une métadonnée temporelle :
    -- elle révèle quand chacun parle. Aucune autre fonctionnalité ne doit s'y adosser.
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, seq)
);

-- Journal auditable des clés de compte.
--
-- Ce que cette migration change dans le modèle de menace : jusqu'ici, le serveur ne pouvait pas
-- ajouter d'appareil à un compte (attestations) ni inventer de révocation (certificats). Il
-- pouvait encore mentir sur la clé du compte elle-même **au premier contact** — quand Alice
-- demande le compte de Bob pour la première fois, elle n'a rien à quoi comparer.
--
-- Chaque clé publiée entre désormais dans un arbre de Merkle append-only. Le serveur signe une
-- tête (STH) et fournit, à la demande, la preuve qu'une clé y figure et que le journal
-- d'aujourd'hui prolonge celui d'hier.
--
-- Ce que cela ne règle pas, et qui doit rester dit : le serveur peut tenir DEUX journaux et en
-- servir un à chacun. Chaque victime voit un journal parfaitement cohérent. Seule la
-- comparaison des têtes entre clients — hors de la base, dans les messages chiffrés — attrape
-- cette bifurcation.

CREATE TABLE log_entries (
    -- L'indice dans l'arbre. `BIGSERIAL` garantit la croissance stricte ; c'est l'ordre
    -- d'insertion qui définit l'arbre, et il ne doit jamais être réordonné.
    seq          BIGSERIAL PRIMARY KEY,
    handle       TEXT NOT NULL REFERENCES accounts(handle) ON DELETE CASCADE,
    identity_key BYTEA NOT NULL,
    -- Hash de feuille pré-calculé. Le recalculer à chaque preuve serait correct mais rendrait
    -- une divergence de formule silencieuse : figée ici, elle se constate.
    leaf         BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT log_identity_key_is_ed25519 CHECK (octet_length(identity_key) = 32),
    CONSTRAINT log_leaf_is_sha256 CHECK (octet_length(leaf) = 32)
);

-- Un compte peut apparaître plusieurs fois : c'est le principe même d'un journal append-only.
-- Une rotation ajoute une entrée, elle n'en remplace aucune.
CREATE INDEX log_entries_handle_idx ON log_entries (handle, seq DESC);

-- Clé de signature du journal.
--
-- Elle vit en base parce que ce projet n'a qu'un seul processus. **C'est la faiblesse
-- structurelle du dispositif** : le journal est signé par la même partie que celle qu'il
-- surveille. Un déploiement sérieux confierait le journal à un opérateur distinct, ou à
-- plusieurs, dont aucun ne serait le serveur de messagerie. Voir les limites du README.
CREATE TABLE log_key (
    id          BOOLEAN PRIMARY KEY DEFAULT TRUE,
    signing_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Une seule ligne possible : deux clés de journal signeraient deux journaux.
    CONSTRAINT log_key_unique CHECK (id),
    CONSTRAINT log_signing_key_is_ed25519 CHECK (octet_length(signing_key) = 32)
);

-- Le rattrapage des comptes déjà créés se fait **en Rust au démarrage**, pas ici.
--
-- Recalculer le hash de feuille en SQL exigerait de réécrire la formule (préfixe de domaine,
-- longueurs préfixées) dans un second langage. Deux définitions qui divergent d'un octet
-- produisent des preuves refusées — ou, bien pire, acceptées pour un arbre différent. C'est
-- exactement le problème que la crate `transparency` existe pour supprimer, il serait absurde
-- de le réintroduire dans une migration.

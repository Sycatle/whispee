-- Comptes pseudonymes et rattachement attesté des appareils.
--
-- Ce que cette migration change dans le modèle de menace : jusqu'ici, le serveur ne pouvait
-- pas mentir, faute d'avoir quoi que ce soit à dire — un appareil était son propre contact.
-- Dès qu'un compte regroupe plusieurs appareils, le serveur devient la source de la liste,
-- et une liste qu'il compose librement lui permet d'y glisser un appareil qu'il contrôle.
--
-- D'où `attestation` : une signature du compte que le serveur ne peut pas produire. Il peut
-- encore OMETTRE un appareil de la liste (censure, détectable par l'utilisateur qui ne voit
-- pas arriver ses messages), jamais en AJOUTER un (écoute, indétectable). C'est cette
-- asymétrie qui justifie toute la migration.

CREATE TABLE accounts (
    -- Pseudonyme, en clair. Le serveur le voit, et tous les membres d'un groupe aussi — le
    -- credential MLS transporte déjà le nom d'appareil en clair dans l'arbre public.
    -- N'y rattacher ni numéro, ni e-mail, ni rien de réel : voir les limites du README.
    handle       TEXT PRIMARY KEY,
    -- Clé Ed25519 publique du compte (AIK). Dérivée côté client de la phrase de
    -- récupération ; le serveur n'en voit que la moitié publique et ne peut rien signer.
    identity_key BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT handle_non_vide CHECK (handle <> '' AND octet_length(handle) <= 64),
    CONSTRAINT identity_key_is_ed25519 CHECK (octet_length(identity_key) = 32)
);

-- Les appareils antérieurs n'ont pas de compte et ne peuvent pas s'en voir attribuer un :
-- personne ne détient la clé qui les attesterait. Base de démonstration, données jetables.
-- Sur un déploiement réel il faudrait une période de transition avec `handle` nullable.
DELETE FROM devices;

ALTER TABLE devices
    ADD COLUMN handle      TEXT NOT NULL REFERENCES accounts(handle) ON DELETE CASCADE,
    -- Clé publique de signature MLS. Attestée EN MÊME TEMPS que `auth_key` : les attester
    -- séparément permettrait de recombiner l'attestation d'un appareil légitime avec la clé
    -- MLS d'un appareil hostile.
    ADD COLUMN mls_key     BYTEA NOT NULL,
    ADD COLUMN attestation BYTEA NOT NULL,
    -- Révocation douce. Effacer la ligne casserait les clés étrangères de `group_members`
    -- et effacerait l'appareil de conversations où il a réellement participé ; on veut
    -- l'empêcher d'être ajouté ailleurs, pas réécrire le passé.
    ADD COLUMN revoked_at  TIMESTAMPTZ,

    ADD CONSTRAINT attestation_is_ed25519 CHECK (octet_length(attestation) = 64);

-- L'index ne couvre que les appareils actifs : c'est la seule liste qu'on sert.
CREATE INDEX devices_handle_idx ON devices (handle) WHERE revoked_at IS NULL;

-- Boîte de dépôt pour l'appairage par QR code.
--
-- Le serveur ne voit qu'un blob scellé sous un secret X25519 dont les deux moitiés publiques
-- ont transité par le QR — hors de sa portée. Il ne sert que de relais asynchrone entre deux
-- appareils qui ne peuvent pas se parler directement.
CREATE TABLE pairings (
    id         BYTEA PRIMARY KEY,
    payload    BYTEA NOT NULL,
    -- Le blob périme vite : il contient de quoi prendre le contrôle du compte. Une fenêtre
    -- courte limite la valeur d'un vol de base.
    expires_at TIMESTAMPTZ NOT NULL,
    -- Lecture unique. Une seconde lecture réussie signalerait qu'un tiers a récupéré le blob.
    claimed_at TIMESTAMPTZ,

    CONSTRAINT pairing_id_len CHECK (octet_length(id) = 16)
);

-- Anti-rejeu des requêtes signées.
--
-- # La limite que cette migration ferme
--
-- Jusqu'ici, une requête signée restait rejouable pendant toute la fenêtre de tolérance
-- d'horloge — soixante secondes. Le README l'annonçait comme une limite connue, en estimant
-- l'impact borné : le doublon d'une enveloppe est rejeté par le client MLS, faute de clé de
-- message encore disponible.
--
-- Cet argument tenait pour les enveloppes, et seulement pour elles. Un dépôt de KeyPackages
-- rejoué remplit le stock de doublons ; une consommation rejouée épuise le stock d'autrui. Rien
-- de catastrophique, mais « c'est sans effet » n'était vrai que sur un chemin.
--
-- # Pourquoi un nonce explicite, et non la signature elle-même
--
-- Mémoriser la signature aurait évité de toucher au format signé, et c'est tentant. **C'est
-- faux** : Ed25519 est déterministe. Deux requêtes identiques — même méthode, même chemin, même
-- corps, même seconde — produisent exactement la même signature, et l'une est un rejeu quand
-- l'autre est parfaitement légitime. Réclamer deux KeyPackages coup sur coup suffit à produire
-- le cas.
--
-- Le nonce entre donc dans le message signé, et le format change : voir `auth::signing_payload`.
--
-- # Pourquoi la clé porte l'appareil
--
-- Un nonce est tiré au hasard par chaque client, sans coordination. Deux appareils peuvent tirer
-- le même sans qu'aucun ne rejoue quoi que ce soit ; l'unicité n'a de sens que par appareil.
-- Même structure que `posting_nonces` en 0007, pour la même raison.
--
-- # Pourquoi `UNLOGGED`
--
-- Le contenu de cette table **n'a aucune valeur au-delà de soixante secondes** : passé la
-- fenêtre de tolérance, une requête est refusée sur son horodatage de toute façon. Perdre la
-- table à un redémarrage est donc sans conséquence, et écrire son WAL serait payer une
-- durabilité dont personne n'a besoin — sur une table qui reçoit une écriture par requête
-- authentifiée.
CREATE UNLOGGED TABLE request_nonces (
    device_id TEXT NOT NULL,
    nonce     BYTEA NOT NULL,
    seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (device_id, nonce),
    CONSTRAINT request_nonce_len CHECK (octet_length(nonce) = 16)
);

-- Pas de clé étrangère vers `devices`, délibérément : elle imposerait une vérification
-- référentielle sur le chemin de latence de chaque requête, alors que l'appelant vient d'être
-- authentifié — donc que l'appareil existe forcément. Le nettoyage se fait par l'âge, pas par
-- cascade.
--
-- Cet index sert la purge, et elle seule. La lecture se fait par la clé primaire.
CREATE INDEX request_nonces_seen_at_idx ON request_nonces (seen_at);

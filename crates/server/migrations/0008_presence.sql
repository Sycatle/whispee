-- Présence : le registre que les migrations précédentes refusaient de tenir.
--
-- L'en-tête de 0001 interdit les colonnes ajoutées « pour le confort » — et cet en-tête ne peut
-- pas être amendé : sqlx vérifie l'empreinte de chaque migration déjà appliquée, donc le texte
-- de 0001 est immuable au sens propre. La règle y reste donc écrite telle quelle, et c'est ici
-- que se déclare l'exception, une seule, nommée : `last_seen_at`. Elle n'est pas un contournement
-- de la règle, elle l'enfreint sciemment, parce qu'aucune formulation chiffrée ne permet
-- d'afficher qu'un compte est connecté. Pour le savoir, il faut que
-- quelqu'un le sache ; ce quelqu'un est le serveur, et ce qu'il apprend ce faisant, ce sont les
-- horaires de sommeil, les fuseaux et les absences de chacun.
--
-- Ce qui borne la fuite, et qui est le vrai contenu de cette migration :
--
--  * la colonne est sur l'APPAREIL, mais n'est jamais servie par appareil à un tiers — seul le
--    MAX par compte sort du serveur. Servir le détail dirait combien d'appareils une personne
--    possède et lequel elle utilise à quelle heure ;
--  * elle n'est écrite que par des chemins authentifiés par identité. Les dépôts anonymes
--    (0007) ne la touchent pas : le serveur ne sait pas qui dépose, et une présence dérivée
--    d'un dépôt reviendrait à le lui apprendre ;
--  * elle est tronquée à la minute. Le serveur voit de toute façon l'instant exact de la
--    requête ; la troncature ne le protège pas de lui-même, elle empêche seulement de diffuser
--    à tous les correspondants une horloge à la seconde ;
--  * il n'y a PAS d'historique. Une table `presence_log` serait un journal de déplacements.
--    L'écrasement est la fonctionnalité, pas un raccourci d'implémentation.

ALTER TABLE devices
    -- Nullable, sans DEFAULT : un appareil jamais vu depuis cette migration doit être
    -- indiscernable d'un appareil hors ligne. `DEFAULT now()` déclarerait en ligne, à l'instant
    -- du déploiement, l'intégralité du parc — un mensonge, et le premier que les clients
    -- afficheraient.
    ADD COLUMN last_seen_at TIMESTAMPTZ;

-- Volontairement PAS d'index sur `last_seen_at`.
--
-- Ce n'est pas une omission : une colonne indexée interdit les mises à jour HOT, et chaque
-- battement réécrirait alors une entrée d'index en plus de la ligne. Le MAX porte sur les
-- quelques appareils d'un compte, que l'index partiel `devices_handle_idx` ramène déjà.
--
-- L'index qui manque vraiment est ailleurs : la clé primaire de `group_members` est
-- (group_id, device_id), donc toute recherche PAR APPAREIL balaye la table. Le contrôle d'accès
-- de la présence — « partageons-nous un groupe ? » — le ferait à chaque lecture.
CREATE INDEX group_members_device_idx ON group_members (device_id);

-- Refus de présence, réciproque.
--
-- Honoré À L'ÉCRITURE, dans `presence::touch` : rien n'est enregistré pour ce compte. Un réglage
-- qui se contenterait de filtrer en lecture laisserait le serveur tenir le registre quand même,
-- et une case à cocher purement cliente serait un mensonge à l'écran.
--
-- Réciproque, comme la désactivation des accusés de lecture : ne plus diffuser sa présence,
-- c'est aussi cesser de voir celle des autres. Sans cette symétrie, le réglage permettrait de
-- voir sans être vu, c'est-à-dire exactement ce qu'il prétend empêcher.
ALTER TABLE accounts
    ADD COLUMN presence_optout BOOLEAN NOT NULL DEFAULT false;

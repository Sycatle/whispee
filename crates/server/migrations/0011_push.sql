-- Réveil des appareils endormis, et ce que cela coûte.
--
-- # Ce que cette table dégrade, avant ce qu'elle apporte
--
-- Tout le reste de ce schéma tend vers un serveur qui en sait le moins possible. Cette table va
-- dans l'autre sens, et il faut le dire dans cet ordre.
--
-- Pour qu'un téléphone endormi apprenne qu'un message l'attend, quelqu'un doit le réveiller.
-- Sur Android et iOS, ce quelqu'un ne peut être que Google ou Apple : le système refuse à une
-- application de tenir une connexion en arrière-plan, et c'est un refus qu'aucune astuce ne
-- contourne durablement. Le serveur doit donc dire à un tiers « réveille cet appareil,
-- maintenant » — et ce tiers apprend, à chaque message, le **rythme** des conversations d'un
-- appareil qu'il sait par ailleurs rattacher à un compte Google ou Apple.
--
-- Le contenu reste chiffré, personne n'y touche. Ce qui fuit, ce sont les métadonnées
-- d'activité : quand, à quelle fréquence, et pour quel appareil. C'est irréductible — c'est le
-- principe même du push, pas un défaut d'implémentation.
--
-- # D'où les trois bornes
--
--  * **Facultatif.** L'absence de ligne est l'état normal. Un compte qui n'en veut pas garde une
--    application pleinement fonctionnelle : elle relève quand elle est ouverte, comme
--    aujourd'hui. Le choix appartient à l'appareil, jamais au serveur.
--
--  * **Inerte sans configuration.** Un déploiement auto-hébergé qui refuse de parler à Apple et
--    Google doit fonctionner intégralement. Les jetons s'y enregistrent sans que rien ne parte :
--    c'est l'émetteur qui est absent, pas la table.
--
--  * **Vide.** Le réveil ne transporte ni texte, ni expéditeur, ni identifiant de groupe. Rien
--    d'autre que « réveille-toi ». L'application relève ensuite par le chemin normal, déchiffre,
--    et compose la notification localement. Faire autrement montrerait à Apple, à Google et à
--    l'écran verrouillé qui écrit à qui — c'est-à-dire précisément ce que tout ce projet cherche
--    à ne pas divulguer.
--
-- # Le jeton est un secret d'acheminement
--
-- Qui le détient peut faire vibrer le téléphone quand il veut. Il ne déchiffre rien et ne prouve
-- aucune identité, mais il désigne un appareil de façon stable : c'est une donnée à traiter comme
-- une adresse privée, pas comme un identifiant public. D'où l'absence d'index qui le rendrait
-- énumérable, et l'unicité portée par l'appareil.

CREATE TABLE push_tokens (
    -- Un appareil, un jeton. Le remplacement est la règle et non l'exception : les fournisseurs
    -- font tourner leurs jetons sans prévenir, et conserver les anciens accumulerait des adresses
    -- mortes qui ne servent qu'à en garder trace.
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,

    -- `fcm` ou `apns`. Stocké parce que le même serveur sert les deux plateformes et que
    -- l'acheminement n'est pas le même ; il ne dit rien de plus que ce que le jeton trahit déjà
    -- par sa forme.
    provider TEXT NOT NULL,

    token TEXT NOT NULL,

    -- Sert à repérer les jetons abandonnés. Pas d'historique : une table qui garderait les
    -- enregistrements successifs dirait quand un appareil se réinstalle, se met à jour ou change
    -- de main — un journal de vie de l'appareil, pour un bénéfice nul.
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

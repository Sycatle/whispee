# whatsapp_clone

Messagerie chiffrée de bout en bout, multi-plateforme, à cœur crypto unique en Rust.

## ⚠️ Statut : projet d'apprentissage et de démonstration

**Ce projet n'est pas destiné à protéger de vrais utilisateurs, et encore moins des
utilisateurs à risque.** Il n'a reçu aucun audit externe et n'en recevra pas. Un protocole
E2EE correct sur le papier échoue en pratique sur des détails que seul un audit révèle.
Pour des communications réellement sensibles : utilisez Signal.

## Architecture

```
crates/
  ratchet-lab/    Réimplémentation pédagogique de X3DH + Double Ratchet
  crypto-core/    OpenMLS — le seul chemin de production
  crypto-wasm/    binding web (wasm-bindgen)
  attest/         domaines de signature et de MAC
  transparency/   arbre de Merkle append-only (key transparency)
  server/         delivery service (axum + PostgreSQL)
apps/
  web/            Vite + React (web, et source de l'application de bureau)
  desktop/        application de bureau (Tauri 2)
```

### Le serveur

MLS définit le protocole mais ni le transport ni l'authentification : les deux sont à
construire. `crates/server` est une **boîte aux lettres aveugle** — il route des blobs
opaques, tient l'ordre total des messages par groupe, et ne peut rien déchiffrer.

```sh
docker compose up -d              # PostgreSQL 17 sur le port 55432
cargo run -p server               # écoute sur 127.0.0.1:8787
cargo test -p server --release
```

Le port 55432 évite les collisions avec un Postgres système (5432) ou un Supabase local
(54322).

**Authentification par signature Ed25519**, sans mot de passe ni jeton de session : la base
ne contient que des clés publiques, donc une fuite de base ne donne accès à aucun compte.
La clé d'authentification est délibérément **distincte de la clé de signature MLS** —
réutiliser une clé pour deux protocoles est une erreur classique dès que les formats de
message se recouvrent. Le message signé couvre méthode, chemin, horodatage et empreinte du
corps, ce qui empêche de rejouer une signature d'un endpoint sur un autre.

Chaque requête porte en outre un **nonce**, couvert par la signature et mémorisé à la première
présentation : la rejouer est refusé. Le nonce est indispensable et ne peut pas être remplacé par
la signature elle-même — Ed25519 est déterministe, donc deux requêtes identiques dans la même
seconde portent la même signature, l'une pouvant être un rejeu quand l'autre est légitime.
Réclamer deux KeyPackages coup sur coup suffit à produire le cas. La table des nonces est
`UNLOGGED` et purgée au-delà de la fenêtre de tolérance d'horloge : au-delà, l'horodatage refuse
la requête de toute façon.

Les quatre routes qui ne peuvent pas être authentifiées — création de compte, enregistrement
d'appareil, dépôt et relève d'appairage — portent une **limite de débit par adresse**, réglable par
`THROTTLE_PER_MINUTE` (60 par défaut). La création de compte est celle qui la justifie : elle
écrit dans le journal de transparence, dont les entrées ne se reprennent pas sans casser les
preuves de consistance. Sans limite, un tiers sans identité faisait grossir indéfiniment la seule
table du schéma qu'on ne sait pas nettoyer — la clé étrangère `ON DELETE CASCADE` offre bien une
sortie, mais elle troue le journal, c'est-à-dire qu'elle choisit de casser les preuves plutôt que
de garder le déchet.

Le compteur vit **en mémoire, donc par instance** : deux instances offrent deux fois le quota, et
un redémarrage remet à zéro. L'adresse n'est pas non plus une identité — qui en change contourne,
et des utilisateurs derrière un même NAT partagent. C'est un ralentisseur, pas une barrière ; un
déploiement sérieux porterait cette limite dans le répartiteur, qui voit tout le trafic. Le
serveur ne lit d'ailleurs que l'adresse de la socket et jamais `X-Forwarded-For`, qui se falsifie
librement.

**Points critiques implémentés :**

- retrait atomique des KeyPackages (`DELETE ... RETURNING` sur `FOR UPDATE SKIP LOCKED`) —
  OpenMLS n'empêche pas leur réutilisation, c'est donc au serveur de la rendre impossible ;
- ordre total par groupe, incrément et insertion dans la même transaction — deux membres qui
  divergent d'epoch ne peuvent plus se lire ;
- contrôle d'accès explicite par groupe : un identifiant de groupe aléatoire n'est pas un
  contrôle d'accès.

`envelopes` est partitionnée par `HASH(group_id)`, en seize partitions. Le découpage temporel
serait le réflexe et c'est le mauvais ici : aucune lecture ne mentionne `created_at`, donc aucune
partition ne serait élaguée, et PostgreSQL exigerait d'ajouter la clé de partitionnement à la clé
primaire — ce qui ferait sauter l'unicité de `(group_id, seq)`, dont dépend l'ordre total MLS.
`group_id` faisant déjà partie de la clé, le hash ne coûte rien de tout cela et élague
parfaitement. Fait maintenant, tant que la table est petite : PostgreSQL ne convertit pas une table
en table partitionnée sur place.

**Limites assumées du serveur :**

| Limite | Détail |
|---|---|
| `group_members` | Le serveur sait qui parle avec qui. Même compromis que WhatsApp ; l'éviter demande des credentials à divulgation nulle (Private Group System de Signal). |
| Enregistrement | Trust on first use. Reprendre un identifiant avec une autre clé est refusé, mais rien ne prouve que le premier arrivé était légitime. Un déploiement réel adosse cet endpoint à une vérification de numéro ou d'e-mail. |
| `created_at` | Métadonnée temporelle conservée pour la purge. Aucune autre fonctionnalité ne doit s'y adosser — la règle vaut toujours pour cette colonne-ci. |
| Purge jamais faite | Et elle ne peut pas l'être automatiquement : chaque enveloppe consomme une génération du ratchet applicatif MLS, un trou empêche le déchiffrement de la suite, et le serveur n'a aucune notion de « livré » — la lui donner demanderait des accusés de réception, c'est-à-dire la métadonnée que ce schéma refuse de tenir. `envelopes` croît donc sans borne, et c'est un vrai problème d'exploitation, pas une simplification. |
| `last_seen_at` | Dernière activité de chaque appareil, à la minute près. C'est **le** registre que les autres colonnes refusaient de tenir, et il est tenu délibérément : voir « Présence » plus bas. Écrit par le seul battement de la gateway, donc jamais depuis un dépôt anonyme. |
| Arbre de ratchet | Le Welcome d'ajout transporte l'arbre MLS, **public par construction** : il contient les credentials, donc les noms des membres. Vérifié par `le_welcome_expose_les_identites_mais_jamais_le_contenu`. Le serveur connaît déjà ces identités par `devices` et `group_members`, donc la fuite n'ajoute rien à ce qu'il sait — mais elle est réelle. |

Un seul cœur crypto en Rust. Réimplémenter la crypto une fois par plateforme triplerait la
surface de bug sur la partie où un bug est silencieux — c'est ce qui a fait écarter un binding
UniFFI séparé pour le mobile : l'application Tauri sert les trois cibles depuis le même code.

### `ratchet-lab` est isolé par construction

`ratchet-lab` existe pour comprendre le protocole en l'écrivant. Il n'est **jamais** importé
par `crypto-core` ni par aucun code exécuté par un utilisateur. L'absence de dépendance
vers `ratchet-lab` dans le manifeste de `crypto-core` est un invariant à préserver — c'est
la garantie qu'aucune crypto maison ne dérive vers le chemin d'exécution réel.

### Choix : MLS (RFC 9420) plutôt que la stack Signal

- **Licence.** libsignal est AGPL-3.0, incompatible avec du code propriétaire. OpenMLS est
  sous licence MIT.
- **Une primitive pour tout.** En MLS, un 1-to-1 est un groupe de 2 : passer aux groupes ne
  demande aucune réécriture. Avec Signal, les groupes imposent d'ajouter Sender Keys, un
  mécanisme entièrement distinct.
- **Multi-device natif** : chaque appareil est un membre du groupe. Pas de couche Sesame.
- **PCS de groupe réelle** via TreeKEM, en O(log N) — ce que Sender Keys n'offre pas.

MLS ne fournit ni le *Delivery Service* ni l'*Authentication Service* : les deux sont à
construire.

### Le client

```sh
cd apps/web
pnpm install
pnpm run wasm     # compile crypto-core en WASM et le copie dans public/
pnpm run build && pnpm run preview
```

L'origine de l'API se déclare par `VITE_API_URL` ; à défaut, `http://127.0.0.1:8787`.

#### Pourquoi Vite et non Next

Le projet n'utilisait de Next qu'une seule chose : un middleware posant un nonce CSP par
requête. Pas de rendu serveur — tout est chiffré localement, il n'y a rien à prégénérer —, pas
de route d'API puisque le serveur est en Rust, et une seule page.

Or ce nonce n'était nécessaire **que parce que Next injecte des scripts inline** (amorçage,
streaming RSC). Sans eux, il n'y a rien d'inline à autoriser et `script-src 'self'` suffit — ce
qui est **plus strict** qu'un nonce : `'self'` n'autorise que les fichiers de cette origine, là
où un nonce autorise ce que le serveur désigne. Retirer Next n'a donc pas affaibli la CSP, il
l'a durcie.

Un réglage porte cette propriété et ne doit pas être défait : `build.modulePreload.polyfill`
est à `false` dans `vite.config.ts`. Vite injecte sinon un petit polyfill inline, ce qui
réintroduirait exactement le script inline qu'on vient de supprimer.

La CSP elle-même est **calculée au build** à partir de `VITE_API_URL`, et non écrite dans
`index.html` : une politique en dur et une origine configurable divergent au premier
déploiement, et le symptôme est un « Failed to fetch » émis par le navigateur avant tout envoi
— le serveur ne voit rien, et le message ne désigne pas la cause. `connect-src` y porte les
deux origines, `http(s)://` et `ws(s)://` : la seconde ne se déduit pas de la première, et
n'en garder qu'une couperait la moitié du client sans que l'autre ne le signale.

Ce que rien de tout cela ne corrige, et qu'il faut redire : le serveur livre ce JavaScript et
peut en livrer une version hostile. Aucune politique navigateur ne s'y oppose. Seule une
application dont le code est empaqueté dans le binaire installé ferme cette voie — d'où
`apps/desktop`.

### L'application de bureau

```sh
cd apps/web && pnpm run build            # produit `dist/`, que Tauri empaquette
cargo run -p desktop --release
```

**Ce qui décide d'où vient l'interface est la feature `custom-protocol`, pas le profil de
compilation.** Avec elle, la webview lit les fichiers empaquetés dans le binaire ; sans elle,
elle va chercher `devUrl` — le serveur Vite sur le port 5173 — et affiche « Connection refused »
s'il n'y en a pas. C'est le CLI `tauri build` qui l'ajoute d'ordinaire ; ce projet n'utilisant pas
ce CLI, `apps/desktop/Cargo.toml` la déclare **activée par défaut**, à rebours de la convention :
le cas courant est de lancer l'application, pas de travailler sur son interface.

Pour ce dernier cas, avec rechargement à chaud :

```sh
cd apps/web && pnpm run dev              # sert sur 5173, ce que `devUrl` attend
cargo run -p desktop --no-default-features
```

**C'est ce qui ferme la voie décrite juste au-dessus.** L'interface est dans le binaire
installé : le serveur ne la livre plus, donc il ne peut plus la remplacer. Ce n'est pas le
confort d'une fenêtre native qui justifie cette cible, c'est cela.

Ce que cela déplace plutôt que supprimer : la confiance va désormais au canal de distribution du
binaire. Un binaire substitué annule le bénéfice entier de cette cible — et le fait
silencieusement. C'est à quoi répond la publication vérifiable décrite ci-dessous.

#### Publier et vérifier un binaire

```sh
scripts/release.sh /chemin/vers/cle-privee.pem   # construit, empreinte, signe
scripts/verify-release.sh                        # vérifie, sans aucune clé privée
```

**Reproductible d'abord, signé ensuite.** Une signature dit « quelqu'un détenant cette clé a
produit ce fichier » ; elle ne dit pas « ce fichier correspond à ce code ». L'ordre importe pour
un projet dont la thèse est que l'utilisateur ne devrait pas avoir à croire l'opérateur sur
parole : le binaire est **reproductible**, donc vérifiable en le reconstruisant, sans faire
confiance à quiconque. La signature n'authentifie ensuite que la publication.

La reproductibilité tient à trois `--remap-path-prefix` posés par `scripts/release.sh` — dépôt,
registre Cargo et sysroot. Sans eux, le binaire contenait 217 chemins absolus, et deux
constructions honnêtes du même commit donnaient deux empreintes différentes. Ils sont calculés
par le script et non figés dans un fichier versionné : les y écrire en dur reproduirait le défaut
qu'ils corrigent, en ne valant que pour une machine.

Ed25519 via `openssl`, plutôt que GPG ou minisign : ce projet vérifie déjà des signatures Ed25519
partout — attestations, révocations, rotations, tête du journal. Une seule primitive pour une
seule question.

**Ce que cela ne protège pas**, et qu'il faut dire aussi nettement que le reste :

| Limite | Détail |
|---|---|
| Première installation | Trust on first use, exactement comme l'enregistrement d'un compte : rien ne prouve que la première clé publique rencontrée soit légitime. |
| Clé publique dans le dépôt | Qui contrôle le dépôt peut la remplacer en même temps que le binaire. La seule protection réelle est de comparer son empreinte hors bande — le même geste que la vérification d'empreinte de compte que l'application demande déjà. |
| Vérification manuelle | Sans mécanisme de mise à jour, `verify-release.sh` doit être lancé à la main. Un utilisateur qui ne le lance pas n'est protégé par rien. |
| Fichiers surnuméraires | La vérification contrôle que chaque fichier listé dans `SHA256SUMS` est conforme, pas qu'aucun autre n'a été ajouté à côté. Sans effet sur le binaire lancé, qui est listé. |
| Reproductibilité conditionnelle | Elle vaut **à environnement donné**. Une autre version de `rustc` ou de `pnpm` produit un binaire différent sans que rien ne soit compromis, d'où le fichier `BUILD-INFO` publié avec les empreintes. Vérifié ici entre deux constructions successives sur la même machine ; la reproductibilité entre machines distinctes n'a pas été mesurée. |

La clé privée n'entre jamais dans le dépôt. Pour en produire une :

```sh
openssl genpkey -algorithm ed25519 -out cle-privee.pem
openssl pkey -in cle-privee.pem -pubout -out release/whatsapp_clone.pub
```

Ce que cela ne change pas encore : la cryptographie tourne toujours en WebAssembly dans la
webview, comme sur le web. Les clés privées vivent donc dans la mémoire linéaire du module,
accessible au JavaScript de la page. Les faire passer en Rust natif — où `zeroize` s'applique
vraiment et où le JavaScript n'a aucun accès — demande de rendre asynchrone chaque appel crypto
du client, et reste à faire.

Le mobile passe par la même base de code (Tauri 2 cible iOS et Android), mais n'a pas été
construit : il demande le SDK Android et, pour iOS, un macOS. La webview mobile ne vaudra de
toute façon pas du natif sur les gestes et les notifications.

Les origines `tauri://localhost` et `http://tauri.localhost` figurent dans le défaut
d'`ALLOWED_ORIGINS` côté serveur : elles sont imposées par le système d'exploitation, et les
oublier produirait un « Failed to fetch » que le serveur ne verrait jamais passer.

#### Pièces jointes

Chaque fichier est chiffré côté client avec une **clé AES-256-GCM qui lui est propre**, puis
déposé sur le serveur. La clé ne suit jamais ce chemin : elle voyage dans le message MLS,
donc chiffrée de bout en bout, avec le nom du fichier et son type — tout cela est du contenu,
et le serveur n'a aucune raison de le connaître.

Réutiliser une clé entre fichiers ferait qu'un seul descripteur divulgué les ouvrirait tous.
Une clé par fichier borne les dégâts, et permet de partager une pièce jointe précise sans
donner accès au reste.

Ce qui fuit malgré tout : la **taille**, à seize octets près (le tag GCM). Elle suffit souvent
à identifier un document connu ; seul du padding la masquerait.

Deux précautions côté lecture :

- le fichier est **téléchargé, jamais rendu inline**. Le type MIME vient de l'expéditeur :
  c'est une indication, pas une preuve. Un fichier déclaré `image/png` mais contenant du SVG
  ou du HTML exécuterait du script sur cette origine — à portée des clés dans IndexedDB ;
- le serveur répond `application/octet-stream` + `nosniff` + `Content-Disposition: attachment`,
  pour que le navigateur ne devine rien de son côté.

L'intégrité est portée par l'AEAD : un blob substitué ou altéré fait échouer le déchiffrement
au lieu de rendre des octets falsifiés. Aucune empreinte séparée n'est nécessaire.

#### Vérification d'identité : silence en nominal, alerte sur anomalie

L'interface ne dit **rien** tant que tout va bien. Elle alerte uniquement quand l'empreinte
d'un correspondant change, et propose une comparaison manuelle à la demande.

C'est un choix de sécurité autant que d'ergonomie. Un bandeau permanent « identité non
vérifiée » s'apprend à ignorer en quelques jours ; le jour où il compte vraiment, il est
déjà devenu invisible. C'est pourquoi l'état vérifié est stocké comme **l'empreinte
elle-même** et non comme un booléen : c'est ce qui permet de détecter un changement.

Le silence sur un correspondant jamais vérifié fait un pari — que le premier KeyPackage
servi était bien le sien (trust on first use). Le combler demande de la **key transparency** :
un log Merkle auditable des clés publiques, vérifié automatiquement par le client. C'est ce
que déploient WhatsApp et Apple, et c'est ce qui permet de ne rien demander à l'utilisateur
sans pour autant faire confiance au serveur. Non implémenté ici.

## Comptes multi-appareils

Un compte est une clé Ed25519 (*account identity key*, AIK) dérivée d'une phrase BIP-39 de
douze mots, plus un pseudonyme. Ni numéro de téléphone, ni adresse e-mail, nulle part : la
découverte de contacts par numéro est l'endroit le plus toxique d'un système de messagerie —
même haché, un numéro a un espace énumérable en quelques heures.

**Le problème que résolvent les attestations.** Dès qu'un compte regroupe plusieurs appareils,
quelqu'un doit dire lesquels — et ce quelqu'un est le serveur. Une liste qu'il compose
librement lui suffirait à s'inviter dans toute conversation : le message resterait chiffré de
bout en bout, simplement l'un des bouts serait lui. C'est l'attaque reprochée à WhatsApp en
2019, et elle ne casse aucune ligne de cryptographie.

Chaque appareil porte donc une signature du compte sur `(handle, device_id, auth_key,
mls_key)`, longueur-préfixée pour interdire la confusion de champs. Le client revérifie chaque
attestation à la réception — jamais il ne se fie à la vérification du serveur, puisque c'est
précisément le serveur qu'on soupçonne. Le gain est une asymétrie : **le serveur peut
retrancher un appareil, jamais en ajouter un.**

Le test `un_appareil_fantome_injecte_en_sql_ne_passe_pas_la_verification_du_client` incarne
l'attaquant plutôt que de le simuler : il insère l'appareil directement en base, en
contournant l'endpoint. Le serveur le sert ; le client le rejette.

L'empreinte affichée porte sur la clé du compte, donc **elle ne change pas quand un
correspondant ajoute un téléphone**. Une empreinte qui changerait à chaque événement légitime
serait ignorée en quelques semaines. Les ajouts d'appareils sont signalés séparément.

L'identifiant d'appareil est qualifié par le handle (`alice:desktop`) et le serveur l'impose :
sans cela l'espace de noms serait global et le premier arrivé accaparerait « desktop » pour
tout le monde. Le nom est détecté, jamais demandé.

## Groupes, rôles et retrait

Un groupe est un groupe MLS de plus de deux membres ; une conversation à deux reste **plate**,
sans rôles — une hiérarchie n'y aurait aucun sens.

### Un admin, des modérateurs

Le créateur est l'**admin**, seul et unique. Il nomme des **modérateurs**, qui ajoutent et
retirent des membres ordinaires sans pouvoir toucher aux rôles.

Plusieurs admins de rang égal n'auraient pas de départage : deux d'entre eux peuvent se
rétrograder mutuellement ou se contredire sur la composition du groupe, et rien dans le
protocole ne dit lequel a raison. Une racine unique supprime la question.

| Opération | Qui |
|---|---|
| Ajouter, retirer un membre ordinaire | admin, modérateur |
| Retirer un modérateur | admin |
| Nommer, révoquer, transmettre | admin |
| Retirer l'admin | personne |

### MLS ne fournit aucune autorisation

C'est le point à comprendre. La RFC 9420 décrit qui peut *prouver* quoi, pas qui a le *droit*
de faire quoi : n'importe quel membre peut commiter n'importe quel retrait, et le protocole
l'acceptera.

Les rôles vivent donc dans une **extension de group context** (`0xF100`, plage d'usage privé),
ce qui les rend authentifiés et hachés dans chaque commit — tous les membres s'accordent dessus
par construction, et un vieux roster n'est pas rejouable. Mais l'application de la règle
appartient aux clients : chacun valide le commit reçu avant de le fusionner, et refuse sans
avancer d'un pouce.

Une extension `RequiredCapabilities` accompagne le roster. Ce n'est pas une formalité : elle
interdit à un client **qui ne sait pas lire les rôles** de rejoindre un groupe administré. Sans
elle il entrerait, appliquerait une politique vide, accepterait ce que les autres refusent —
et forkerait le groupe sans que rien ne le signale.

### Retrait, et post-compromise security

C'est la propriété pour laquelle MLS a été choisi, et la seule qui prive réellement un appareil
de la suite. Filtrer côté serveur ne lui retire rien : il détient les secrets du groupe et
déchiffrerait tout ce qu'il obtiendrait par un autre chemin. Le commit de retrait, lui, re-clé
l'arbre en O(log N).

Le test `un_membre_retire_ne_dechiffre_plus_la_suite` le fige : le retiré conserve **tout** son
état de groupe, et échoue quand même à lire le message suivant.

Retirer quelqu'un le retire avec **tous ses appareils** : l'unité est le compte, jamais
l'appareil.

### Quitter un groupe

Le départ est une **demande**, pas un fait. La RFC 9420 interdit de se retirer soi-même dans un
commit qu'on génère — celui-ci se signe sous le secret de l'epoch qu'il produit, précisément
celle dont l'émetteur vient d'être exclu. Un autre membre doit la reprendre, et l'interface le
dit plutôt que de faire disparaître la conversation : quelqu'un qui se croit sorti continue
d'être lu.

Un admin qui part **transmet d'abord** : au rang immédiatement en dessous — un modérateur —
sinon au membre le plus ancien. Un groupe sans admin serait définitivement figé.

Un groupe dont il ne reste qu'un membre est supprimé localement : ce n'est plus une
conversation, et le laisser dans la liste serait promettre un interlocuteur qui n'existe plus.

## Révocation d'appareil et rotation de compte

**Tous les appareils d'un compte détiennent la même graine.** C'est la condition de leur
parité : chacun peut attester, révoquer et lire comme les autres, sans appareil « principal ».

La contrepartie décide de tout le reste.

### Appareil perdu → révocation

La révocation produit un **certificat signé par le compte** (`wac-revoke-v1`), distinct de
l'attestation. Ce n'est pas pour le serveur, qui connaît déjà la clé du compte : c'est pour les
**autres membres des groupes**, qui doivent pouvoir constater la révocation sans nous croire, et
commiter le retrait MLS en conséquence. Sans certificat, le serveur retrouvait le pouvoir de
faire exclure les appareils de son choix.

Les appareils révoqués sont **servis** aux clients, avec leur certificat. Les taire rendrait la
révocation indiscernable d'une omission — et l'omission est ce que le serveur peut encore faire.

N'importe quel membre peut évincer un appareil dont il a vérifié le certificat, sans attendre
un modérateur : c'est précisément le délai que la révocation existe pour supprimer.

### Appareil volé → rotation

**La révocation ne suffit pas.** Le voleur détient la graine, donc le compte : il s'atteste un
appareil neuf dans la seconde.

La rotation change la clé d'identité du compte, signée par l'ancienne. Son effet principal est
mécanique et gratuit : **toutes les attestations existantes deviennent invérifiables**, puisque
chaque client les recalcule contre la clé courante. La révocation totale n'est pas un mécanisme
séparé, c'est une conséquence. L'appareil qui tourne se ré-atteste aussitôt ; les autres devront
être ré-appairés.

Le test `une_rotation_invalide_toutes_les_attestations_existantes` le mesure : 2 appareils
vérifiables → 0 après rotation → 1 après ré-attestation.

Deux prix, annoncés dans l'interface avant l'action et non après : l'empreinte du compte change,
donc tous les correspondants voient l'alerte — elle est exacte. Et **le voleur détient la même
clé et peut tourner le premier** ; le serveur ne peut pas les distinguer et applique la première
rotation valide.

## Journal auditable des clés (key transparency)

Les attestations empêchent le serveur d'**ajouter** un appareil à un compte. Elles ne
l'empêchent pas de mentir sur la clé du compte **au premier contact** : quand on demande le
compte de quelqu'un pour la première fois, on n'a rien à quoi comparer. Le serveur peut servir
sa propre clé et relayer en clair entre deux sessions parfaitement chiffrées.

C'était le dernier vrai trou cryptographique du projet.

### Ce que le journal apporte

Chaque clé publiée entre dans un arbre de Merkle **append-only** (RFC 6962). Le serveur signe
une tête et fournit, à la demande, une preuve d'inclusion et une preuve de cohérence. Le client
vérifie trois choses, et il en faut trois :

1. **Signature de la tête** — elle vient bien du journal.
2. **Inclusion** — la clé servie est celle du journal, recalculée depuis le handle et la clé
   reçus, jamais depuis un hash fourni par le serveur.
3. **Cohérence** — le journal d'aujourd'hui prolonge celui vu hier.

Sans le troisième, le serveur remplace une clé déjà publiée et sert un journal tout aussi
cohérent : les deux premiers passent et le journal ne prouve plus rien sur le passé. Le test
`un_journal_reecrit_ne_passe_pas_la_coherence` le fige.

Les préfixes de domaine `0x00` (feuille) et `0x01` (nœud) de la RFC 6962 ne sont pas une
formalité : sans eux, le hash d'un nœud interne se présente comme une feuille, et un attaquant
fabrique une preuve d'inclusion pour l'entrée de son choix.

### Le gossip, et pourquoi il utilise la conversation elle-même

Aucun des trois contrôles n'attrape un serveur qui tient **deux journaux** et en sert un à
chacun : chaque victime voit un journal signé, cohérent, où sa propre vue est parfaite.

Le détecter demande de comparer deux vues par un canal que le serveur ne contrôle pas. Ce canal
existe déjà — **la conversation chiffrée**. Le serveur en transporte les octets sans pouvoir
les lire ni les modifier.

La comparaison ne confronte pas les racines, qui diffèrent légitimement puisque les tailles
diffèrent : le destinataire demande au serveur de **prouver que son journal prolonge celui
servi à l'autre**. S'il en a servi deux, aucune preuve de cohérence ne relie deux arbres qui
ont bifurqué.

### La faiblesse structurelle, à ne pas masquer

Le journal est signé par la partie qu'il surveille. Un déploiement sérieux le confierait à un
ou plusieurs opérateurs distincts, dont aucun ne serait le serveur de messagerie. Ici il y a un
seul processus, et le gossip est ce qui rattrape partiellement le défaut.

La clé publique du journal est elle-même servie par le serveur — pis-aller assumé. Elle devrait
être livrée avec l'application. Le client refuse au moins qu'elle change en cours de route.

## Métadonnées : rembourrage et sealed sender

### Ce que la taille révélait

Le contenu est chiffré, sa **longueur** ne l'est pas. Elle suffit à distinguer « oui » d'une
phrase, à repérer un mot de passe collé, à reconnaître un message type. Sur une conversation
suivie, la suite des longueurs est une signature.

Les messages sont désormais rembourrés par paliers doublants à partir de 256 octets. « ok »,
« oui » et un texte de 200 caractères produisent **exactement la même taille**. Le doublement
borne le gaspillage sous 100 % et ne laisse au serveur que l'ordre de grandeur.

Le marqueur `0x80` (ISO/IEC 7816-4) plutôt qu'un remplissage par des zéros : un contenu se
terminant légitimement par un zéro serait sinon indistinguable de son rembourrage, et tronqué.

### Sealed sender : prouver l'appartenance, pas l'identité

Chaque enveloppe portait la signature de l'appareil émetteur. Le serveur n'a pourtant jamais eu
besoin de savoir **qui** poste — seulement que le posteur est membre, pour ne pas servir de
boîte aux lettres ouverte. Ce sont deux choses distinctes, et la seconde suffit.

Chaque groupe porte donc une clé de dépôt, partagée par ses membres **via MLS** et connue du
serveur. Poster demande un MAC sous cette clé :

```
HMAC(clé du groupe, "wac-post-v1" ‖ group_id ‖ nonce ‖ SHA256(corps))
```

Le `group_id` empêche de rejouer un dépôt dans un autre groupe. L'empreinte du corps empêche
d'y substituer une autre enveloppe. Le nonce le rend unique, et son unicité est imposée par une
**contrainte de clé primaire** — un contrôle applicatif laisserait une fenêtre de concurrence.

La clé transite par MLS et non par le serveur : la lui faire distribuer reviendrait à lui
demander de diffuser le moyen de ne pas lui parler.

### Ce que cela ne cache pas

L'adresse IP, l'horaire, et le groupe visé. Le serveur détient la clé, donc il peut déposer du
bruit — il ne produira pas de MLS valide, mais il peut polluer. C'est le prix d'un MAC
symétrique ; des jetons à divulgation nulle l'éviteraient, au prix d'une machinerie sans commune
mesure avec ce projet.

## Signalisation : accusés, frappe, présence, réactions

Quatre signaux séparent une démonstration cryptographique d'une messagerie utilisable : savoir si le
message est arrivé, savoir s'il a été lu, savoir si l'autre est en train de répondre, savoir s'il
est là. Ils sont tous générateurs de métadonnées — mais à des degrés si inégaux que les traiter
ensemble serait l'erreur.

### Présence : un registre serveur, et ce qu'il coûte

Ce projet a longtemps refusé la présence, et l'argument n'était pas faux : c'est la seule de ces
quatre fonctions qui oblige *quelqu'un* à tenir un registre transverse aux conversations. Pour
afficher qu'un compte est connecté, il faut savoir qu'il l'est — donc connaître ses horaires de
sommeil, son fuseau, ses absences. Aucune formulation chiffrée ne contourne cela : c'est le routage
lui-même qui l'apprend.

Le registre est désormais tenu, et c'est un choix, pas une dérive. Signal, lui, refuse toujours de
le tenir ; il n'y a pas de parité à revendiquer ici, seulement un compromis assumé et son prix.

**Ce que le serveur détient** : `devices.last_seen_at`, un horodatage par appareil, **tronqué à la
minute**, écrasé à chaque battement. Pas d'historique — une table `presence_log` serait un journal
de déplacements, et l'écrasement est la fonctionnalité, pas un raccourci d'implémentation.

**Ce qui borne la fuite**, et qui est le vrai contenu de la fonctionnalité :

- la colonne est sur l'appareil, mais **n'est jamais servie par appareil à un tiers** : seul le
  maximum par compte sort. Servir le détail dirait combien d'appareils une personne possède et
  lequel elle utilise à quelle heure — une fuite distincte de « en ligne ». Le propriétaire, lui,
  voit ses propres appareils : c'est ce qui rend visible un appareil perdu qui relève toujours ;
- elle n'est écrite que depuis les chemins **authentifiés par identité**. Un dépôt anonyme ou un
  signal de frappe ne la touche jamais : le serveur ne sait pas qui dépose, et l'en déduire
  reviendrait à défaire le sealed sender. Le test
  `un_depot_anonyme_ne_met_jamais_a_jour_la_presence` existe pour que cela le reste — la protection
  tient aujourd'hui à une seule ligne ;
- la lecture exige un **groupe commun**. Sans cette clause, la route serait un oracle d'activité sur
  n'importe quel pseudonyme. Un handle inconnu et un handle sans groupe commun rendent le même
  résultat, faute de quoi elle serait aussi un oracle d'existence de compte ;
- un appareil **révoqué** cesse de compter : un téléphone volé puis révoqué ne doit plus afficher
  son propriétaire éveillé.

**Le réglage coupe à la source.** Le refuser ne masque pas l'affichage : le serveur cesse
d'enregistrer et efface ce qu'il avait noté. Un réglage qui filtrerait seulement à la lecture
laisserait le registre se remplir quand même, c'est-à-dire ne réglerait rien. Il est **réciproque**,
comme celui des accusés de lecture — ne plus diffuser sa présence, c'est aussi cesser de voir celle
des autres, sans quoi il permettrait de voir sans être vu.

**Ce qu'il en coûte quand même**, et qu'aucune de ces bornes ne répare : la présence rétrécit
l'ensemble d'anonymat d'un dépôt anonyme. Si le serveur voit un dépôt dans un groupe à deux et qu'un
seul des deux comptes est éveillé, il conclut. L'inférence existait déjà partiellement — les
abonnements au flux disent qui écoute quel groupe — mais elle était volatile et cantonnée à un
groupe ; elle devient durable et transverse.

### Accusés : cumulatifs, réciproques, et coupés de la boucle

Un accusé annonce « j'ai reçu jusqu'au message N », jamais « j'ai reçu ce message-ci ». Ouvrir une
conversation en retard de deux cents messages coûte donc **une** enveloppe et non deux cents — dans
une table qui n'est jamais purgée, c'est une question de viabilité, pas d'optimisation.

Deux états distincts, et la distinction compte : `reçu` constate qu'un appareil a relevé sa boîte,
`lu` qu'une personne a eu le message à l'écran. Le premier est mécanique et n'est pas désactivable ;
le second engage quelqu'un, et se coupe d'un clic.

**La désactivation est réciproque** : ne plus émettre ses accusés de lecture, c'est aussi cesser de
voir ceux des autres. Sans cette symétrie, le réglage permettrait de voir sans être vu, c'est-à-dire
exactement ce qu'il prétend empêcher. C'est écrit sur l'écran de réglage, pas enfoui ici.

**Le piège, mesuré en fonctionnement :** un accusé est lui-même une enveloppe. Si le curseur qu'on
annonce avance sur toutes les enveloppes — accusés compris — chaque accusé en fait naître un autre.
Observé avant correction : dix enveloppes en quarante secondes, pour deux personnes qui ne disaient
rien. La coupure tient en deux points : `content.isControl()` retire les accusés du fil et du
coffre, et le curseur annoncé (`contentCursor`) n'avance que sur les vrais messages. Un test gèle
la règle.

### Frappe : un second canal, qui ne touche jamais le disque

L'indicateur de frappe **ne passe pas par le ratchet applicatif MLS**, et ce n'est pas un détail
d'implémentation. `envelopes` n'est jamais purgée et ne peut pas l'être : chaque message consomme
une génération du ratchet, et un trou trop large empêcherait de déchiffrer la suite. Faire transiter
la frappe par ce chemin conserverait indéfiniment la trace de qui a commencé à répondre puis s'est
ravisé.

Il emprunte donc un canal distinct :

| | Canal durable | Canal éphémère |
|---|---|---|
| Porte | messages, accusés, réactions, réponses | frappe |
| Chiffrement | ratchet applicatif MLS | AES-256-GCM sous le secret d'export de l'epoch |
| Stockage serveur | `envelopes` | **aucun** — relais en mémoire, jamais le disque |
| Perte d'un élément | rattrapée par le curseur | sans conséquence |

Le dépôt réutilise le MAC d'appartenance du sealed sender, sous un **domaine distinct**
(`wac-signal-mac-v1` contre `wac-post-v1`) : un MAC de signal — dont le rejeu n'est volontairement
pas contrôlé — ne vaut pas comme MAC de dépôt d'enveloppe.

Aucun signal « a cessé d'écrire » n'est émis : un signal de fin pourrait se perdre, et laisserait
l'indicateur allumé indéfiniment. Il s'éteint donc par deux chemins purement locaux — l'arrivée
d'un message de l'auteur, qui est la preuve la plus sûre qu'il a fini et qui ne peut pas s'égarer
puisqu'on ne l'attend pas ; et à défaut l'expiration, trois secondes après le dernier signal reçu.

Cette expiration demande un minuteur côté affichage, et ce n'est pas un détail d'implémentation :
calculer qu'un indicateur est périmé ne sert à rien si personne ne redessine. Or quand quelqu'un
cesse d'écrire, il ne se produit précisément plus rien — pas de signal, pas d'enveloppe. Sans
réveil programmé, l'indicateur restait peint à l'écran jusqu'au prochain événement quelconque,
c'est-à-dire jusqu'à la relève périodique : trente secondes pour une donnée qui en vaut trois.

Bénéfice non planifié : la clé du canal éphémère change à chaque commit. **Un membre retiré perd
l'indicateur de frappe au même instant qu'il perd les messages**, sans une ligne de code
supplémentaire — la PCS s'applique là aussi.

### La gateway : une connexion, tous les groupes

`GET /v1/gateway` (WebSocket) remplace la relève à 1,5 seconde, et a remplacé le flux SSE qui
l'avait précédée. Contre-intuitivement, cela **retire** de l'information au serveur : il recevait
une requête signée par conversation et par tour, soit un journal d'activité à la seconde près. Une
connexion longue le remplace par un seul point d'observation, à l'ouverture. La relève subsiste à
30 secondes pour l'entretien qui n'a pas d'événement déclencheur.

La session n'est **jamais** une dépendance de correction. Chaque trame se contente de dire « va
voir » ; c'est la relève normale qui lit, revérifie l'appartenance et fait avancer le curseur. Un
navigateur qui bloque la connexion laisse l'application entièrement fonctionnelle, seulement moins
réactive. Cette propriété est une contrainte de conception : un transport dont la panne perdrait
des messages serait un transport construit au-dessus du transport.

Trois choses que le flux SSE ne pouvait pas faire, et qui ont chacune un coût réel :

- **s'abonner à un groupe rejoint après l'ouverture.** Le SSE figeait sa liste à la connexion ;
  une trame `subscribe` suffit désormais.
- **rattraper le retard sans relever.** Le client annonce ses curseurs dans son `identify` et le
  serveur ne répond que s'il a quelque chose à dire. Le rattrapage ne sert que des numéros de
  séquence — la lecture passe toujours par le chemin HTTP, qui revérifie l'appartenance.
- **constater qu'un client est parti.** Le keep-alive SSE n'allait que du serveur vers le client.

**Ce que cela change dans le modèle de menace**, et qui coupe dans les deux sens.

*Ce qu'on gagne* : la session s'ouvre sur un défi émis par le serveur, consommé à la première
utilisation. La fenêtre de rejeu de soixante secondes que le HTTP conserve faute de mémoriser ses
nonces n'existe pas ici. Le défi porte son propre domaine de signature (`wac-gateway-v1`), sans
quoi n'importe quelle signature HTTP captée ouvrirait une session.

*Ce qu'on perd* : l'authentification passe de la requête à la session. Une signature par requête
revérifiait gratuitement, à chaque appel, que l'appareil n'était ni révoqué ni évincé. Une session
ouverte, elle, survivrait à l'un comme à l'autre — d'où une revalidation à chaque battement, qui
ferme la socket d'un appareil révoqué et retire les groupes dont il est sorti. Deux tests le
figent.

La trame `signal` reste authentifiée par le MAC de groupe, comme le chemin HTTP : la session
connaît pourtant l'identité de son propriétaire, mais s'en servir défairait le sealed sender pour
la seule commodité de ne pas revérifier un MAC.

Détail qui a dicté l'implémentation, et qui vaut aussi pour l'`EventSource` d'avant : l'API
`WebSocket` du navigateur **n'accepte aucun en-tête**. Y authentifier le handshake imposerait de
mettre la signature dans l'URL, où elle finirait dans les journaux d'accès de tout intermédiaire.
La socket s'ouvre donc sans identité, et rien n'est servi avant le défi — ce qui est aussi ce qui
a permis de supprimer la fenêtre de rejeu, plutôt que de la transporter telle quelle.

### La présence a changé de déclencheur

Elle était un effet de bord de l'extracteur `Signed` : n'importe quelle requête signée marquait
l'appareil éveillé, ce qui plaçait une écriture SQL potentielle sur le chemin de latence de tout
le serveur — pour un point de couleur. Elle est désormais écrite par le battement de la gateway.

C'est un signal plus juste : une session ouverte dit qu'un client est là, là où une requête peut
venir d'un onglet oublié. Mais c'est un **changement de comportement**, pas une optimisation
invisible — un client qui interroge le serveur sans jamais ouvrir de session n'apparaît jamais en
ligne. C'est cohérent, puisqu'il n'est de toute façon pas joignable en temps réel, et un test le
fige.

Sa **lecture** ne passe délibérément pas par la session : le point vert en dépendrait, et une
socket bloquée afficherait alors tout le monde hors ligne. Une interface fausse est pire qu'une
interface en retard. La présence se relève donc sur le même tour de 30 secondes que le reste, et
jamais sur un minuteur à part.

### Plusieurs instances

Le hub de diffusion vivait dans la mémoire d'un seul processus : deux instances derrière un
répartiteur donnaient deux populations de clients qui ne se voyaient pas. Elles se parlent
désormais par `LISTEN/NOTIFY`, sur un canal Postgres unique — la base est déjà là, et la diffusion
est déjà best-effort, ce qui ne justifiait pas d'ajouter un bus à déployer et à surveiller.

Ce que cela ajoute à ce que le serveur sait : rien. Le `group_id` transite en clair dans le
payload, mais il le connaît déjà par `group_members`. Ce qui est nouveau, c'est qu'un déploiement
réglé sur `log_statement = all` verrait passer les signaux dans ses journaux — la propriété « les
signaux n'atteignent jamais le disque » dépend donc désormais d'un réglage de la base, ce qui n'est
pas la même chose qu'être vraie par construction.

### Réactions et réponses

Durables, dans le canal MLS ordinaire. Une réaction **n'est pas** du trafic de protocole : elle
s'affiche, elle s'archive, son auteur l'assume. Elle se replie simplement sur le message visé
plutôt que de produire une bulle, et un emoji vide la retire.

## Verrou local

Le mot de passe chiffre l'état au repos **sur cet appareil**, et rien d'autre. Ce n'est pas un
facteur de récupération : l'oublier ne fait rien perdre définitivement, la phrase de douze mots
reste le seul chemin de restauration. En faire un second facteur du coffre doublerait la surface
de perte pour un gain nul contre le serveur, qui ne voit de toute façon jamais ce mot de passe.

**Argon2id, 64 Mio, 3 passes** — environ une seconde. WebCrypto n'offre que PBKDF2, qui ne coûte
que du calcul : c'est exactement ce qu'un GPU fait par milliards. Le coût *mémoire* d'Argon2id
est ce qui ramène une attaque parallèle au niveau d'un processeur ordinaire. D'où une dérivation
côté Rust plutôt que native.

Le chiffrement passe par une indirection :

```
mot de passe --Argon2id--> clé de déverrouillage --chiffre--> clé maîtresse --chiffre--> état
```

La clé maîtresse est aléatoire et indépendante du mot de passe. Changer celui-ci ne re-chiffre
donc que 32 octets, jamais l'état complet — qui grandit avec les conversations, et qui repasserait
sinon en clair en mémoire au pire moment : celui où l'utilisateur soupçonne une compromission.

Ce que le verrou change par rapport à la clé non-extractable d'IndexedDB : celle-ci protège de
l'exfiltration par script, mais **pas de qui obtient la session du navigateur** — il lui suffit
d'appeler l'API de déchiffrement. Avec le verrou, la clé maîtresse n'existe qu'en mémoire.

**Politique de mot de passe** : longueur minimale et rejet des suites connues, sans règle de
composition. « Une majuscule, un chiffre » ne crée aucune entropie — cela déplace le `A` au début
et le `1!` à la fin, dans un espace que les attaquants connaissent mieux que nous. Le NIST les a
abandonnées dans SP 800-63B.

## Coffre d'historique

**Activé par défaut.** Ce qu'on abandonne ne change pas pour autant : les entrées sont chiffrées
par une clé dérivée de la phrase de récupération, donc **stable pour toujours**. Si cette phrase
fuit un jour, tout le passé sauvegardé fuit avec elle, rétroactivement. Sans coffre, ce passé serait
resté hors d'atteinte — c'est la forward secrecy, et c'est une protection réelle, pas un effet de
bord gênant.

Le compromis a été tranché dans l'autre sens, et il faut dire pourquoi : une messagerie dont la
conversation repart vide à chaque rechargement n'en est pas une. Faire porter ce choix par un écran
de réglage revenait à le refuser pour presque tout le monde, sans que presque personne ne l'ait
décidé. Il est donc pris ici, une fois, et il reste **révocable dans les réglages**.

Ce que cela change dans le reste du document : le paragraphe qui disait « l'activer par défaut le
ferait payer à tous ceux qui n'en ont pas besoin » énonçait la décision inverse. Elle a changé ;
l'argument, lui, reste vrai, et c'est précisément ce qui en fait un compromis plutôt qu'une
amélioration.

Deux conséquences qui suivent du défaut, et qui n'existaient pas quand il était optionnel :

- **la phrase de récupération protège désormais le passé autant que le compte.** Elle est énoncée
  comme telle sur l'écran qui l'affiche, puisque c'est le seul moment où elle est sous les yeux de
  quelqu'un ;
- **la rotation de compte rend l'historique archivé définitivement illisible**, sa clé dérivant de
  l'ancienne phrase. Celui qui tournait sa clé savait autrefois qu'il avait un coffre ; ce n'est
  plus le cas, et l'écran de rotation le dit avant de proposer le bouton.

L'historique revient tout seul à l'ouverture d'une conversation, une fois par session. Cette
restauration **ne fait avancer aucun curseur d'accusé** : un message restauré a déjà été accusé
lors d'une session antérieure, et faire avancer `contentCursor` ferait ré-émettre un accusé à chaque
rechargement — donc renaître la boucle décrite plus haut. C'est le seul chemin par lequel elle peut
revenir.

Chaque compte a **son** coffre, chiffré sous sa propre clé : un message d'une conversation à deux
est stocké deux fois, une par participant. Partager une clé de coffre entre comptes reviendrait à
donner à l'un le pouvoir de lire les sauvegardes de l'autre longtemps après la conversation.

Deux choses que l'interface dit franchement plutôt que de les taire :

- l'archivage **ne remonte pas dans le temps** — les clés des messages déjà échangés sont
  détruites, rien ne permet de les reconstituer ;
- arrêter la sauvegarde **n'efface pas** ce qui a été archivé. Le serveur conserve les entrées, et
  la clé qui les ouvre reste dérivable de la phrase. Promettre une suppression qu'on ne contrôle
  pas serait un mensonge de sécurité.

## Limites connues

Le chiffrement de bout en bout ne résout qu'une partie du problème. Ce qui n'est pas traité
à ce stade, par ordre d'importance réelle :

| Limite | Conséquence |
|---|---|
| **Métadonnées** | La taille des messages est désormais rembourrée par paliers, et l'expéditeur n'est plus identifié au serveur (sealed sender). Restent visibles : **qui appartient à quel groupe, quand un dépôt a lieu, et depuis quelle adresse IP**. Souvent plus révélateur que le contenu ; le masquer demanderait un relais tiers et du trafic factice. |
| **Journal signé par le surveillé** | Le journal auditable existe, mais il est signé par la même partie que celle qu'il surveille. Un déploiement sérieux le confierait à des opérateurs distincts. Le gossip entre clients rattrape partiellement le défaut — il ne l'efface pas. |
| **Clé du journal servie par le serveur** | Le client la découvre auprès du serveur qu'elle est censée surveiller, ce qui ne protège pas d'un serveur malveillant dès le premier contact. Elle devrait être livrée avec l'application. Le client refuse au moins qu'elle change ensuite. |
| **Suppression de compte** | Il n'en existe aucun mécanisme, et c'est délibéré : un journal append-only interdit de retirer une entrée. En supprimer une hors du code fait rétrécir le journal, ce que le gossip signale immédiatement comme une attaque — à juste titre. |
| **Bruit de dépôt** | Le serveur détient la clé de dépôt de chaque groupe : il peut y déposer des enveloppes. Elles ne seront pas déchiffrables — il ne sait pas produire de MLS valide — mais il peut polluer. C'est le prix d'un MAC symétrique. |
| **Rythme des dépôts de frappe** | Le contenu du signal est opaque et n'atteint jamais le disque, mais le serveur voit qu'un dépôt a lieu vers un groupe donné. Dans un tête-à-tête, il en déduit qu'un des deux membres écrit. Le sealed sender cache *qui*, pas *que* — désactiver l'indicateur est la seule protection réelle. |
| **Signaux non authentifiés** | Le canal éphémère est chiffré sous une clé symétrique de groupe. Dans un groupe, un membre peut donc faire croire qu'un autre est en train d'écrire. Sans conséquence à deux, où il n'y a qu'un autre. |
| **Forward secrecy des signaux** | Aucune à l'intérieur d'une epoch : la compromission du secret d'export expose les signaux de cette epoch. Ils n'ont aucune valeur rétrospective et ne sont stockés nulle part — le compromis est délibéré, il évite de faire payer à l'historique le prix d'une donnée jetable. |
| **Accusés et coercition** | Un accusé de lecture prouve qu'un appareil a affiché un message : une information sur le comportement, non sur le contenu. D'où la désactivation, et sa réciprocité. |
| **Authentification par session** | Sur la gateway, la signature vaut pour toute la durée de la connexion et non par requête. Une révocation ou un retrait de groupe ne prend donc effet qu'à la revalidation suivante — au prochain battement du client, ou au tick du serveur pour un client muet. |
| **Signaux et journaux Postgres** | La diffusion inter-instances fait transiter les signaux par `pg_notify`. Ils ne sont écrits dans aucune table, mais un serveur réglé sur `log_statement = all` les verrait dans ses journaux. |
| **Omission d'appareil** | Le serveur ne peut ni *ajouter* un appareil à un compte (attestations) ni *inventer* une révocation (certificats signés). Il peut encore en *omettre* un de la liste, ou taire une révocation authentique. La victime constate qu'un appareil ne reçoit rien : de la censure, bruyante, mais réelle. |
| **Course à la rotation** | Un appareil volé détient la clé du compte et peut tourner avant son propriétaire. Le serveur ne peut pas les distinguer et applique la première rotation valide. Le seul recours est l'alerte de changement d'empreinte chez les correspondants — raison de plus pour ne jamais la banaliser. |
| **Fork applicatif** | MLS n'applique pas les rôles : ce sont les clients. Un client qui n'appliquerait pas la même règle ne produirait pas une erreur mais un *fork* silencieux du groupe. `RequiredCapabilities` empêche un client qui ignore l'extension d'entrer, mais pas un client qui la lit mal. |
| **Retrait et délai** | La post-compromise security commence au **commit**, pas à la révocation. Un serveur qui retarde la livraison du commit de retrait laisse l'exclu lire ce qui a été chiffré entre-temps. Le filtre d'appartenance côté serveur réduit la fenêtre sans la fermer. |
| **Ancienneté approximative** | La succession d'un admin sans modérateur désigne le membre le plus ancien *au sens de l'arbre MLS*. MLS réutilisant les feuilles libérées, un arrivant tardif peut en hériter. Le déterminisme — qui protège du fork — a été préféré à l'exactitude ; la vraie ancienneté demanderait de tenir l'ordre d'arrivée dans le roster. |
| **Suppression de groupe** | Un groupe vidé disparaît du client, mais le serveur garde la boîte. Rien ne prouverait qu'il l'ait réellement effacée ; le prétendre serait pire que de ne rien dire. |
| **Compte compromis** | Un appareil ajouté par un compte dont la phrase a fuité est dûment attesté, donc indiscernable d'un ajout légitime. L'application le signale ; seul l'utilisateur peut dire s'il possède cet appareil. |
| **Coffre d'historique** | Il retire à l'historique la protection de la forward secrecy : la fuite de la phrase devient rétroactivement totale. Il est **actif par défaut**, la contrepartie étant énoncée sur l'écran de la phrase de récupération et rappelée au présent dans les réglages, où il reste débrayable. |
| **Historique orphelin** | Après récupération par phrase, le coffre est lisible mais les groupes correspondants n'apparaissent nulle part : le client ne connaît que les conversations dont son état MLS porte la trace. La promesse « survit à la perte de tous les appareils » n'est donc pas encore tenue. La tenir demanderait une route listant les groupes archivés et des conversations en lecture seule. |
| **Rotation et coffre** | Tourner la clé du compte rend l'historique déjà archivé définitivement illisible. L'écran de rotation l'annonce ; rien ne permet de le rechiffrer. |
| **Registre de présence** | Le serveur détient l'heure de dernière activité de chaque appareil. C'est un registre transverse aux conversations — horaires d'éveil, fuseau, absences — qu'aucune formulation chiffrée n'évite. Débrayable, et alors non enregistré. |
| **Présence et sealed sender** | La présence rétrécit l'ensemble d'anonymat d'un dépôt anonyme : un dépôt dans un groupe à deux dont un seul membre est éveillé se laisse attribuer. |
| **Précision de la présence** | La troncature à la minute borne ce que voient les *clients*, pas ce que sait le serveur : il observe de toute façon l'instant exact de chaque requête. |
| **Backups** | Non implémentés. Un backup en clair annule intégralement le E2EE ; c'est l'échec le plus courant en production. |
| **Post-quantique** | Pas de PQXDH ni de ratchet PQ. Vulnérable au *harvest-now-decrypt-later*. |
| **Le web** | Le serveur livre le JS à chaque chargement et peut donc livrer une version qui exfiltre les clés. Aucune quantité de WebCrypto ne corrige ça — seule une application native ou une extension signée le fait. |
| **Liste de mots de passe** | La liste des mots de passe rejetés est courte : elle attrape les cas manifestes, pas plus. Un déploiement réel utiliserait les 10 000 premiers de rockyou, ou l'API k-anonyme de Have I Been Pwned. |
| **Estimation d'entropie** | Le nombre de bits affiché suppose des caractères tirés au hasard, ce qu'un humain ne fait jamais. C'est un plafond optimiste, présenté comme tel ; un vrai estimateur (zxcvbn) reconnaît mots et substitutions, au prix de 400 Ko. |
| **Verrou et mémoire** | Une fois déverrouillé, l'état est en clair en mémoire jusqu'à la fermeture de l'onglet. Il n'y a pas de re-verrouillage après inactivité. |
| **Volume du coffre** | Le serveur apprend combien de messages chaque compte archive et quand. Il savait déjà qui parle à qui ; ceci ajoute un volume et une chronologie. Cette fuite n'est plus subie par une minorité qui l'a choisie : elle est le régime normal. L'éviter demanderait du padding et des dépôts factices. |
| **Suppression du coffre** | Aucun endpoint d'effacement. Même s'il en existait un, rien ne prouverait que le serveur a réellement supprimé les copies. |
| **Endpoint compromis** | Hors périmètre par nature. Un appareil compromis lit les messages déchiffrés. |

## Développement

```sh
cargo test --release                      # voir l'avertissement ci-dessous
cargo clippy --all-targets
wasm-pack test --node crates/crypto-wasm  # tests dans l'environnement WASM
wasm-pack build --target web --release --out-dir pkg crates/crypto-wasm
```

Le binaire WASM fait **1,5 Mo brut / 512 Ko gzip**. Servez-le compressé et avec un cache
long : c'est un coût utilisateur direct à chaque premier chargement.

`crypto-wasm` active manuellement `getrandom` 0.2 avec sa feature `js`. `openmls/js` ne
couvre que getrandom 0.3, mais les crates à courbes elliptiques d'OpenMLS tirent encore la
0.2. Sans cette activation, la compilation wasm32 échoue — ce qui est heureux : un aléa
défaillant ne lève aucune erreur, il produit des clés prévisibles en silence. Le test
`l_alea_du_navigateur_fonctionne` verrouille ce point.

### ⚠️ Toujours tester et déployer en release

OpenMLS 0.8.1 exécute un `debug_assert!(false)` avant de retourner l'erreur de déchiffrement
(`framing/private_message_in.rs:136`). En build **debug**, un message altéré en transit fait
donc paniquer le processus au lieu d'être rejeté proprement : c'est un déni de service à
distance déclenchable en modifiant un seul octet.

En release, `debug_assert!` disparaît et l'erreur remonte normalement. Le test
`ciphertext_altere_rejete` est donc ignoré en debug et ne vaut qu'en release.

**Ne jamais déployer un build debug de ce code.**

### Responsabilités qui n'appartiennent pas à la bibliothèque

OpenMLS n'empêche pas la réutilisation d'un KeyPackage (test
`la_reutilisation_de_key_package_doit_etre_empechee_par_le_serveur`). Or leur clé
d'initialisation est à usage unique : la resservir détruit la forward secrecy de l'ajout.
**Le serveur doit retirer chaque KeyPackage du stock dès qu'il est servi** et signaler
l'épuisement du stock d'un appareil.

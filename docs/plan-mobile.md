# Plan d'exécution — adaptation mobile

Synthèse de six spécifications produites en parallèle. Ce document arbitre **l'ordre** et
**ce qui peut avancer en même temps** ; le détail de chaque domaine est dans les specs.

## Ce que la conception a révélé, et qui n'était pas dans l'énoncé

Trois découvertes changent le plan par rapport à la liste de départ.

**Le stockage ne se limite pas à l'état MLS.** `keys.auth` — la clé de signature de l'appareil —
est au moins aussi mortelle à perdre, et pire : elle est non extractable et le serveur **refuse**
d'en changer (`register_device` compare `auth_key`). Un état MLS sauvé nativement dont la clé
d'authentification a disparu avec IndexedDB ne sert à rien : l'appareil ne peut plus émettre une
seule requête. Toute solution qui laisse quelque chose de vital dans IndexedDB est incomplète par
construction.

**Le bouton retour Android ne demande aucun code natif.** `wry` installe déjà un gestionnaire qui
consomme l'historique de la webview avant de terminer l'activité. Une pile d'écrans alimentée par
`history.pushState` suffit — pas de plugin, pas de commande Rust, pas de `gen/android` versionné.
C'était l'inconnue la plus coûteuse du lot ; elle tombe.

**Le push affaiblit le sealed sender.** Pas par ses jetons — par son existence. Un serveur qui
choisit *qui* réveiller obtient un déclencheur d'activité ciblé : cesser de réveiller quatre
membres sur cinq rend les dépôts suivants attribuables au cinquième. Le sealed sender protège
d'un serveur qui observe, pas d'un serveur qui **cadence**. Rien de cryptographique n'y répond.
C'est le prix de la fonctionnalité, à écrire dans le README, et une raison de plus de la rendre
strictement optionnelle.

## Deux défauts déjà corrigés

La revue a trouvé, dans du code écrit aujourd'hui, deux bugs qui n'attendaient pas le mobile :

- **La présence mentait.** Elle s'écrivait au tick du serveur et non à la réception d'un
  battement : une socket abandonnée par un téléphone suspendu déclarait son propriétaire éveillé
  pendant tout `SILENCE_MAX`, et la fenêtre d'affichage du client prolongeait encore. Corrigé
  (`2c7b57c`).
- **Les actions de message sont inatteignables au doigt** (`hidden group-hover:flex`). Réagir et
  répondre sont **impossibles** sur mobile. Ce n'est pas du polissage, c'est une fonction absente.
  À corriger dans le lot 1.

## Prérequis bloquant

`apps/desktop` n'a ni `lib.rs`, ni `[lib]`, ni `#[cfg_attr(mobile, tauri::mobile_entry_point)]`.
Tauri 2 en a besoin pour que Gradle trouve une `cdylib`. **Rien de ce plan n'a de sens tant que
`cargo tauri android build` n'a pas abouti au moins une fois.** Vérification en cours.

## Lots, et ce qui les sépare

Le conflit n'est pas là où on l'attendait. `session.ts` (2 100 lignes) est le point de convergence
de trois lots, mais leurs zones y sont disjointes : le stockage touche constructeur, `create`,
`restore`, `persist` ; le cycle de vie ajoute des méthodes ; le push branche un rappel. **Le vrai
point de contention est `App.tsx`**, que la navigation remanie entièrement.

D'où la règle d'ordonnancement : le lot navigation commence par une **extraction mécanique** de
`App.tsx` vers `components/ConversationList.tsx` et `components/Conversation.tsx`, sans aucun
changement de comportement, poussée seule. Elle coûte un conflit de renommage unique et immédiat,
puis retire durablement `App.tsx` du chemin de tout le monde.

| Lot | Domaine | Dépend de | Parallélisable avec |
|---|---|---|---|
| 0 | Extraction d'`App.tsx` + `platform.ts` + variantes CSS | — | rien : à pousser seul |
| 1 | Navigation, zones sûres, clavier, cibles tactiles | 0 | 2, 3 |
| 2 | Stockage natif et clé d'appareil | 0, prérequis mobile | 1, 3 |
| 3 | Cycle de vie et état hors ligne | 0 | 1, 2 |
| 4 | Verrouillage biométrique | 2 (le cipher), 3 (le reverrouillage) | 5 |
| 5 | Appairage par QR | 1 (navigation), prérequis mobile | 4 |
| 6 | Notifications push | 2, 3 | — |

**Trois fichiers doivent être créés par le lot 0 et par personne d'autre** : `platform.ts`
(`isTauri()`), les variantes Tailwind `duo:` / `tactile:`, et `viewport.ts`. Trois lots en ont
besoin ; deux versions concurrentes coûteraient plus cher que l'attente.

## Ordre recommandé

**D'abord le lot 2 (stockage).** C'est le seul de la liste qui peut faire **perdre des données**,
et il est plus petit qu'il n'en a l'air : `sign`, `wrapState` et `unwrapState` sont **déjà
asynchrones** et n'ont que quatre appelants. Les remplacer par un aller-retour IPC ne propage
aucun refactor — l'inverse exact du portage de la crypto MLS, écarté plus tôt précisément parce
qu'il aurait tout contaminé.

**Puis 1 et 3 en parallèle**, sur des fichiers désormais disjoints grâce au lot 0.

**Le lot 4 après 3**, pour une raison qui n'est pas d'ordonnancement mais de sens : aujourd'hui le
verrou n'agit qu'au démarrage à froid. Sans reverrouillage en arrière-plan, la biométrie ajoute du
confort à une porte qui reste ouverte.

**Le lot 6 en dernier**, et pas seulement parce qu'il est gros : il exige des secrets APNs et FCM,
un plugin natif dans deux langages, et il porte la seule décision qui **dégrade** une propriété du
projet. Il doit rester inerte sans configuration — un déploiement auto-hébergé qui refuse de
parler à Apple et Google doit rester pleinement fonctionnel.

## Ce qui n'est pas résolu et ne le sera pas par ce plan

- **La migration n'aura aucune couverture automatique.** Le harnais (`node --test`, sans DOM) ne
  peut tester ni IndexedDB ni l'IPC. Le code le plus dangereux du lot — celui qui ne s'exécute
  qu'une fois par installation et dont l'échec est irréversible — sera vérifié à la main.
- **Sur iOS, la notification n'affichera jamais le contenu.** L'extension de service est un
  processus Swift séparé ; les clés vivent dans un module WASM à l'intérieur de la webview.
  Corriger cela demanderait le portage de la crypto en natif.
- **Aucun appareil physique ici.** L'invalidation biométrique par ré-enrôlement, l'encoche réelle,
  `windowSoftInputMode` : trois choses qu'aucun émulateur ne tranche honnêtement.
- **Android sans services Google n'aura pas de réveil.** UnifiedPush serait la réponse ; non
  spécifié.

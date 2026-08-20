import assert from "node:assert/strict";
import { test } from "node:test";

import { ONLINE_WINDOW_MS, describePresence, isOnline } from "./presence.ts";

const MAINTENANT = Date.now();

test("un compte vu dans la fenêtre est en ligne", () => {
  assert.equal(isOnline(MAINTENANT - 1000, MAINTENANT), true);
  assert.equal(describePresence(MAINTENANT - 1000, MAINTENANT), "en ligne");
});

test("la borne est stricte : à la fenêtre exacte, le compte est hors ligne", () => {
  assert.equal(isOnline(MAINTENANT - ONLINE_WINDOW_MS + 1, MAINTENANT), true);
  assert.equal(isOnline(MAINTENANT - ONLINE_WINDOW_MS, MAINTENANT), false);
});

test("hors de la fenêtre, l'heure de la dernière activité s'affiche", () => {
  const vu = MAINTENANT - ONLINE_WINDOW_MS - 60_000;
  assert.match(describePresence(vu, MAINTENANT), /^vu (à \d\d:\d\d|le )/);
});

/**
 * Ne pas savoir n'est pas la même chose que savoir absent. Le compte peut n'avoir jamais été vu,
 * ou avoir refusé de diffuser sa présence — trancher à sa place serait le premier mensonge de
 * l'écran.
 */
test("sans donnée, rien ne s'affiche — surtout pas « hors ligne »", () => {
  assert.equal(describePresence(undefined, MAINTENANT), "");
  assert.equal(isOnline(undefined, MAINTENANT), false);
});

/**
 * Deux horloges se comparent, et elles divergent : c'est la raison d'être de `MAX_CLOCK_SKEW`
 * côté serveur. « Vu dans trois minutes » serait la seule autre réponse possible.
 */
test("un horodatage dans le futur vaut « en ligne », jamais « vu dans trois minutes »", () => {
  assert.equal(describePresence(MAINTENANT + 180_000, MAINTENANT), "en ligne");
});

/** C'est l'horloge du serveur qui décide, pas celle du navigateur. */
test("la référence est le maintenant du serveur", () => {
  const serveur = MAINTENANT - 10 * ONLINE_WINDOW_MS;
  assert.equal(isOnline(serveur - 1000, serveur), true);
  assert.equal(isOnline(serveur - 1000, MAINTENANT), false);
});

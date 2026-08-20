import assert from "node:assert/strict";
import { test } from "node:test";

import {
  TYPING_DEBOUNCE_MS,
  TYPING_TTL_MS,
  fresh,
  nextExpiry,
  without,
  type Typing,
} from "./signals.ts";

const T0 = 1_000_000;

test("le seuil d'émission ne dépasse pas la moitié du TTL", () => {
  // Au-delà, la dernière émission peut expirer avant la suivante : l'indicateur clignote.
  assert.ok(TYPING_DEBOUNCE_MS * 2 <= TYPING_TTL_MS);
});

test("un indicateur expire au bout du TTL, pas avant", () => {
  const typing: Typing[] = [{ handle: "alice", at: T0 }];

  assert.equal(fresh(typing, T0 + TYPING_TTL_MS - 1).length, 1);
  assert.equal(fresh(typing, T0 + TYPING_TTL_MS).length, 0);
});

/**
 * **Le test qui empêche l'indicateur de rester allumé.** L'expiration ne s'évalue qu'au rendu,
 * et rien ne provoque de rendu quand quelqu'un cesse d'écrire. Sans ce délai, l'affichage
 * n'apprend la péremption qu'au prochain événement quelconque — jusqu'à trente secondes plus
 * tard.
 */
test("le délai d'expiration vise la plus ancienne entrée", () => {
  const typing: Typing[] = [
    { handle: "alice", at: T0 },
    { handle: "bob", at: T0 + 500 },
  ];

  assert.equal(nextExpiry(typing, T0), TYPING_TTL_MS);
  assert.equal(nextExpiry(typing, T0 + 1000), TYPING_TTL_MS - 1000);
});

test("sans indicateur, aucun réveil n'est programmé", () => {
  assert.equal(nextExpiry([], T0), undefined);
});

test("une entrée déjà expirée demande un rendu immédiat, jamais un délai négatif", () => {
  const typing: Typing[] = [{ handle: "alice", at: T0 }];
  assert.equal(nextExpiry(typing, T0 + TYPING_TTL_MS * 10), 0);
});

/**
 * Ce que fait `absorb` quand un message arrive : l'envoi prouve que son auteur a fini d'écrire.
 * Sans cela, l'expéditeur paraît continuer d'écrire pendant tout le TTL après avoir envoyé.
 */
test("retirer un correspondant ne touche pas les autres", () => {
  const typing: Typing[] = [
    { handle: "alice", at: T0 },
    { handle: "bob", at: T0 },
  ];

  assert.deepEqual(without(typing, "alice"), [{ handle: "bob", at: T0 }]);
  assert.deepEqual(without(typing, "carol"), typing);
});

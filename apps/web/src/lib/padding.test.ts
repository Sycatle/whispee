/**
 * Le rembourrage est réversible ou il ne sert à rien : une erreur ici rend les messages
 * illisibles, pas seulement moins privés.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { pad, unpad } from "./padding.ts";

test("tout contenu survit à un aller-retour", () => {
  for (const length of [0, 1, 2, 255, 256, 257, 511, 512, 513, 1024, 5000]) {
    const body = new Uint8Array(length).map((_, i) => (i * 7) % 256);
    assert.deepEqual(unpad(pad(body)), body, `longueur ${length}`);
  }
});

/** Le point du dispositif : les messages écrits courants deviennent indiscernables. */
test("les messages courts ont tous la même taille", () => {
  const tailles = new Set(
    ["ok", "oui", "je te rappelle dans dix minutes", "a".repeat(200)].map(
      (texte) => pad(new TextEncoder().encode(texte)).length,
    ),
  );
  assert.equal(tailles.size, 1);
  assert.equal([...tailles][0], 256);
});

/** Le gaspillage reste borné : c'est ce qui rend le doublement acceptable. */
test("le rembourrage ne double jamais la taille", () => {
  for (let length = 256; length < 20000; length += 37) {
    assert.ok(pad(new Uint8Array(length)).length < length * 2 + 256);
  }
});

/**
 * Un contenu se terminant par des zéros est le cas que le marqueur existe pour couvrir : sans
 * lui, ces zéros seraient pris pour du rembourrage et le message serait tronqué.
 */
test("un contenu terminé par des zéros est restitué intact", () => {
  const body = new Uint8Array([1, 2, 3, 0, 0, 0]);
  assert.deepEqual(unpad(pad(body)), body);
});

test("un rembourrage mal formé est refusé plutôt que deviné", () => {
  assert.throws(() => unpad(new Uint8Array(256)));
  assert.throws(() => unpad(new Uint8Array([1, 2, 3])));
});

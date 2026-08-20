import assert from "node:assert/strict";
import { test } from "node:test";

import { decode, encode, isControl } from "./content.ts";

test("un accusé fait l'aller-retour", () => {
  const rendu = decode(encode({ kind: "receipt", state: "read", seq: 4200 }));
  assert.deepEqual(rendu, { kind: "receipt", state: "read", seq: 4200 });
});

test("les deux états d'accusé sont distincts", () => {
  const livre = decode(encode({ kind: "receipt", state: "delivered", seq: 1 }));
  const lu = decode(encode({ kind: "receipt", state: "read", seq: 1 }));
  assert.notDeepEqual(livre, lu);
});

test("une réaction et une réponse ne se confondent pas malgré leur format commun", () => {
  const reaction = decode(encode({ kind: "reaction", target: 12, emoji: "👍" }));
  const reponse = decode(encode({ kind: "reply", target: 12, text: "👍" }));

  assert.deepEqual(reaction, { kind: "reaction", target: 12, emoji: "👍" });
  assert.deepEqual(reponse, { kind: "reply", target: 12, text: "👍" });
});

test("un emoji vide encode le retrait d'une réaction", () => {
  assert.deepEqual(decode(encode({ kind: "reaction", target: 3, emoji: "" })), {
    kind: "reaction",
    target: 3,
    emoji: "",
  });
});

/**
 * **Le test qui empêche la boucle infinie.** Un accusé est lui-même une enveloppe : s'il
 * n'est pas reconnu comme trafic de protocole, chacun accuse réception de l'accusé de
 * l'autre et la conversation ne s'arrête plus jamais.
 */
test("un accusé est du trafic de protocole, une réaction n'en est pas", () => {
  assert.equal(isControl({ kind: "receipt", state: "read", seq: 1 }), true);
  assert.equal(isControl({ kind: "reaction", target: 1, emoji: "🙂" }), false);
  assert.equal(isControl({ kind: "reply", target: 1, text: "oui" }), false);
  assert.equal(isControl({ kind: "text", text: "bonjour" }), false);
});

test("un accusé tronqué est refusé plutôt qu'interprété", () => {
  const complet = encode({ kind: "receipt", state: "read", seq: 9 });
  assert.throws(() => decode(complet.subarray(0, complet.length - 1)));
});

test("une référence de message tronquée est refusée", () => {
  assert.throws(() => decode(new Uint8Array([5, 0, 0, 0])));
});

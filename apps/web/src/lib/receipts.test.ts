import assert from "node:assert/strict";
import { test } from "node:test";

import { pending, record, statusOf, type ReceiptBook } from "./receipts.ts";

test("un accusé qui recule n'écrase pas un curseur plus avancé", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 10);
  record(book, "bob", "read", 4);
  assert.equal(book.get("bob")?.read, 10);
});

test("lire implique avoir reçu", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 7);
  assert.deepEqual(book.get("bob"), { delivered: 7, read: 7 });
});

/**
 * **Le test qui empêche la conversation de ne plus s'arrêter.** Une fois l'accusé émis pour
 * un curseur, il ne doit plus rien y avoir à émettre pour ce même curseur.
 */
test("rien n'est à émettre quand le compte a déjà accusé ce numéro", () => {
  const book: ReceiptBook = new Map();

  assert.equal(pending(book, "alice", "read", 5), 5);
  record(book, "alice", "read", 5);
  assert.equal(pending(book, "alice", "read", 5), undefined);
  assert.equal(pending(book, "alice", "read", 6), 6);
});

test("le second appareil d'un compte n'émet pas un accusé déjà émis par le premier", () => {
  const book: ReceiptBook = new Map();

  // Le premier appareil émet ; l'accusé revient à tous les membres, dont le second appareil.
  record(book, "alice", "delivered", 12);

  assert.equal(pending(book, "alice", "delivered", 12), undefined);
});

test("un message n'est lu que lorsque tous les correspondants l'ont lu", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 3);
  record(book, "carol", "delivered", 3);

  assert.equal(statusOf(book, ["bob", "carol"], 3, true), "delivered");

  record(book, "carol", "read", 3);
  assert.equal(statusOf(book, ["bob", "carol"], 3, true), "read");
});

/** La réciprocité : désactiver ses accusés de lecture, c'est aussi cesser de voir ceux des autres. */
test("sans accusés de lecture, l'état s'arrête à reçu", () => {
  const book: ReceiptBook = new Map();
  record(book, "bob", "read", 3);

  assert.equal(statusOf(book, ["bob"], 3, false), "delivered");
});

test("un message que personne n'a encore relevé reste au stade envoyé", () => {
  assert.equal(statusOf(new Map(), ["bob"], 1, true), "sent");
});

/**
 * **Le test qui empêche la conversation de ne plus s'arrêter.**
 *
 * Un accusé est lui-même une enveloppe. Si le curseur qu'on accuse avance sur les accusés,
 * chaque accusé en fait naître un autre. Ce test fige la règle : seul un curseur qui ne bouge
 * que sur les vrais messages peut être annoncé.
 *
 * Le cas a été observé en fonctionnement avant correction — dix enveloppes en quarante
 * secondes, pour deux personnes qui ne disaient rien.
 */
test("un curseur figé ne produit plus d'accusé, même après plusieurs tours", () => {
  const book: ReceiptBook = new Map();
  const curseurDeContenu = 3;

  let emissions = 0;
  for (let tour = 0; tour < 10; tour += 1) {
    const du = pending(book, "alice", "delivered", curseurDeContenu);
    if (du === undefined) continue;
    record(book, "alice", "delivered", du);
    emissions += 1;
  }

  assert.equal(emissions, 1, "un accusé par message reçu, pas un par tour de relève");
});

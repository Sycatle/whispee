import assert from "node:assert/strict";
import { test } from "node:test";

import { decoderSession, encoderSession, type SessionSansCles } from "./session-codec.ts";

function session(ajouts: Partial<SessionSansCles> = {}): SessionSansCles {
  return {
    deviceId: "appareil-1",
    handle: "alice",
    accountSeed: new Uint8Array([1, 2, 3, 4]),
    groupIds: [],
    verified: {},
    cursors: {},
    knownDevices: {},
    ...ajouts,
  };
}

const allerRetour = (valeur: SessionSansCles) => decoderSession(encoderSession(valeur));

test("une session complète se relit à l'identique", () => {
  const original = session({
    lock: { salt: "c2Vs", wrapped: "Y2xl" },
    vaultEnabled: true,
    state: new Uint8Array([9, 8, 7]),
    groupIds: [new Uint8Array([1]), new Uint8Array([2, 3])],
    verified: { bob: "empreinte" },
    cursors: { "0a0b": 42 },
    knownDevices: { bob: ["appareil-2"] },
    signals: { readReceipts: true, typingIndicator: false, presence: true },
    postingKeys: { "0a0b": "cle" },
  });

  assert.deepEqual(allerRetour(original), original);
});

/**
 * **Le test qui porte la propriété du module.**
 *
 * Absent vaut actif, `false` est un refus. Les confondre rallumerait la sauvegarde d'historique
 * dans le dos de quelqu'un qui l'avait coupée — sans rien afficher qui le signale.
 */
test("vaultEnabled distingue l'absence du refus", () => {
  const neuf = allerRetour(session());
  assert.equal(neuf.vaultEnabled, undefined);
  // Absente, et non présente valant `undefined` : la session relue doit avoir exactement la forme
  // de celle qui a été écrite, sinon une comparaison structurelle ou un `in` répondrait faux.
  assert.ok(!("vaultEnabled" in neuf));
  assert.equal(allerRetour(session({ vaultEnabled: false })).vaultEnabled, false);
  assert.equal(allerRetour(session({ vaultEnabled: true })).vaultEnabled, true);
});

/** Même distinction, un cran plus bas : `presence` absent vaut activé. */
test("presence distingue l'absence du refus", () => {
  const sans = allerRetour(session({ signals: { readReceipts: true, typingIndicator: true } }));
  assert.equal(sans.signals?.presence, undefined);

  const refus = allerRetour(
    session({ signals: { readReceipts: true, typingIndicator: true, presence: false } }),
  );
  assert.equal(refus.signals?.presence, false);
});

/**
 * Les octets survivent au-delà de 127.
 *
 * L'encodage passe par `String.fromCharCode` puis `btoa` : un octet traité comme un point de code
 * UTF-16 se briserait au-dessus de 127. La graine du compte est aléatoire, donc la moitié de ses
 * octets tombe dans cette zone — la panne serait immédiate et totale, mais seulement en
 * production.
 */
test("les octets hauts traversent intacts", () => {
  const seed = new Uint8Array(256).map((_, i) => i);
  assert.deepEqual(allerRetour(session({ accountSeed: seed })).accountSeed, seed);
});

/** Un état absent n'est pas un état vide : le premier signifie « pas encore de MLS ». */
test("un état absent se distingue d'un état vide", () => {
  assert.equal(allerRetour(session()).state, undefined);
  assert.deepEqual(allerRetour(session({ state: new Uint8Array() })).state, new Uint8Array());
});

test("une version inconnue est refusée", () => {
  const futur = new TextEncoder().encode(JSON.stringify({ v: 99, deviceId: "x" }));
  assert.throws(() => decoderSession(futur), /version 99/);
});

/**
 * Un champ requis manquant lève, plutôt que de rendre une session amputée.
 *
 * Un curseur perdu fait rejouer des clés MLS déjà consommées : la conversation reste vide après
 * un rechargement, sans qu'aucune erreur ne l'explique.
 */
test("un champ requis manquant lève", () => {
  const octets = encoderSession(session());
  const brut = JSON.parse(new TextDecoder().decode(octets));
  delete brut.cursors;

  assert.throws(
    () => decoderSession(new TextEncoder().encode(JSON.stringify(brut))),
    /cursors/,
  );
});

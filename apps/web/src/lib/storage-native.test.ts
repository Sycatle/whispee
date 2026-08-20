import assert from "node:assert/strict";
import { test } from "node:test";

import { NativeStore, type PontSession } from "./storage-native.ts";
import type { StoredSession } from "./storage.ts";
import type { DeviceCipher } from "./cipher.ts";

/**
 * Un chiffrement factice, mais **pas transparent** : il décale chaque octet.
 *
 * Un faux qui rendrait le clair laisserait passer un store qui oublie de sceller — la panne
 * exacte qu'on veut interdire, puisqu'elle écrirait l'état MLS en clair sur le disque sans que
 * rien ne le signale.
 */
function cipherFactice(): DeviceCipher & { vuEnClair: boolean } {
  const decaler = (octets: Uint8Array, sens: number) =>
    Uint8Array.from(octets, (octet) => (octet + sens + 256) % 256);

  return {
    vuEnClair: false,
    authPublicKey: () => Promise.resolve(new Uint8Array([1])),
    sign: () => Promise.resolve(""),
    seal: (clair) => Promise.resolve(decaler(clair, 1)),
    open: (blob) => Promise.resolve(decaler(blob, -1)),
  };
}

function pontMemoire(): PontSession & { contenu: string | null } {
  return {
    contenu: null,
    charger() {
      return Promise.resolve(this.contenu);
    },
    enregistrer(contenu: string) {
      this.contenu = contenu;
      return Promise.resolve();
    },
    effacer() {
      this.contenu = null;
      return Promise.resolve();
    },
  };
}

function session(ajouts: Partial<StoredSession> = {}): StoredSession {
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

test("une session enregistrée se relit à l'identique", async () => {
  const pont = pontMemoire();
  const store = new NativeStore(cipherFactice(), pont);

  const original = session({
    state: new Uint8Array([9, 8, 7]),
    cursors: { "0a0b": 3 },
    vaultEnabled: false,
  });
  await store.save(original);

  assert.deepEqual(await store.load(), original);
});

/**
 * **Le test qui porte la propriété du module.**
 *
 * Ce qui atteint le pont ne doit rien laisser voir. Le handle est en clair côté serveur, mais
 * l'état MLS ne l'est nulle part — et un store qui oublierait de sceller écrirait tout sur le
 * disque sans qu'aucun autre test ne s'en aperçoive.
 */
test("rien n'atteint le disque en clair", async () => {
  const pont = pontMemoire();
  await new NativeStore(cipherFactice(), pont).save(session({ handle: "alice" }));

  assert.ok(pont.contenu !== null);
  assert.ok(!atob(pont.contenu).includes("alice"), "le contenu a été écrit sans être scellé");
});

/** Un premier lancement rend `undefined`, et non une session vide. */
test("l'absence de fichier n'est pas une session", async () => {
  assert.equal(await new NativeStore(cipherFactice(), pontMemoire()).load(), undefined);
});

test("l'effacement rend le stockage vierge", async () => {
  const pont = pontMemoire();
  const store = new NativeStore(cipherFactice(), pont);

  await store.save(session());
  await store.clear();

  assert.equal(await store.load(), undefined);
});

/**
 * Un blob illisible lève, plutôt que de passer pour une installation neuve.
 *
 * Les deux situations demandent des réponses opposées : l'une crée un compte, l'autre alerte.
 * Les confondre effacerait un compte au lieu de signaler un disque en panne.
 */
test("un blob corrompu ne passe pas pour un premier lancement", async () => {
  const pont = pontMemoire();
  pont.contenu = btoa("des octets qui ne sont pas une session");

  await assert.rejects(() => new NativeStore(cipherFactice(), pont).load());
});

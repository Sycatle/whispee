import assert from "node:assert/strict";
import { test } from "node:test";

import type { Message } from "./session.ts";
import { decryptEntry, encryptEntry, importVaultKey, merge, restore, store } from "./vault.ts";
import type { VaultApi } from "./vault.ts";

const GROUP = new Uint8Array([1, 2, 3, 4]);

function key(): Promise<CryptoKey> {
  return importVaultKey(new Uint8Array(32).fill(7));
}

function message(seq: number): Message {
  return { seq, sender: "alice", mine: false, content: { kind: "text", text: `n°${seq}` } };
}

/** Transport factice : enregistre les lots déposés, sert des pages à la demande. */
function faux(pages: { seq: number; payload: Uint8Array }[][] = []): VaultApi & {
  lots: number[];
  demandes: number[];
} {
  const lots: number[] = [];
  const demandes: number[] = [];

  return {
    lots,
    demandes,
    async storeVault(_groupId, entries) {
      lots.push(entries.length);
      return { stored: entries.length };
    },
    async fetchVault(_groupId, after) {
      demandes.push(after);
      return pages.shift() ?? [];
    },
  };
}

test("une entrée archivée se relit à l'identique", async () => {
  const k = await key();
  const original: Message = {
    seq: 42,
    sender: "bob",
    mine: true,
    content: { kind: "reply", target: 7, text: "d'accord" },
  };

  const relu = await decryptEntry(k, 42, await encryptEntry(k, original));
  assert.deepEqual(relu, original);
});

/**
 * La clé du coffre dérive de la phrase de récupération : elle ne change **jamais**. AES-GCM
 * casse catastrophiquement si un nonce est réutilisé sous la même clé — c'est le seul endroit
 * du projet où cette règle n'a aucun filet.
 */
test("deux chiffrements du même message n'ont pas le même nonce", async () => {
  const k = await key();
  const a = await encryptEntry(k, message(1));
  const b = await encryptEntry(k, message(1));

  assert.notDeepEqual([...a.slice(0, 12)], [...b.slice(0, 12)]);
});

/**
 * **Le test qui empêche le 400 silencieux.** Le serveur refuse tout lot de plus de deux cents
 * entrées ; un appareil qui rattrape un retard en a bien davantage à archiver d'un coup.
 */
test("un dépôt trop gros est découpé en lots que le serveur accepte", async () => {
  const api = faux();
  await store(api, await key(), GROUP, Array.from({ length: 450 }, (_, i) => message(i)));

  assert.deepEqual(api.lots, [200, 200, 50]);
});

test("un dépôt vide ne parle pas au serveur", async () => {
  const api = faux();
  await store(api, await key(), GROUP, []);

  assert.deepEqual(api.lots, []);
});

/**
 * **Le test qui empêche l'historique tronqué en silence.** Le serveur sert au plus deux cents
 * lignes ; sans pagination, tout ce qui suit disparaissait sans la moindre erreur.
 */
test("une restauration suit le curseur jusqu'à épuisement", async () => {
  const k = await key();

  const page = async (debut: number, taille: number) =>
    await Promise.all(
      Array.from({ length: taille }, async (_, i) => ({
        seq: debut + i,
        payload: await encryptEntry(k, message(debut + i)),
      })),
    );

  const api = faux([await page(1, 200), await page(201, 200), await page(401, 30)]);
  const { messages, illisibles } = await restore(api, k, GROUP);

  assert.equal(messages.length, 430);
  assert.equal(illisibles, 0);
  // Le curseur repart du dernier `seq` servi, jamais d'un décompte local.
  assert.deepEqual(api.demandes, [0, 200, 400]);
});

test("une page pleine suivie du vide ne boucle pas indéfiniment", async () => {
  const k = await key();
  const pleine = await Promise.all(
    Array.from({ length: 200 }, async (_, i) => ({
      seq: i + 1,
      payload: await encryptEntry(k, message(i + 1)),
    })),
  );

  const { messages } = await restore(faux([pleine, []]), k, GROUP);
  assert.equal(messages.length, 200);
});

test("une entrée illisible est comptée, pas fatale", async () => {
  const k = await key();
  const api = faux([
    [
      { seq: 1, payload: await encryptEntry(k, message(1)) },
      { seq: 2, payload: new Uint8Array(40) },
      { seq: 3, payload: await encryptEntry(k, message(3)) },
    ],
  ]);

  const { messages, illisibles } = await restore(api, k, GROUP);
  assert.deepEqual(messages.map((m) => m.seq), [1, 3]);
  assert.equal(illisibles, 1);
});

test("la fusion ne rapatrie que ce qui manque au fil", () => {
  const existants = [message(1), message(2)];
  assert.deepEqual(
    merge(existants, [message(1), message(2), message(3)]).map((m) => m.seq),
    [3],
  );
});

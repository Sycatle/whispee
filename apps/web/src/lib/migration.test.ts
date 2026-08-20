import assert from "node:assert/strict";
import { test } from "node:test";

import { decider, migrer, PropagationIncomplete, type Etapes } from "./migration.ts";

const web = { handle: "alice" };
const natif = { handle: "alice" };

test("rien de rangé : l'installation est neuve", () => {
  assert.deepEqual(decider(undefined, undefined), { quoi: "neuve" });
});

test("session native seule : la migration est finie", () => {
  assert.deepEqual(decider(undefined, natif), { quoi: "native" });
});

test("session web seule : la migration est à faire", () => {
  assert.deepEqual(decider(web, undefined), { quoi: "demarrer", handle: "alice" });
});

test("les deux sessions : la migration est à reprendre", () => {
  assert.deepEqual(decider(web, natif), { quoi: "reprendre", handle: "alice" });
});

/**
 * **Le test qui porte la décision de conception.**
 *
 * Sans coffre, l'historique n'existe que dans l'état MLS de l'appareil courant, et le ratchet en
 * a détruit les clés au fur et à mesure : le nouvel appareil ne pourrait le relire nulle part.
 * Migrer échangerait alors une éviction possible contre une perte certaine.
 */
test("un coffre refusé interdit la migration", () => {
  const decision = decider({ handle: "alice", vaultEnabled: false }, undefined);

  assert.equal(decision.quoi, "repli");
  assert.match(decision.quoi === "repli" ? decision.raison : "", /sauvegarde d'historique/);
});

/**
 * Absent n'est pas `false`.
 *
 * Les comptes antérieurs au drapeau n'ont jamais eu à décider ; les traiter comme un refus
 * refuserait de migrer précisément les installations les plus anciennes.
 */
test("un coffre jamais refusé se migre", () => {
  assert.equal(decider({ handle: "alice" }, undefined).quoi, "demarrer");
  assert.equal(decider({ handle: "alice", vaultEnabled: true }, undefined).quoi, "demarrer");
});

/** Deux comptes distincts ne sont pas une migration à moitié faite. */
test("deux comptes différents font reculer", () => {
  const decision = decider(web, { handle: "bob" });

  assert.equal(decision.quoi, "repli");
  assert.match(decision.quoi === "repli" ? decision.raison : "", /autre compte/);
});

function etapes(ajouts: Partial<Etapes> = {}): Etapes & { journal: string[] } {
  const journal: string[] = [];
  const noter = (nom: string) => () => {
    journal.push(nom);
    return Promise.resolve();
  };

  return {
    journal,
    enregistrerAppareilNatif: () => {
      journal.push("enregistrer");
      return Promise.resolve("alice:desktop-2");
    },
    propagerDepuisAncien: noter("propager"),
    avancement: () => Promise.resolve({ rejointes: 2, attendues: 2 }),
    restaurerHistorique: noter("restaurer"),
    revoquerAncien: (ancien: string) => {
      journal.push(`revoquer:${ancien}`);
      return Promise.resolve();
    },
    oublierWeb: noter("oublier"),
    ...ajouts,
  };
}

const sansAttente = () => Promise.resolve();

/**
 * **Le test qui porte l'ordre des étapes.**
 *
 * La révocation avant l'effacement, et les deux après la propagation : révoquer l'ancien
 * appareil trop tôt le couperait des groupes avant qu'il n'y ait introduit le nouveau, et
 * effacer la session web avant tout le reste retirerait la seule chose qui permet de rejouer.
 */
test("une migration complète suit l'ordre imposé", async () => {
  const plan = etapes();
  await migrer({ quoi: "demarrer", handle: "alice" }, plan, "alice:desktop", sansAttente);

  assert.deepEqual(plan.journal, [
    "enregistrer",
    "propager",
    "restaurer",
    "revoquer:alice:desktop",
    "oublier",
  ]);
});

/** Reprendre ne réenregistre pas : l'appareil natif existe déjà, et le serveur en créerait un second. */
test("une reprise n'enregistre pas un appareil de plus", async () => {
  const plan = etapes();
  await migrer({ quoi: "reprendre", handle: "alice" }, plan, "alice:desktop", sansAttente);

  assert.ok(!plan.journal.includes("enregistrer"));
  assert.deepEqual(plan.journal[0], "propager");
});

/**
 * On attend le **résultat** de la propagation, pas le geste.
 *
 * L'ancien appareil dépose des commits, le nouveau doit les relever : révoquer entre les deux
 * rendrait les conversations inaccessibles de ce côté-ci, sans recours.
 */
test("la révocation attend que les groupes soient rejoints", async () => {
  let tours = 0;
  const plan = etapes({
    avancement: () => {
      tours += 1;
      return Promise.resolve({ rejointes: tours >= 3 ? 2 : 0, attendues: 2 });
    },
  });

  await migrer({ quoi: "reprendre", handle: "alice" }, plan, "alice:desktop", sansAttente);

  assert.equal(plan.journal.filter((e) => e === "propager").length, 3);
  assert.ok(plan.journal.indexOf("revoquer:alice:desktop") > plan.journal.lastIndexOf("propager"));
});

/**
 * Un serveur muet fait abandonner, sans rien détruire.
 *
 * L'abandon laisse deux appareils actifs : un état sain, seulement redondant, dont le démarrage
 * suivant repart. Ce qu'il ne faut surtout pas, c'est révoquer ou effacer par dépit.
 */
test("une propagation qui n'aboutit pas ne révoque rien", async () => {
  const plan = etapes({ avancement: () => Promise.resolve({ rejointes: 0, attendues: 2 }) });

  await assert.rejects(
    () => migrer({ quoi: "reprendre", handle: "alice" }, plan, "alice:desktop", sansAttente),
    PropagationIncomplete,
  );

  assert.ok(!plan.journal.some((e) => e.startsWith("revoquer")));
  assert.ok(!plan.journal.includes("oublier"));
});

/** Aucune décision de repli ne doit toucher à quoi que ce soit. */
test("un repli n'exécute aucune étape", async () => {
  for (const decision of [
    { quoi: "repli", raison: "peu importe" },
    { quoi: "native" },
    { quoi: "neuve" },
  ] as const) {
    const plan = etapes();
    await migrer(decision, plan, "alice:desktop", sansAttente);
    assert.deepEqual(plan.journal, [], `${decision.quoi} a agi`);
  }
});

/** Une conversation de plus côté nouveau (rare, mais possible) ne bloque pas. */
test("un avancement supérieur à l'attendu ne boucle pas", async () => {
  const plan = etapes({ avancement: () => Promise.resolve({ rejointes: 3, attendues: 2 }) });
  await migrer({ quoi: "reprendre", handle: "alice" }, plan, "alice:desktop", sansAttente);

  assert.ok(plan.journal.includes("oublier"));
});

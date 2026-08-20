import assert from "node:assert/strict";
import { test } from "node:test";

import qrcode from "qrcode-generator";

/**
 * Le code d'appairage tel que `encodePairingCode` le produit : 48 octets en base64url, donc 64
 * caractères. C'est la seule donnée que ce projet met dans un QR.
 */
const CODE = "A".repeat(64);

function grille(valeur: string) {
  const qr = qrcode(0, "M");
  qr.addData(valeur);
  qr.make();
  return qr;
}

/**
 * Les trois motifs de repérage sont là.
 *
 * C'est ce qu'un lecteur cherche en premier : sans eux il ne trouve même pas le code dans
 * l'image. Un carré qui en manquerait un serait indétectable — et le seul symptôme serait un
 * utilisateur qui « n'arrive pas à scanner », sans rien à l'écran qui l'explique.
 */
test("le carré porte ses trois motifs de repérage", () => {
  const qr = grille(CODE);
  const n = qr.getModuleCount();

  for (const [ligne, colonne] of [
    [0, 0],
    [0, n - 7],
    [n - 7, 0],
  ]) {
    // Un motif de repérage est un carré plein de 7×7 bordé de clair : on vérifie ses coins et
    // son centre, ce qui suffit à distinguer un motif d'une zone de données quelconque.
    assert.ok(qr.isDark(ligne, colonne), `coin ${ligne},${colonne} absent`);
    assert.ok(qr.isDark(ligne + 6, colonne + 6));
    assert.ok(qr.isDark(ligne + 3, colonne + 3));
    assert.ok(!qr.isDark(ligne + 1, colonne + 1), "l'anneau clair manque");
  }
});

/**
 * La version choisie reste petite.
 *
 * Un QR trop dense n'est pas illisible en théorie, il l'est en pratique : plus de modules sur la
 * même surface d'écran, donc une caméra qui doit s'approcher, sur un geste que l'utilisateur ne
 * fait qu'une fois et sans savoir pourquoi il échoue.
 *
 * Les 64 caractères actuels tombent en version 5, soit 37 modules — mesuré, non déduit. Le seuil
 * est là pour signaler une donnée qui grossit : allonger le code d'appairage ferait monter la
 * version, et la dégradation du scan serait attribuée à la caméra plutôt qu'à ce changement.
 */
test("le code d'appairage tient dans une version basse", () => {
  const modules = grille(CODE).getModuleCount();

  // Version n → 17 + 4n modules. La version 5 en fait 37.
  assert.ok(modules <= 37, `${modules} modules : la donnée a grossi`);
});

/** Deux données différentes donnent deux carrés différents — l'encodeur encode vraiment. */
test("le carré dépend de la donnée", () => {
  const a = grille(CODE);
  const b = grille("B".repeat(64));

  const empreinte = (qr: ReturnType<typeof grille>) => {
    const n = qr.getModuleCount();
    let bits = "";
    for (let l = 0; l < n; l += 1) for (let c = 0; c < n; c += 1) bits += qr.isDark(l, c) ? "1" : "0";
    return bits;
  };

  assert.notEqual(empreinte(a), empreinte(b));
});

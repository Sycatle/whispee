import qrcode from "qrcode-generator";

/**
 * Le code d'appairage, en carré à scanner.
 *
 * # Pourquoi une dépendance ici, dans un projet qui s'en méfie
 *
 * Écrire un encodeur QR demande Reed-Solomon, les huit masques et leurs pénalités : quelques
 * centaines de lignes qu'aucun test disponible ici ne pourrait valider, faute de lecteur — Chrome
 * sous Linux n'expose pas `BarcodeDetector`. Un carré subtilement faux ne se verrait qu'entre les
 * mains d'un utilisateur.
 *
 * Le contenu, lui, ne coûte rien à confier : identifiant et clé publique éphémère, tous deux
 * publics par construction. Une bibliothèque compromise ne pourrait pas voler de secret — au pire
 * afficher un code menant ailleurs, ce que le code de confirmation affiché des deux côtés est
 * précisément là pour attraper.
 *
 * # Rendu en SVG, pas en canvas
 *
 * Net à toute taille, donc lisible par une caméra quel que soit l'écran, et sans lecture de
 * pixels — un canvas devrait être dimensionné à la main pour ne pas rendre un carré flou sur
 * écran dense, exactement là où le scan doit fonctionner.
 */
export function QrCode({ value, taille = 240 }: { value: string; taille?: number }) {
  // Version 0 : la bibliothèque choisit la plus petite qui contienne la donnée. Correction « M »,
  // le compromis habituel — un QR affiché sur un écran propre n'a pas besoin de « H », qui
  // densifierait les modules et rendrait le scan plus difficile à distance.
  const qr = qrcode(0, "M");
  qr.addData(value);
  qr.make();

  const modules = qr.getModuleCount();
  // Une marge de quatre modules est exigée par la norme : sans elle, un lecteur ne distingue pas
  // le motif du fond et bien des scans échouent sans rien dire.
  const cote = modules + 8;

  const cases: string[] = [];
  for (let ligne = 0; ligne < modules; ligne += 1) {
    for (let colonne = 0; colonne < modules; colonne += 1) {
      if (qr.isDark(ligne, colonne)) cases.push(`M${colonne + 4},${ligne + 4}h1v1h-1z`);
    }
  }

  return (
    <svg
      viewBox={`0 0 ${cote} ${cote}`}
      width={taille}
      height={taille}
      role="img"
      aria-label="Code d'appairage à scanner"
      // Fond blanc et modules noirs en dur, hors du thème : un lecteur attend du contraste et
      // du noir sur blanc. Un QR en couleurs de thème sombre est illisible pour beaucoup de
      // caméras, ce qui ferait passer un défaut d'affichage pour une panne d'appairage.
      className="rounded-md bg-white"
    >
      <path d={cases.join("")} fill="#000" shapeRendering="crispEdges" />
    </svg>
  );
}

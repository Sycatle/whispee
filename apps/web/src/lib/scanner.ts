/**
 * Lecture d'un code QR par la caméra.
 *
 * # Ce que le navigateur fournit, et là où il ne fournit rien
 *
 * `BarcodeDetector` décode nativement, sans bibliothèque : Chrome sur Android l'expose, donc la
 * WebView de Tauri aussi. WKWebView ne l'expose pas, et Firefox non plus.
 *
 * Sur ces plateformes, il n'y a pas de scan — et **c'est acceptable**, parce que la saisie du
 * code reste là. Embarquer un décodeur en JavaScript coûterait une dépendance de plus dans un
 * client dont tout l'argumentaire est qu'il en a peu, pour remplacer un repli qui fonctionne
 * déjà. Ce n'est pas le même arbitrage que pour l'affichage : là, aucun repli n'existait.
 *
 * # Le scan ne remplace pas la vérification
 *
 * Il remplace une saisie, rien de plus. La sécurité de l'appairage est **physique** : elle tient
 * à ce que l'utilisateur ne scanne que l'écran qu'il a en main, et le code de confirmation
 * affiché des deux côtés est ce qui le lui confirme. Une caméra ne sait pas quel écran elle
 * regarde.
 */

/** Le décodage natif est-il disponible ? */
export function scanDisponible(): boolean {
  return "BarcodeDetector" in globalThis;
}

interface DetecteurQr {
  detect(source: CanvasImageSource): Promise<{ rawValue: string }[]>;
}

/**
 * Ouvre la caméra, lit jusqu'au premier code, et rend ce qu'il contient.
 *
 * Rend aussi de quoi tout arrêter : le flux vidéo doit être coupé quoi qu'il arrive — un scan
 * abandonné qui laisse la caméra allumée est un voyant qui reste vert sur le téléphone, ce qui
 * est au mieux inquiétant et au pire une fuite de vie privée.
 */
export async function scanner(video: HTMLVideoElement): Promise<{
  lecture: Promise<string>;
  arreter: () => void;
}> {
  const Detecteur = (globalThis as unknown as {
    BarcodeDetector: new (options: { formats: string[] }) => DetecteurQr;
  }).BarcodeDetector;

  // `facingMode: environment` demande la caméra arrière : c'est elle qui vise l'autre écran.
  // Un `ideal` plutôt qu'un `exact` — un ordinateur portable n'a qu'une caméra, et exiger
  // l'arrière y ferait échouer l'ouverture au lieu de prendre celle qui existe.
  const flux = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: "environment" } },
  });

  let vivant = true;
  const arreter = () => {
    vivant = false;
    for (const piste of flux.getTracks()) piste.stop();
  };

  video.srcObject = flux;
  await video.play();

  const detecteur = new Detecteur({ formats: ["qr_code"] });

  const lecture = (async () => {
    // Une boucle et non un `requestVideoFrameCallback` : la seconde n'existe pas partout, et la
    // cadence n'a aucune importance ici — l'utilisateur vise un écran fixe, pas un objet en
    // mouvement.
    while (vivant) {
      const codes = await detecteur.detect(video).catch(() => []);
      const trouve = codes.find((code) => code.rawValue.length > 0);
      if (trouve) {
        arreter();
        return trouve.rawValue;
      }

      await new Promise((resolve) => setTimeout(resolve, 200));
    }

    throw new Error("Scan interrompu.");
  })();

  return { lecture, arreter };
}

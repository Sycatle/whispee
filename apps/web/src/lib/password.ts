/**
 * Politique de mot de passe.
 *
 * # Pourquoi pas « une majuscule, un chiffre, un caractère spécial »
 *
 * Ces règles ne créent aucune entropie : elles déplacent le `A` au début et le `1!` à la fin.
 * L'espace des mots de passe qu'un humain produit sous ces contraintes est plus petit, pas
 * plus grand — et les attaquants le connaissent mieux que nous. Le NIST les a explicitement
 * abandonnées dans SP 800-63B.
 *
 * Ce qui compte réellement : **la longueur**, et **ne pas figurer dans une liste connue**.
 * C'est ce que ce module vérifie.
 *
 * # Ce que ce mot de passe protège
 *
 * L'état au repos sur cet appareil, rien d'autre. Il n'est pas un facteur de récupération :
 * l'oublier ne fait rien perdre, la phrase de douze mots reste le seul chemin de restauration.
 */

/** Longueur minimale. Douze caractères de français courant valent ~40 bits — le plancher
 * en dessous duquel Argon2id lui-même ne suffit plus à rendre une attaque hors ligne coûteuse. */
export const MIN_LENGTH = 12;

/**
 * Mots de passe et motifs les plus fréquemment observés dans les fuites.
 *
 * Cette liste est volontairement courte : elle attrape les cas manifestes sans alourdir le
 * bundle. **Un déploiement réel utiliserait la liste complète** — les 10 000 premiers de
 * rockyou, ou l'API k-anonyme de Have I Been Pwned, qui vérifie sans révéler le mot de passe.
 * C'est noté dans les limites connues du README plutôt que fait à moitié en silence.
 */
const COMMUNS = [
  "motdepasse", "password", "azertyuiop", "qwertyuiop", "123456789", "1234567890",
  "administrateur", "changeme", "letmein", "welcome1", "iloveyou", "sunshine",
  "princesse", "football", "monkey123", "dragon123", "abc123456", "passw0rd",
  "motdepasse1", "password1", "azerty123", "qwerty123", "000000000", "111111111",
];

export interface Verdict {
  ok: boolean;
  /** Message à afficher. Vide quand le mot de passe convient. */
  raison: string;
}

export function verifier(password: string): Verdict {
  if (password.length < MIN_LENGTH) {
    return {
      ok: false,
      raison: `Au moins ${MIN_LENGTH} caractères. La longueur est ce qui protège réellement — pas les majuscules ni les chiffres.`,
    };
  }

  const normalise = password.toLowerCase();

  if (COMMUNS.some((connu) => normalise.includes(connu))) {
    return {
      ok: false,
      raison: "Ce mot de passe contient une suite figurant dans les listes de fuites connues.",
    };
  }

  // Un seul caractère répété, ou une suite de clavier, passe la longueur minimale sans rien
  // valoir : « aaaaaaaaaaaa » fait douze caractères et zéro bit d'entropie.
  if (new Set(password).size <= 4) {
    return {
      ok: false,
      raison: "Trop peu de caractères distincts : la longueur seule ne suffit pas.",
    };
  }

  return { ok: true, raison: "" };
}

/**
 * Estimation grossière de l'entropie, en bits, à afficher à titre indicatif.
 *
 * Grossière et **optimiste** : elle suppose un mot de passe tiré au hasard dans l'alphabet
 * observé, ce qu'un humain ne fait jamais. Un vrai estimateur (zxcvbn) reconnaît les mots du
 * dictionnaire, les dates et les substitutions ; il pèse 400 Ko. La valeur affichée est donc
 * un plafond, à présenter comme tel — jamais comme une garantie.
 */
export function bitsApproximatifs(password: string): number {
  const classes = [
    /[a-z]/.test(password) ? 26 : 0,
    /[A-Z]/.test(password) ? 26 : 0,
    /[0-9]/.test(password) ? 10 : 0,
    /[^a-zA-Z0-9]/.test(password) ? 33 : 0,
  ].reduce((a, b) => a + b, 0);

  if (classes === 0) return 0;
  return Math.round(password.length * Math.log2(classes));
}

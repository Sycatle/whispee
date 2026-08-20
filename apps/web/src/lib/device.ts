/**
 * Nom de l'appareil courant.
 *
 * Le demander à l'utilisateur ne sert à rien : il n'a pas d'information que le navigateur
 * n'ait déjà, et la question arrive au pire moment — juste avant qu'il découvre sa phrase de
 * récupération, qui elle mérite toute son attention.
 *
 * Ce nom est **transporté en clair** dans l'identifiant d'appareil, visible du serveur comme
 * des correspondants. D'où deux mots génériques plutôt qu'un modèle précis : « iPhone 15 Pro
 * bleu » distinguerait son porteur bien au-delà de ce qu'exige le routage.
 */
export type DeviceKind = "desktop" | "mobile";

export function detectDeviceKind(): DeviceKind {
  // `userAgentData` est l'API non dépréciée et non falsifiable par simple chaîne ; elle
  // manque encore à Safari et Firefox, d'où le repli sur l'user agent.
  const hints = (navigator as Navigator & { userAgentData?: { mobile?: boolean } }).userAgentData;
  if (typeof hints?.mobile === "boolean") return hints.mobile ? "mobile" : "desktop";

  return /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) ? "mobile" : "desktop";
}

/**
 * Décline un nom déjà pris : `desktop`, `desktop-2`, `desktop-3`…
 *
 * Un compte peut légitimement avoir deux ordinateurs. Le serveur refuse alors le second avec
 * un 409, et cette suite permet de réessayer sans rien demander à l'utilisateur.
 */
export function* deviceNameCandidates(kind: DeviceKind): Generator<string> {
  yield kind;
  for (let n = 2; n <= 20; n += 1) yield `${kind}-${n}`;
}

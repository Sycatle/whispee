/**
 * Name of the current device.
 *
 * Asking the user is pointless: they have no information the browser does not already have, and
 * the question comes at the worst moment — right before they discover their recovery phrase,
 * which deserves all their attention.
 *
 * This name is **carried in the clear** inside the device id, visible to the server and to
 * correspondents. Hence two generic words rather than a precise model: "blue iPhone 15 Pro"
 * would single out its owner far beyond what routing requires.
 */
export type DeviceKind = "desktop" | "mobile";

export function detectDeviceKind(): DeviceKind {
  // `userAgentData` is the non-deprecated API, and cannot be faked with a plain string; Safari
  // and Firefox still lack it, hence the fallback on the user agent.
  const hints = (navigator as Navigator & { userAgentData?: { mobile?: boolean } }).userAgentData;
  if (typeof hints?.mobile === "boolean") return hints.mobile ? "mobile" : "desktop";

  return /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) ? "mobile" : "desktop";
}

/**
 * Varies a name that is already taken: `desktop`, `desktop-2`, `desktop-3`…
 *
 * An account can legitimately have two computers. The server then refuses the second with a 409,
 * and this sequence allows a retry without asking the user anything.
 */
export function* deviceNameCandidates(kind: DeviceKind): Generator<string> {
  yield kind;
  for (let n = 2; n <= 20; n += 1) yield `${kind}-${n}`;
}

/**
 * Web Push, from the browser's side.
 *
 * # What this gets you, and what it costs
 *
 * A message arriving while the tab is closed wakes the browser, which shows "New message" and
 * nothing else. That is the whole feature. `notifications.ts` already handles the case where the
 * tab is open, and keeps handling it — the two do not overlap, because a push handler only runs
 * when no page is there to.
 *
 * The cost is two things, and both belong on the screen before the switch rather than in a
 * document afterwards:
 *
 * 1. **The browser's push service learns the rhythm.** Chrome subscribes through Google, Firefox
 *    through Mozilla. That service sees a wake-up arrive for this browser every time a message
 *    does, and it can tie that to an IP address. The content stays encrypted; the timing does not.
 * 2. **The server learns who to wake, which sealed sender was built to remove.** A server that
 *    chooses whom to wake gains a targeted activity trigger: ceasing to wake four members of five
 *    makes the next post attributable to the fifth. Nothing cryptographic answers this — see
 *    `docs/ROADMAP.md`, which says so at more length.
 *
 * # Why there is no stored setting
 *
 * The subscription itself is the state. `pushManager.getSubscription()` answers "is this browser
 * subscribed" without anything of ours being written down, which is both one fewer thing to keep
 * in step and the answer to something the roadmap asks for: a token has to be re-registered at
 * every start, because it rotates without warning. Re-registering is just sending back whatever
 * `getSubscription()` returns, so the replay and the read are the same operation.
 *
 * It is also per browser and not per account. `signal-sync.ts` gives the test — a fact about the
 * *machine* rather than about the *account* — which is why this is never synchronised between
 * devices, the same reason `locale` is not.
 *
 * # Why no payload
 *
 * Because the wake-up carries nothing, the whole content-encryption half of Web Push (RFC 8291)
 * is unused: the `p256dh` and `auth` secrets a subscription carries are never read here and never
 * sent anywhere. See `crates/server/src/vapid.rs` for the same observation from the other end.
 */
/**
 * What this module needs from the server, and nothing more.
 *
 * A structural port rather than an import of `Api`, for the reason `notifications.ts` gives about
 * every browser object it touches: `api.ts` uses constructor parameter properties, which
 * `node --test` cannot strip, so importing it would make this module untestable. Naming the two
 * methods used is also a shorter statement of what waking a browser can reach than a class with
 * fifty.
 */
export interface PushApi {
  setPushToken(provider: string, token: string): Promise<void>;
  forgetPushToken(): Promise<void>;
}

/** The provider name the server files this subscription under. Must match `push::WEB_PUSH`. */
export const PROVIDER = "webpush";

/**
 * Copy for the settings screen, stated before the choice — the same discipline as
 * `DISCLOSE_NAME_COPY` and the vault screen, and exported from beside the behaviour so the
 * sentence and the code cannot drift apart.
 */
export const PUSH_DISCLOSURE_COPY =
  "Waking this browser means two things leave. Your browser's push service — Google for Chrome, " +
  "Mozilla for Firefox — learns each time a message arrives for you, and can tie that to your " +
  "address. And this server learns which devices to wake, which is exactly what it was arranged " +
  "not to know: a server that stops waking four members of five can tell who wrote the next " +
  "message. Nothing in the message itself is disclosed — the notification says a message " +
  "arrived and never what it says or who sent it.";

/**
 * Is Web Push usable here at all?
 *
 * Three conditions, and the third is the one that surprises people: a secure context. Service
 * workers and the Push API are both refused over plain http, `localhost` excepted.
 */
export function pushSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "serviceWorker" in navigator &&
    typeof window !== "undefined" &&
    "PushManager" in window &&
    window.isSecureContext
  );
}

/**
 * Decodes the server's key into the form `subscribe` demands.
 *
 * The key travels as base64url because that is how it is written everywhere in this protocol, and
 * arrives as a `BufferSource` because that is what the browser takes. Exported for its test: an
 * error here produces `InvalidCharacterError` from deep inside the browser, which names nothing.
 */
export function decodeApplicationServerKey(base64url: string): Uint8Array<ArrayBuffer> {
  const padded = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "="));

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/**
 * Registers the worker, or `null` where it cannot be.
 *
 * Scoped to the root because that is where the file is served from and where the notification's
 * click has to land. Failure is a `null`, not a throw: an unsupported browser and a blocked
 * registration are the same thing to every caller here — this feature is absent — and neither is
 * worth an error dialog on a path the user did not ask for.
 */
async function worker(): Promise<ServiceWorkerRegistration | null> {
  if (!pushSupported()) return null;

  try {
    return await navigator.serviceWorker.register("/sw.js", { scope: "/" });
  } catch (error) {
    console.warn("service worker not registered", error);
    return null;
  }
}

/** Is this browser subscribed right now? The subscription is the state; nothing else is read. */
export async function pushEnabled(): Promise<boolean> {
  const registration = await worker();
  if (!registration) return false;

  return (await registration.pushManager.getSubscription()) !== null;
}

/**
 * Subscribes this browser and hands the endpoint to the server.
 *
 * Returns `false` when the deployment does not do push — `Api.vapidPublicKey` answers `null` on a
 * 503 — so the caller can say "this server does not offer that" rather than "it failed".
 *
 * **Notification permission is not requested here.** It belongs to a click, and `Notices.tsx`
 * already owns that; `subscribe` with `userVisibleOnly` would raise the prompt itself, from
 * whatever code path happened to call it. Asked for from a settings screen it is a question;
 * raised from a replay after a reconnection it is an ambush.
 */
export async function enablePush(api: PushApi, key: string | null): Promise<boolean> {
  const registration = await worker();
  if (!registration) return false;

  // `null` is this deployment answering 503 on the key route: it does not do push. Fetched by the
  // caller rather than here, because the route is unsigned and `Api` exposes it as a static —
  // and because this module stays free of `api.ts`, which it cannot import. See `PushApi`.
  if (key === null) return false;

  const subscription =
    (await registration.pushManager.getSubscription()) ??
    (await registration.pushManager.subscribe({
      // Required by every browser that implements this, and it is not a formality: it is the
      // promise that every wake-up produces something the user sees. A silent push is what a
      // tracker would want, and the worker keeps that promise by always showing a notification.
      userVisibleOnly: true,
      applicationServerKey: decodeApplicationServerKey(key),
    }));

  await api.setPushToken(PROVIDER, subscription.endpoint);
  return true;
}

/**
 * Unsubscribes, and tells the server to forget the address.
 *
 * Both halves, in that order, and neither is enough alone: dropping the local subscription while
 * the server keeps the endpoint leaves it pushing into a void until the service reports it gone,
 * and forgetting it server-side while the browser stays subscribed leaves a live subscription
 * nobody uses.
 */
export async function disablePush(api: PushApi): Promise<void> {
  const registration = await worker();
  const subscription = await registration?.pushManager.getSubscription();

  await subscription?.unsubscribe();
  await api.forgetPushToken();
}

/**
 * Re-sends the endpoint this browser already holds, if any.
 *
 * Called at every start and after every reconnection, which is what the roadmap asks for: a push
 * address rotates without warning, and a browser that re-subscribes on its own would otherwise be
 * reachable at an address the server does not have. Doing nothing when there is no subscription
 * is the point — this must never turn the feature on by itself.
 *
 * Silent on failure. It runs on a path nobody asked for; a toast here would report a problem the
 * user did not cause and cannot act on.
 */
export async function replayPushToken(api: PushApi): Promise<void> {
  try {
    if (!pushSupported()) return;

    const registration = await navigator.serviceWorker.getRegistration("/");
    const subscription = await registration?.pushManager.getSubscription();
    if (!subscription) return;

    await api.setPushToken(PROVIDER, subscription.endpoint);
  } catch (error) {
    console.warn("wake address not re-registered", error);
  }
}

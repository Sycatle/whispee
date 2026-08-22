/**
 * The media layer, behind an interface narrow enough to be replaced by nothing.
 *
 * # Why this file exists at all
 *
 * `session-call.ts` holds the whole of what a call *means* — who is ringing, who answered, when
 * it started, when it may be given up on. None of that involves a media server, and all of it is
 * worth testing. Importing the SDK there would make it untestable by `node --test`, which is the
 * same reason `cipher.ts` hands `Session` a capability instead of a key: a module that cannot be
 * loaded outside a browser is a module nobody writes a test for.
 *
 * So this is a port, and {@link liveMedia} is the only implementation that talks to a network.
 * The state machine takes a {@link Media} and never learns what is behind it.
 *
 * # What the media server is trusted with, and what it is not
 *
 * It routes the audio, and it cannot hear it. Every frame is encrypted a second time, inside the
 * browser, under a key derived from the current MLS epoch — `Client.callKey`, which every member
 * computes locally and nobody sends anywhere. What reaches the server is already ciphertext when
 * the transport encryption is applied to it, and it is still ciphertext when the transport
 * encryption is removed on the far side.
 *
 * What it does learn is real and is not hidden here: who shares a room with whom, and for how
 * long. `crates/server/src/call.rs` argues the whole trade, and `docs/THREAT-MODEL.md` records
 * it where a user might look.
 *
 * # Why the identity is derived rather than given
 *
 * A participant needs a name inside the room, and the two obvious candidates both leak: a device
 * id hands the media server the directory this project spends its effort keeping from the
 * delivery service, and a random name leaves members unable to tell each other apart. So it is
 * derived from the call key — every member can compute every other member's, and the server sees
 * a string that changes at every call and means nothing to it.
 *
 * That derivation is not authentication, and must not be read as one: a member of the group can
 * compute another member's identity and take it. It is the same forgery the ephemeral channel
 * allows, from the same cause — a key that belongs to the group authenticates the group.
 */
import type { Room } from "livekit-client";

/**
 * Whether this build was told where a media server is.
 *
 * A *build-time* value, like the policy in `csp.ts` that has to name the same origin — a client
 * whose Content-Security-Policy does not carry that origin cannot reach it, so a runtime toggle
 * would offer a button that is guaranteed to fail. The server has the last word regardless: it
 * answers 503 when it holds no credentials, and the call ends there.
 *
 * Read defensively because this module is also loaded by `node --test`, where `import.meta.env`
 * does not exist.
 */
export const CALLS_CONFIGURED = Boolean(
  (import.meta as { env?: Record<string, string | undefined> }).env?.VITE_MEDIA_URL,
);

/** Where a call happens, and what it takes to be let in. */
export interface Admission {
  /** The media server, as the delivery service knows it. */
  url: string;
  token: string;
  /** The relay, when the deployment has one. */
  relay?: { urls: string[]; username: string; credential: string };
}

/** What a joined call offers. Deliberately four verbs: anything more is state, and state is not here. */
export interface Call {
  /** Silences or restores the microphone. */
  mute(muted: boolean): Promise<void>;
  /**
   * Hands the call a new key.
   *
   * Called on every MLS commit. Without it a call spanning an epoch change goes silent — which
   * is the correct failure for a member who has just been removed, and the wrong one for the
   * five who have not.
   */
  rekey(key: Uint8Array): Promise<void>;
  /** Leaves. Idempotent: hanging up twice is a thing interfaces do. */
  leave(): Promise<void>;
  /** The identities currently publishing audio, ours excluded. */
  peers(): string[];
}

/** How a call is joined. The state machine holds one of these and nothing else about media. */
export interface Media {
  join(options: JoinOptions): Promise<Call>;
}

export interface JoinOptions {
  admission: Admission;
  /** The frame key, derived from the MLS epoch. Never leaves this device. */
  key: Uint8Array;
  /** Called whenever the participant list changes, with our own identity excluded. */
  onPeers: (peers: string[]) => void;
  /**
   * Called when the connection is lost for good.
   *
   * A call that dies has to reach the state machine, or the interface keeps showing a
   * conversation that ended — which is worse than showing none.
   */
  onClosed: () => void;
}

/**
 * The name a device answers to inside a room.
 *
 * Derived from the call key so that members recognise each other while the media server sees an
 * opaque string. Truncated to sixteen hex characters: it names one participant of one call, and
 * a full digest would only be longer.
 */
export async function identityFor(key: Uint8Array, deviceId: string): Promise<string> {
  const material = new TextEncoder().encode(`wac-call-peer-v1${deviceId}`);
  const input = new Uint8Array(key.length + material.length);
  input.set(key, 0);
  input.set(material, key.length);

  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input.slice().buffer));
  return [...digest.subarray(0, 8)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * The real media layer.
 *
 * Imported lazily, and that is not a performance flourish: the SDK and its encryption worker are
 * a few hundred kilobytes that a user who never places a call has no reason to download, and
 * this application is served to people whose connection is the reason they chose it.
 */
export function liveMedia(): Media {
  return {
    async join(options: JoinOptions): Promise<Call> {
      const { ExternalE2EEKeyProvider, Room, RoomEvent, Track } = await import("livekit-client");

      const keys = new ExternalE2EEKeyProvider();
      await keys.setKey(options.key.slice().buffer);

      const room = new Room({
        adaptiveStream: false,
        dynacast: false,
        e2ee: {
          keyProvider: keys,
          // Same-origin, bundled by Vite. The SDK otherwise reaches for a `blob:` wrapper, which
          // `worker-src 'self'` refuses — silently, as a blocked worker reports no reason.
          worker: new Worker(new URL("livekit-client/e2ee-worker", import.meta.url), {
            type: "module",
          }),
        },
        ...(options.admission.relay && {
          rtcConfig: {
            iceServers: [
              {
                urls: options.admission.relay.urls,
                username: options.admission.relay.username,
                credential: options.admission.relay.credential,
              },
            ],
          },
        }),
      });

      const announce = () => options.onPeers(peersOf(room));

      // Subscribed **before** connecting, all of them. A listener registered afterwards misses
      // whoever was already in the room — which is every participant, for the second person to
      // join a call.
      room
        .on(RoomEvent.ParticipantConnected, announce)
        .on(RoomEvent.ParticipantDisconnected, announce)
        .on(RoomEvent.Disconnected, options.onClosed)
        // Audio has to be attached to an element to be heard. Nothing is rendered: an `<audio>`
        // element with no controls is the browser's own way of playing a stream, and giving React
        // a node to own would tie the sound to a component's lifetime rather than the call's.
        //
        // **Every track is attached, including one from an account the user has blocked, and
        // that is decided rather than missed.**
        //
        // Blocking closes the channels that reach somebody without being asked for: the thread,
        // the typing indicator, notifications, and the ring. A group call is not one of them.
        // Joining is a deliberate act — the room is entered on purpose, by somebody who can see
        // who is in it — so what happens inside it is not content arriving unbidden, and blocking
        // has no claim over it.
        //
        // The line is there, and it is worth naming because it is the one to reason from: **what
        // arrives without being asked for is filtered; what is walked into is not.**
        //
        // So the test is on **who placed the call**, never on who is in it. An invitation from a
        // blocked account is refused in `session.ts` and never rings — that one arrives unbidden,
        // and it is the whole of the exception. A blocked member sitting in a call somebody else
        // placed is not: this device chose to enter that room. Same if they join after us, or if
        // the person who called leaves and they stay; the question was settled when the ring was
        // answered, and re-asking it mid-call would end a conversation under its participants for
        // a reason none of them could see.
        //
        // Filtering here would also cost the wrong person. Muting one voice in a conversation
        // several people are holding breaks it for the one who muted — the others answer somebody
        // this device cannot hear, and the thread of what is being said is lost. The blocked
        // member loses nothing. A measure whose whole effect lands on the person who took it is
        // not protection, it is a penalty for having used the feature.
        //
        // Nothing is given up on confidentiality by this: that member holds the epoch key
        // legitimately, being in the group at all is what the call is derived from, and removing
        // them from the group is the action that actually ends their access — see
        // `Session.tickCall`.
        //
        // **One debt this decision creates, and it is owed to the reader of another screen.** The
        // blocking control says "hides what someone says", which stopped being true the moment
        // calls existed: a blocked member's voice arrives in a call somebody else placed. That
        // wording lives outside this branch, so it cannot be fixed here — it has to change to
        // "hides what someone writes", plus a line saying their voice still carries in a call
        // they did not place, at the same time as the ring guard lands in `session.ts`. A control
        // describing an effect it does not have is the defect this whole comment exists to avoid
        // creating.
        .on(RoomEvent.TrackSubscribed, (track) => {
          if (track.kind === Track.Kind.Audio) track.attach();
          announce();
        });

      await room.connect(options.admission.url, options.admission.token);

      // **This line is what makes the call end-to-end encrypted, and it is not implied by the
      // `e2ee` option above.**
      //
      // Passing `e2ee` to the constructor builds the key provider, loads the worker and accepts
      // every key handed to it. It does not encrypt anything: the SDK only sets the local
      // participant's encryption type when this is called, so without it the frames reach the
      // media server in the clear and the derived key does nothing at all. Nothing reports the
      // difference — the call connects, the audio is heard, and every key rotation appears to
      // work, because none of it is in the media path.
      //
      // That is exactly how it was found: a member removed from the group mid-call went on
      // hearing it for forty seconds. See `docs/THREAT-MODEL.md` for what this line is
      // load-bearing for; the short of it is everything this module claims.
      //
      // **After `connect` and before publishing.** Before connecting, the local participant has
      // no identity yet and the SDK skips enabling its cryptor; after publishing, turning it on
      // republishes every track, which drops the audio it has just started carrying.
      await room.setE2EEEnabled(true);

      await room.localParticipant.setMicrophoneEnabled(true);

      announce();

      return {
        async mute(muted: boolean) {
          await room.localParticipant.setMicrophoneEnabled(!muted);
        },
        async rekey(key: Uint8Array) {
          await keys.setKey(key.slice().buffer);
        },
        async leave() {
          await room.disconnect();
        },
        peers: () => peersOf(room),
      };
    },
  };
}

function peersOf(room: Room): string[] {
  return [...room.remoteParticipants.values()].map((participant) => participant.identity);
}

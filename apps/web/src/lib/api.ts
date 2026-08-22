/**
 * Delivery service client.
 *
 * Every request is signed with the device's Ed25519 key. The signed message covers the method,
 * the path, the timestamp and the body digest: a signature captured on one endpoint is replayable
 * neither on another path nor with a modified body.
 */
import type { Admission } from "./call";
import type { DeviceCipher } from "./cipher";
import { fromBase64, toBase64, toHex } from "./keys";
import type { AttestedDevice } from "./wasm";

/** See the note about `buffer` in `keys.ts`. */
function buffer(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export const BASE_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8787";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * The message signed by every request.
 *
 * The nonce is what makes the message unique when everything else is identical. Without it, two
 * similar requests in the same second would carry the same signature — Ed25519 being
 * deterministic — and the server could not tell a replay from a legitimate call. It is **inside
 * the signed message**, so changing the header's nonce invalidates the signature.
 */
async function signingPayload(
  method: string,
  path: string,
  timestamp: number,
  nonce: Uint8Array,
  body: Uint8Array,
): Promise<Uint8Array> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(body)));
  const prefix = new TextEncoder().encode(`${method}\n${path}\n${timestamp}\n`);
  const separator = new TextEncoder().encode("\n");

  const payload = new Uint8Array(
    prefix.length + nonce.length + separator.length + digest.length,
  );
  payload.set(prefix, 0);
  payload.set(nonce, prefix.length);
  payload.set(separator, prefix.length + nonce.length);
  payload.set(digest, prefix.length + nonce.length + separator.length);
  return payload;
}

/**
 * Who may start a conversation with an account.
 *
 * Three values and the middle one is the one to read carefully: `known` means "already shares a
 * group with me", because that is the only relation the **server** can establish. It is not
 * "verified" — verification is compared out of band and lives in the client, and teaching the
 * server who verified whom would hand it a finer social graph than it already has, to enforce a
 * rule it can enforce more coarsely without.
 */
export type ContactPolicy = "open" | "known" | "closed";

export function isContactPolicy(value: unknown): value is ContactPolicy {
  return value === "open" || value === "known" || value === "closed";
}

export class Api {
  constructor(
    /**
     * This device's identifier.
     *
     * Public: the gateway's `identify` frame has to name it explicitly, since the WebSocket
     * handshake carries no header to say it earlier.
     */
    readonly deviceId: string,
    /**
     * What the device can do, not what it holds.
     *
     * This module used to sign by handling `CryptoKey` values directly. Going through a
     * capability is what will let the key live outside the webview without a single line here
     * changing.
     */
    private readonly cipher: DeviceCipher,
  ) {}

  /**
   * Creates a pseudonymous account. Unsigned — the server knows no key yet.
   *
   * Trust on first use: nothing proves that the first to claim a handle is its legitimate owner.
   * Only key transparency would answer that; see the README.
   *
   * Returns the **account id**, which the server derives from the key in this very request
   * rather than accepting from us. It is a hash of `identityKey`, so nothing here has to be
   * taken on trust: a caller that cares recomputes it. Everything downstream — device ids,
   * attestations, the roster — names the account by this string and not by the handle, which is
   * a name it merely answers to.
   */
  static async createAccount(handle: string, identityKey: Uint8Array): Promise<string> {
    const response = await fetch(`${BASE_URL}/v1/accounts`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle, identity_key: toBase64(identityKey) }),
    });

    if (!response.ok) {
      throw new ApiError(
        response.status,
        response.status === 409
          ? "handle already taken by another account"
          : await response.text(),
      );
    }

    const body = (await response.json()) as { account: string };
    return body.account;
  }

  /**
   * Registers the device and its attested attachment to the account.
   *
   * The attestation is what stops anyone — the server included — from declaring a device in
   * someone else's account and getting invited into their conversations.
   */
  static async register(
    deviceId: string,
    /** The account id. The device id must be prefixed with it, and the server checks that. */
    account: string,
    /**
     * The public authentication key, as bytes.
     *
     * Passed as-is rather than derived from a `DeviceKeys`: the caller may hold its keys in the
     * webview or in the native process, and registration has no reason to know which.
     */
    authKey: Uint8Array,
    mlsKey: Uint8Array,
    attestation: Uint8Array,
  ): Promise<void> {
    const response = await fetch(`${BASE_URL}/v1/devices`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: deviceId,
        account,
        auth_key: toBase64(authKey),
        mls_key: toBase64(mlsKey),
        attestation: toBase64(attestation),
      }),
    });

    if (!response.ok) {
      throw new ApiError(
        response.status,
        response.status === 409
          ? "id already taken by another device"
          : await response.text(),
      );
    }
  }

  private async request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const encoded = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
    return this.requestRaw(method, path, encoded, "json");
  }

  /** Binary variant, for bodies that are not JSON. */
  private async requestRaw<T>(
    method: "GET" | "POST",
    path: string,
    encoded: Uint8Array,
    expect: "json" | "bytes",
  ): Promise<T> {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const signature = await this.cipher.sign(
      await signingPayload(method, path, timestamp, nonce, encoded),
    );

    const response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: {
        // The server does not inspect the body: this type is indicative, and attachments are
        // opaque bytes anyway.
        "content-type": "application/octet-stream",
        "x-device-id": this.deviceId,
        "x-timestamp": String(timestamp),
        "x-signature": signature,
        "x-nonce": toBase64(nonce),
      },
      body: method === "GET" ? undefined : buffer(encoded),
    });

    if (!response.ok) throw new ApiError(response.status, await response.text());

    if (expect === "bytes") {
      return new Uint8Array(await response.arrayBuffer()) as T;
    }
    return response.json() as Promise<T>;
  }

  /** Restocks. Each KeyPackage is single-use. */
  publishKeyPackages(packages: Uint8Array[]): Promise<{ published: number }> {
    return this.request("POST", "/v1/key-packages", { packages: packages.map(toBase64) });
  }

  /** Worth watching: at zero, nobody can open a conversation with this device any more. */
  keyPackageStock(): Promise<{ remaining: number }> {
    return this.request("GET", "/v1/key-packages/stock");
  }

  async claimKeyPackage(deviceId: string): Promise<{ package: Uint8Array; remaining: number }> {
    const body = await this.request<{ package: string; remaining: number }>(
      "POST",
      `/v1/key-packages/${encodeURIComponent(deviceId)}/claim`,
    );
    return { package: fromBase64(body.package), remaining: body.remaining };
  }

  /**
   * An account's declared devices, as the server reports them.
   *
   * **The result is not trustworthy as-is.** This is the exact place where a malicious server
   * would slip in a device it controls. Always go through `resolveAccount` in `account.ts`, which
   * re-checks every attestation.
   */
  async listAccountDevices(account: string): Promise<{
    identityKey: Uint8Array;
    devices: AttestedDevice[];
    presenceOptout?: boolean;
    contactPolicy?: ContactPolicy;
  }> {
    const body = await this.request<{
      identity_key: string;
      presence_optout?: boolean;
      contact_policy?: string;
      devices: {
        id: string;
        auth_key: string;
        mls_key: string;
        attestation: string;
        revoked_at?: number;
        revocation?: string;
        last_seen?: number;
      }[];
    }>("GET", `/v1/accounts/${encodeURIComponent(account)}/devices`);

    return {
      identityKey: fromBase64(body.identity_key),
      // Served for our own account and for nobody else's, so absent is the ordinary case and
      // means "not ours to know", never "presence is on".
      presenceOptout: body.presence_optout,
      // Narrowed rather than cast. The column is constrained in the schema, so a value outside the
      // three is this server saying something no version of it should — and reading it as a policy
      // would apply a rule nobody wrote.
      contactPolicy: isContactPolicy(body.contact_policy) ? body.contact_policy : undefined,
      devices: body.devices.map((device) => ({
        id: device.id,
        authKey: fromBase64(device.auth_key),
        mlsKey: fromBase64(device.mls_key),
        attestation: fromBase64(device.attestation),
        revokedAt: device.revoked_at,
        revocation: device.revocation ? fromBase64(device.revocation) : undefined,
        lastSeen: device.last_seen,
      })),
    };
  }

  /**
   * Revokes a device, backed by a certificate signed by the account.
   *
   * The certificate is not there for the server — it already knows the account key and could do
   * without. It is there for the **other group members**, who must be able to observe the
   * revocation without taking our word for it, and commit the MLS removal accordingly.
   */
  revokeDevice(
    deviceId: string,
    revocation: Uint8Array,
    revokedAt: number,
  ): Promise<{ revoked: string }> {
    return this.request("POST", `/v1/devices/${encodeURIComponent(deviceId)}/revoke`, {
      revocation: toBase64(revocation),
      revoked_at: revokedAt,
    });
  }

  /**
   * Changes the account's identity key.
   *
   * This is the only real answer to a stolen device: it holds the seed, therefore the whole
   * account. Revoking it does not stop it from attesting a new one; changing the key, on the
   * other hand, makes **every** existing attestation unverifiable at once.
   */
  rotateAccount(
    account: string,
    newIdentityKey: Uint8Array,
    rotation: Uint8Array,
    rotatedAt: number,
  ): Promise<{ account: string }> {
    return this.request("POST", `/v1/accounts/${encodeURIComponent(account)}/rotate`, {
      new_identity_key: toBase64(newIdentityKey),
      rotation: toBase64(rotation),
      rotated_at: rotatedAt,
    });
  }

  /** Current log head, as the server publishes it. */
  async logHead(): Promise<SignedHead> {
    return decodeHead(await this.request<RawHead>("GET", "/v1/log/sth"));
  }

  /** Proof that the key served for this account appears in the log. */
  async logProof(account: string): Promise<{
    identityKey: Uint8Array;
    index: number;
    proof: Uint8Array[];
    head: SignedHead;
  }> {
    const body = await this.request<{
      identity_key: string;
      index: number;
      proof: string[];
      head: RawHead;
    }>("GET", `/v1/log/proof/${encodeURIComponent(account)}`);

    return {
      identityKey: fromBase64(body.identity_key),
      index: body.index,
      proof: body.proof.map(fromBase64),
      head: decodeHead(body.head),
    };
  }

  /** Proof that the current log extends the one of size `from`. */
  async logConsistency(from: number): Promise<{ proof: Uint8Array[]; head: SignedHead }> {
    const body = await this.request<{ proof: string[]; head: RawHead }>(
      "GET",
      `/v1/log/consistency?from=${from}`,
    );

    return { proof: body.proof.map(fromBase64), head: decodeHead(body.head) };
  }

  /** Removes devices from a group's distribution list. */
  removeGroupMembers(groupId: Uint8Array, deviceIds: string[]): Promise<{ removed: number }> {
    return this.request("POST", `/v1/groups/${toHex(groupId)}/members/remove`, {
      device_ids: deviceIds,
    });
  }

  /** Deposits an already sealed pairing packet. The server only ever sees a blob. */
  depositPairing(id: Uint8Array, payload: Uint8Array): Promise<{ deposited: boolean }> {
    return this.request("POST", `/v1/pairings/${toHex(id)}`, { payload: toBase64(payload) });
  }

  /**
   * Collects the pairing packet. **Unsigned**: the new device has no identity the server knows
   * yet — that is precisely what pairing is about to give it.
   *
   * Security therefore rests on encryption, not authentication: without the ephemeral private
   * key, the packet is unreadable. Returns `null` while there is nothing.
   */
  static async claimPairing(id: Uint8Array): Promise<Uint8Array | null> {
    const response = await fetch(`${BASE_URL}/v1/pairings/${toHex(id)}`);
    if (response.status === 404) return null;
    if (!response.ok) throw new ApiError(response.status, await response.text());

    const body = (await response.json()) as { payload: string };
    return fromBase64(body.payload);
  }

  /** Deposits encrypted messages into the account's vault. */
  storeVault(
    groupId: Uint8Array,
    entries: { seq: number; payload: Uint8Array }[],
  ): Promise<{ stored: number }> {
    return this.request("POST", `/v1/vault/${toHex(groupId)}`, {
      entries: entries.map((entry) => ({ seq: entry.seq, payload: toBase64(entry.payload) })),
    });
  }

  /** Collects the account's vault. The server only serves the signing device's own. */
  async fetchVault(
    groupId: Uint8Array,
    after: number,
  ): Promise<{ seq: number; payload: Uint8Array }[]> {
    const rows = await this.request<{ seq: number; payload: string }[]>(
      "GET",
      `/v1/vault/${toHex(groupId)}?after=${after}`,
    );
    return rows.map((row) => ({ seq: row.seq, payload: fromBase64(row.payload) }));
  }

  /**
   * Last activity of the requested accounts.
   *
   * `POST` and not `GET`: the accounts stay out of the URL, hence out of the access logs of any proxy
   * along the way. Same argument that ruled out `EventSource` for the stream — and the body is
   * covered by the signature anyway.
   *
   * The server returns its own clock with the response: freshness is judged by comparing two
   * timestamps, and the browser's can be anything.
   */
  presence(accounts: string[]): Promise<{
    now: number;
    accounts: { account: string; last_seen: number }[];
  }> {
    return this.request("POST", "/v1/presence", { accounts });
  }

  /**
   * The account a handle currently names.
   *
   * # The server is allowed to lie here, and that is survivable
   *
   * This is the directory and nothing more. It can answer late, refuse, or hand back somebody
   * else's id — and none of that produces a *verifying* answer, because the id is a hash of a key
   * that will be inside the credential we are about to check. The worst it achieves is sending us
   * to the wrong account, which is the failure first contact already has and already answers,
   * with an out-of-band fingerprint comparison.
   *
   * That property is the whole reason ids are derived rather than assigned. A server that minted
   * them could tell two people two different things about one name and leave nothing to compare.
   *
   * `410` means the name was given up and is never coming back — a different fact from `404`,
   * which means nobody has taken it yet, and the caller should be able to say which it met.
   *
   * Unsigned: a name has to be resolvable before there is an account to resolve it with.
   */
  static async resolveHandle(handle: string): Promise<string> {
    const response = await fetch(`${BASE_URL}/v1/handles/${encodeURIComponent(handle)}`);

    if (!response.ok) {
      throw new ApiError(
        response.status,
        response.status === 410
          ? "that handle has been retired and cannot be used again"
          : response.status === 404
            ? "nobody goes by that handle"
            : await response.text(),
      );
    }

    const body = (await response.json()) as { account: string };
    return body.account;
  }

  /**
   * Gives this account a new handle, and retires the old one.
   *
   * Nothing else moves: not the account, not its key, not its devices, not their ids, not their
   * attestations, and nothing in any conversation. That is the point of anchoring identity on a
   * key — a handle is a name, and moving a name moves a name.
   *
   * Correspondents do **not** learn the new one from here. They learn it from its owner, inside
   * the encrypted conversation, for the reason `lib/naming.ts` gives about every other
   * self-asserted name: a label read back from the server at render time hands it the power this
   * whole design took away, at the one moment nobody is checking.
   */
  renameAccount(account: string, handle: string): Promise<{ handle: string; retired: string | null }> {
    return this.request("POST", `/v1/accounts/${encodeURIComponent(account)}/handle`, { handle });
  }

  /** Stops or resumes broadcasting presence. Reciprocal: opting out means ceasing to see. */
  setPresenceOptout(optout: boolean): Promise<void> {
    return this.request("POST", "/v1/presence/optout", { optout });
  }

  /**
   * Sets who may start a conversation with this account.
   *
   * The account is never a parameter: the server reads it from the signing device, so this cannot
   * close somebody else's door.
   */
  setContactPolicy(policy: ContactPolicy): Promise<void> {
    return this.request("POST", "/v1/contact-policy", { policy });
  }

  /** Groups where the server declared us a member — how a Welcome gets discovered. */
  listGroups(): Promise<string[]> {
    return this.request("GET", "/v1/groups");
  }

  /**
   * Declares members to the server.
   *
   * `postingKey` is only accepted when the group is **created**: the server ignores it
   * afterwards. Allowing it to change would let one member mute all the others, with no error to
   * explain it.
   */
  addMembers(
    groupId: Uint8Array,
    deviceIds: string[],
    postingKey?: Uint8Array,
  ): Promise<{ added: number }> {
    return this.request("POST", `/v1/groups/${toHex(groupId)}/members`, {
      device_ids: deviceIds,
      ...(postingKey ? { posting_key: toBase64(postingKey) } : {}),
    });
  }

  /**
   * Posts an envelope.
   *
   * With a posting key, the request is **not signed**: it carries a MAC that proves group
   * membership without saying which member is writing. Without a key, we fall back on the device
   * signature — and the server learns who talks to whom, and when.
   */
  postEnvelope(
    groupId: Uint8Array,
    payload: Uint8Array,
    posting?: { key: Uint8Array; mac: PostMac },
  ): Promise<{ seq: number }> {
    const path = `/v1/groups/${toHex(groupId)}/envelopes`;
    const body = { payload: toBase64(payload) };

    if (!posting) return this.request("POST", path, body);

    // The body is serialised **exactly once**: the MAC covers the exact bytes that go out.
    // Re-serialising to send could produce different bytes, and the server would reject
    // everything.
    const encoded = new TextEncoder().encode(JSON.stringify(body));
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const mac = posting.mac(posting.key, groupId, nonce, encoded);

    return this.anonymous(path, encoded, nonce, mac);
  }

  /** Posting without a device signature: the server does not learn who is writing. */
  private async anonymous<T>(
    path: string,
    encoded: Uint8Array,
    nonce: Uint8Array,
    mac: Uint8Array,
  ): Promise<T> {
    const response = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        // No `x-device-id`, no `x-signature`, no timestamp: that is the whole point. Sending
        // them "just in case" would defeat the mechanism without any test noticing.
        "x-group-nonce": toBase64(nonce),
        "x-group-mac": toBase64(mac),
      },
      body: buffer(encoded),
    });

    if (!response.ok) throw new ApiError(response.status, await response.text());
    return response.json() as Promise<T>;
  }

  /**
   * Uploads an **already encrypted** attachment.
   *
   * The body goes out as raw binary: base64 would cost a third of the bandwidth for nothing. The
   * signature covers the body digest, so the scheme is unchanged.
   */
  async uploadAttachment(groupId: Uint8Array, ciphertext: Uint8Array): Promise<{ id: string }> {
    return this.requestRaw("POST", `/v1/groups/${toHex(groupId)}/attachments`, ciphertext, "json");
  }

  async downloadAttachment(groupId: Uint8Array, id: string): Promise<Uint8Array> {
    return this.requestRaw(
      "GET",
      `/v1/groups/${toHex(groupId)}/attachments/${encodeURIComponent(id)}`,
      new Uint8Array(),
      "bytes",
    );
  }

  /**
   * Signs the challenge the server issues when a gateway session opens.
   *
   * # Why a challenge, where HTTP makes do with a timestamp
   *
   * The browser's `WebSocket` API accepts **no header**, and neither does `EventSource`. The
   * handshake therefore cannot be authenticated without putting the signature in the URL, where
   * it would land in the access logs of every intermediary. So the socket opens without an
   * identity, and nothing is served before this signature.
   *
   * Since the nonce comes from the server and is valid only once, there is no replay window here
   * — unlike the sixty seconds HTTP authentication leaves open.
   *
   * The signed message is built by the WebAssembly module — its canonical format lives in the
   * `attest` crate, and rewriting it in TypeScript would duplicate it. It is passed as a
   * parameter rather than imported, for the same reason as [`PostMac`]: this module must not
   * depend on loading the WASM, which is asynchronous and does not happen at the same time.
   */
  signGatewayChallenge(nonce: Uint8Array, format: GatewayChallenge): Promise<string> {
    return this.cipher.sign(format(this.deviceId, nonce));
  }

  /** Posts an ephemeral signal. The server relays it and forgets it: nothing is stored. */
  async postSignal(
    groupId: Uint8Array,
    payload: Uint8Array,
    posting: { key: Uint8Array; mac: PostMac },
  ): Promise<void> {
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const mac = posting.mac(posting.key, groupId, nonce, payload);

    const response = await fetch(`${BASE_URL}/v1/groups/${toHex(groupId)}/signals`, {
      method: "POST",
      headers: {
        "content-type": "application/octet-stream",
        // Same as posting an envelope: no device signature. The server sees that a member is
        // writing, never which one.
        "x-group-nonce": toBase64(nonce),
        "x-group-mac": toBase64(mac),
      },
      body: buffer(payload),
    });

    if (!response.ok) throw new ApiError(response.status, await response.text());
  }

  /**
   * Asks for admission to a call's room.
   *
   * Authenticated by the **group MAC**, like a signal and an anonymous post, and for the same
   * reason: a signed request would tell the server which device is placing a call, in real time.
   * It still learns that a call is being joined and towards which group — see
   * `crates/server/src/call.rs`, which does not pretend otherwise.
   *
   * A 503 means the deployment runs no media server. It is not an error to report: the client
   * hides the call button instead.
   */
  async callAdmission(
    groupId: Uint8Array,
    call: string,
    identity: string,
    posting: { key: Uint8Array; mac: PostMac },
  ): Promise<Admission | undefined> {
    const payload = new TextEncoder().encode(JSON.stringify({ call, identity }));
    const nonce = crypto.getRandomValues(new Uint8Array(16));
    const mac = posting.mac(posting.key, groupId, nonce, payload);

    const response = await fetch(`${BASE_URL}/v1/groups/${toHex(groupId)}/call/token`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-group-nonce": toBase64(nonce),
        "x-group-mac": toBase64(mac),
      },
      body: buffer(payload),
    });

    if (response.status === 503) return undefined;
    if (!response.ok) throw new ApiError(response.status, await response.text());

    return (await response.json()) as Admission;
  }

  /**
   * Reads a page of the mailbox, and where that mailbox now begins.
   *
   * `oldest` is the smallest sequence the server still holds for this group. It exists because
   * the server purges envelopes: without it an empty page would mean either "nothing new" or
   * "everything you had not read is gone", and a client reading it as the first would sit
   * forever on a ratchet that can no longer advance.
   *
   * The comparison is `after < oldest - 1`, and it belongs to the caller rather than here — this
   * class is the wire, and deciding a conversation is broken is a decision about state.
   */
  async fetchEnvelopes(
    groupId: Uint8Array,
    after: number,
  ): Promise<{ oldest: number; envelopes: { seq: number; payload: Uint8Array }[] }> {
    const page = await this.request<{
      oldest: number;
      envelopes: { seq: number; payload: string }[];
    }>("GET", `/v1/groups/${toHex(groupId)}/envelopes?after=${after}`);

    return {
      oldest: page.oldest,
      envelopes: page.envelopes.map((row) => ({
        seq: row.seq,
        payload: fromBase64(row.payload),
      })),
    };
  }
}

/** A signed log head, decoded. */
export interface SignedHead {
  size: number;
  root: Uint8Array;
  timestamp: number;
  signature: Uint8Array;
  /**
   * The log's public key.
   *
   * Served by the very server it is meant to police — an acknowledged, documented stopgap. The
   * client at least refuses to let it change mid-course.
   */
  logKey: Uint8Array;
}

interface RawHead {
  size: number;
  root: string;
  timestamp: number;
  signature: string;
  log_key: string;
}

function decodeHead(raw: RawHead): SignedHead {
  return {
    size: raw.size,
    root: fromBase64(raw.root),
    timestamp: raw.timestamp,
    signature: fromBase64(raw.signature),
    logKey: fromBase64(raw.log_key),
  };
}

/**
 * Posting MAC computation, provided by the WebAssembly module.
 *
 * Passed as a parameter rather than imported: `api.ts` must not depend on loading the WASM
 * module, which is asynchronous and does not happen at the same time.
 */
export type PostMac = (
  key: Uint8Array,
  groupId: Uint8Array,
  nonce: Uint8Array,
  body: Uint8Array,
) => Uint8Array;

/**
 * Builds the message signed when a gateway session opens.
 *
 * Provided by the WebAssembly module, for the same reason as [`PostMac`]: the canonical format
 * lives in the `attest` crate and must exist in only one copy.
 */
export type GatewayChallenge = (deviceId: string, nonce: Uint8Array) => Uint8Array;

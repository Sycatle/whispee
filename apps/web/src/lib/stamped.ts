/**
 * Merging two devices' versions of a keyed preference.
 *
 * # Why a whole module for last-writer-wins
 *
 * Because the naive version loses data, and loses it silently. The signalling settings get away
 * with one timestamp for the whole record: they are three booleans that a person changes one
 * screen at a time, so whichever device wrote last is the one they meant. A *map* is not like
 * that. Block Bob on the laptop and Carol on the phone, and a single stamp over the whole list
 * means one of the two blocks disappears — and the person who blocked them has no way to notice,
 * because nothing failed.
 *
 * So the stamp goes on the entry, not on the collection. Two devices editing different keys never
 * conflict; two devices editing the same key resolve to the later one, which is the only case
 * where somebody has to lose.
 *
 * # Why absence has to be stamped too
 *
 * A removal is a decision, and a decision that is not recorded loses to any earlier decision that
 * was. Unblock Bob on the laptop, and the phone still holds "Bob, blocked at T" — with no record
 * that the unblock happened at T+1, the phone's version wins the next merge and Bob comes back.
 * Silently, again, and in the direction that matters more.
 *
 * The stamp map is therefore the tombstone set: a key present in the stamps and absent from the
 * values *is* the record of a removal. That costs one entry per key ever touched, bounded by the
 * number of distinct accounts an owner has ever blocked or named — which is not a set that grows
 * with time, only with acquaintances.
 *
 * # What this does not attempt
 *
 * Ordering by anything but a self-declared clock. The devices are all our own, so nobody here is
 * hostile, but a clock can still be wrong — `signal-sync.ts` clamps what arrives against the
 * moment of receipt, which bounds the damage a device stuck in the future can do to exactly one
 * merge rather than all of them for ever.
 */

/** When each key was last decided, by whichever device decided it. */
export type Stamps = Record<string, number>;

/** A value-and-stamp map as it travels: `null` is a removal, and is not the same as absent. */
export type StampedPatch<T> = Record<string, { at: number; v: T | null }>;

/**
 * The result of a merge: what the values are now, what the stamps are now, and whether anything
 * moved.
 *
 * `changed` is not a convenience. The announcement is periodic — every device re-sends its
 * settings once per epoch of every conversation — so most merges decide nothing, and persisting
 * on each of them would rewrite the encrypted session for no change, on every epoch of every
 * conversation, for ever.
 */
export interface Merged<T> {
  values: Record<string, T>;
  stamps: Stamps;
  /** A value appeared, changed or went away. */
  changed: boolean;
  /**
   * A stamp moved, whether or not a value did — and this one has to be written down too.
   *
   * Learning a removal we had already applied changes no value and still matters. Take the block
   * on Bob lifted from the phone: a laptop that never held it merges the tombstone, changes
   * nothing visible, and if that stamp is not persisted it is gone at the next start. A third
   * device still holding the block then announces it, wins against a stamp that no longer exists,
   * and Bob is blocked again — by a device that was told he should not be, and forgot.
   */
  stampsMoved: boolean;
}

/**
 * Applies an incoming patch to what we hold.
 *
 * Strictly `>`: a patch carrying a stamp we already have is the periodic re-send of a state we
 * agree on. Taking it would be harmless for the value and expensive for everything downstream —
 * see `Merged.changed`.
 */
export function merge<T>(
  values: Record<string, T>,
  stamps: Stamps,
  patch: StampedPatch<T>,
): Merged<T> {
  const nextValues = { ...values };
  const nextStamps = { ...stamps };
  let changed = false;
  let stampsMoved = false;

  for (const [key, entry] of Object.entries(patch)) {
    const held = stamps[key];
    if (held !== undefined && entry.at <= held) continue;

    nextStamps[key] = entry.at;
    stampsMoved = true;

    if (entry.v === null) {
      // A removal we already have is still worth stamping — the stamp is what makes it stick
      // against an older device that has not heard about it yet.
      changed = changed || key in nextValues;
      delete nextValues[key];
    } else {
      changed = true;
      nextValues[key] = entry.v;
    }
  }

  return { values: nextValues, stamps: nextStamps, changed, stampsMoved };
}

/**
 * Everything we hold, in the shape a patch takes, so that a device that has heard nothing can be
 * caught up by one message.
 *
 * Removals are included — that is the point of walking the stamps rather than the values. A key
 * we stamped and no longer hold is a removal, and it has to travel or the device still holding it
 * will keep re-asserting it at every epoch.
 */
export function patchOf<T>(values: Record<string, T>, stamps: Stamps): StampedPatch<T> {
  const patch: StampedPatch<T> = {};

  for (const [key, at] of Object.entries(stamps)) {
    patch[key] = { at, v: key in values ? values[key] : null };
  }

  return patch;
}

/**
 * Records a local decision about one key, `null` meaning removal.
 *
 * Returns fresh objects rather than mutating: the caller holds these in a session that persists
 * itself, and a mutation that happens to be invisible to the persistence layer is the failure
 * mode this whole file exists to avoid.
 */
export function decide<T>(
  values: Record<string, T>,
  stamps: Stamps,
  key: string,
  value: T | null,
  at: number,
): { values: Record<string, T>; stamps: Stamps } {
  const nextValues = { ...values };
  const nextStamps = { ...stamps, [key]: at };

  if (value === null) delete nextValues[key];
  else nextValues[key] = value;

  return { values: nextValues, stamps: nextStamps };
}

/**
 * Everything the user has chosen and expects to find again.
 *
 * # Why this left `Session`
 *
 * Not because the preferences were coupled to anything — they are not. Because they are the one
 * slice of `StoredSession` whose two halves could be brought together.
 *
 * The mapping to disk lived in `composeStored`; the mapping back lived three hundred lines away
 * in `Session.open`, and nothing related the two. That is a shape where a field added on one side
 * and forgotten on the other reads back as `undefined` at the next start, with no error and no
 * symptom until somebody notices a setting reverted. Here both directions are in one file, next
 * to each other, and a round-trip test can assert they agree — which is a thing neither half
 * could be asked on its own.
 *
 * # The absent-versus-undefined rule, which is the whole subtlety
 *
 * Three of these are optional, and for each of them **absent and `undefined` are different
 * facts**. `skinTone: 0` is somebody choosing the yellow glyph; `skinTone` missing is nobody
 * having been asked. `locale` missing means "follow the system", which is not the same as any
 * particular language. So the write side omits rather than writing `undefined`, and the read side
 * restores the omission rather than inventing a default — and that is what keeps an account that
 * never touched these fields on the exact on-disk shape it had before they existed, which is what
 * makes an unchanged `VERSION` honest rather than merely tolerated.
 *
 * # What it does not solve
 *
 * The other slices. `displayName`, `profiles`, `petnames` and the log head are still written in
 * `composeStored` and read in `Session.open`, still with nothing relating them. This file is what
 * the fix looks like for one slice; it is not the fix.
 */
import { withoutTone } from "./emoji.ts";
import { freshPreferences, type Preferences } from "./session-types.ts";
import type { StoredSession } from "./storage";

/**
 * How many recently-used emoji are kept.
 *
 * Twenty-four is two rows of twelve at the width the picker uses. A longer list is not a longer
 * memory, it is a second grid nobody scrolls.
 */
const RECENT_EMOJI = 24;

export class PreferencesStore {
  private preferences: Preferences = freshPreferences();

  /**
   * May a notification name the conversation?
   *
   * Off unless the user turned it on. Held here rather than in `SignalSettings`, which is about
   * what this device **emits** to others: this discloses nothing to anyone on the network, only to
   * whoever is standing in front of the screen.
   */
  private disclose = false;

  /**
   * Rebuilds the preferences a stored session was carrying.
   *
   * The three `??` and the three conditional reads are not interchangeable. A missing
   * `conversationFlags` is an empty set of flags — there is no third state — so a default is
   * right. A missing `locale` is the absence of a choice, which the type spells `undefined` and
   * which must stay absent rather than become a value — for the reason `session-codec.ts` gives:
   * a property present and holding `undefined` is not an absent one.
   */
  static hydrate(stored: StoredSession | undefined): PreferencesStore {
    const store = new PreferencesStore();
    if (!stored) return store;

    store.disclose = stored.discloseConversationName === true;
    store.preferences = {
      conversations: stored.conversationFlags ?? {},
      searchCoverage: stored.searchCoverage ?? {},
      blocked: stored.blocked ?? [],
      recentEmojis: stored.recentEmojis ?? [],
      ...(stored.locale === undefined ? {} : { locale: stored.locale }),
      ...(stored.contactPolicy === undefined ? {} : { contactPolicy: stored.contactPolicy }),
      ...(stored.skinTone === undefined ? {} : { skinTone: stored.skinTone }),
    };

    return store;
  }

  /** What this contributes to the stored session. The mirror of `hydrate`, and tested against it. */
  snapshot(): Partial<StoredSession> {
    return {
      discloseConversationName: this.disclose,
      conversationFlags: this.preferences.conversations,
      searchCoverage: this.preferences.searchCoverage,
      blocked: this.preferences.blocked,
      recentEmojis: this.preferences.recentEmojis,
      ...(this.preferences.locale === undefined ? {} : { locale: this.preferences.locale }),
      ...(this.preferences.contactPolicy === undefined
        ? {}
        : { contactPolicy: this.preferences.contactPolicy }),
      ...(this.preferences.skinTone === undefined ? {} : { skinTone: this.preferences.skinTone }),
    };
  }

  /**
   * The live value.
   *
   * Handed out rather than copied, and mutable, which is unusual and deliberate: the alternative
   * is a getter and a setter per preference, and a merge conflict for every feature that adds one.
   * `Preferences` explains the trade in full. Read it freely; to change it, go through `update`.
   */
  get value(): Preferences {
    return this.preferences;
  }

  get discloseConversationName(): boolean {
    return this.disclose;
  }

  setDisclose(value: boolean): void {
    this.disclose = value;
  }

  /**
   * Applies a change.
   *
   * Takes a mutator rather than a whole object so that two callers changing different preferences
   * cannot overwrite each other by handing back a stale copy — the mutation happens on the current
   * value, at the moment it is applied.
   *
   * **Does not write.** Nothing in this file reaches a disk: the caller decides when the session
   * is persisted, because that decision is ordered against the MLS state and this file knows
   * nothing about that.
   */
  update(change: (preferences: Preferences) => void): void {
    change(this.preferences);
  }

  /**
   * Records that an emoji was just used, so the picker can offer it first next time.
   *
   * The tone is stripped before storing: what is remembered is the emoji, and the tone is a
   * separate preference applied on the way out. Without that, choosing a tone once fills the list
   * with five variants of the same thumb and pushes everything else off it.
   *
   * Returns whether anything changed, so a caller need not persist for a glyph that was nothing
   * but a tone modifier.
   */
  noteEmoji(emoji: string): boolean {
    const base = withoutTone(emoji);
    if (!base) return false;

    this.preferences.recentEmojis = [
      base,
      ...this.preferences.recentEmojis.filter((known) => known !== base),
    ].slice(0, RECENT_EMOJI);

    return true;
  }
}

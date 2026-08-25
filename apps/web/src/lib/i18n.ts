/**
 * Strings the interface says, in the reader's language when there is one.
 *
 * # What this is not
 *
 * Not a localisation of the application. Every other string in this interface is English written
 * where it is used, and this module does not change that — it is a floor for the strings that
 * reach it, starting with the membership notices in the thread, and a place for the rest to move
 * to one key at a time rather than in one unreviewable sweep.
 *
 * That matters more here than in most projects: a good part of this interface is security prose —
 * what removing somebody costs, what a new member can read, what a fingerprint proves. Those
 * paragraphs commit as much as the code does, and translating them is a piece of work with its
 * own review, not a mechanical pass. Keeping the door open without walking everything through it
 * is the honest position.
 *
 * # No dependency, and why that is not laziness
 *
 * A translation library brings a parser for plural rules, an interpolation syntax, a loader and a
 * React binding. What is needed here is a lookup and a substitution. `Intl.PluralRules` is in the
 * platform for the day plurals are needed, and until they are, adding a package to this client
 * would put another dependency on the page that runs the user's cryptography — the trade
 * `docs/THREAT-MODEL.md` already regrets making once.
 *
 * # Whole sentences, named holes
 *
 * A phrase is stored as one string with `{name}` placeholders, never assembled from pieces. The
 * version this replaced built `` `${actor} added ${subject}` ``, which reads correctly in English
 * and cannot be reordered — and word order is exactly what changes between languages. A
 * translator receives the sentence, not the verb.
 *
 * # What it does not solve
 *
 * No plurals, no gendered agreement, and no date or number formatting — `Intl` covers the last
 * two when something needs them. The catalogue is compiled in rather than fetched, so adding a
 * language is a deploy. And a key missing from a catalogue falls back to English rather than
 * throwing: a sentence in the wrong language is a poor result, and a blank line where a sentence
 * belongs is a worse one.
 */

/** Every phrase this module knows. Adding one here is what makes it translatable. */
export interface Catalogue {
  "membership.joined": string;
  "membership.removed": string;
  "membership.left": string;
  "membership.preview.joined": string;
  "membership.preview.removed": string;
  "membership.preview.left": string;
  "call.ended": string;
  "call.missed": string;
  "call.ringing": string;
  "call.preview.ended": string;
  "call.preview.missed": string;
  "expiry.set": string;
  "expiry.off": string;
  "expiry.preview.set": string;
  "expiry.preview.off": string;
}

export type Phrase = keyof Catalogue;

/**
 * The source language, and the fallback.
 *
 * English is where a phrase is written first, so it is the only catalogue guaranteed complete —
 * which is what makes it the fallback rather than a choice about who this application is for.
 */
const en: Catalogue = {
  "membership.joined": "{actor} added {subject}",
  "membership.removed": "{actor} removed {subject}",
  "membership.left": "{subject} left",
  "membership.preview.joined": "{subject} joined",
  "membership.preview.removed": "{subject} was removed",
  "membership.preview.left": "{subject} left",
  // `{duration}` is already formatted — see `spokenDuration`. Interpolating a number here would
  // put the unit outside the catalogue, which is the half a translator most needs to move.
  "call.ended": "Call · {duration}",
  "call.missed": "Missed call",
  "call.ringing": "{actor} called",
  "call.preview.ended": "Call · {duration}",
  "call.preview.missed": "Missed call",
  // `{delay}` arrives formatted — see `spokenLifetime`. Interpolating a number would leave the
  // unit outside the catalogue, which is the half a translator most needs to move.
  "expiry.set": "{actor} set messages to disappear after {delay}",
  "expiry.off": "{actor} turned off disappearing messages",
  "expiry.preview.set": "Messages disappear after {delay}",
  "expiry.preview.off": "Disappearing messages turned off",
};

const fr: Partial<Catalogue> = {
  "membership.joined": "{actor} a ajouté {subject}",
  "membership.removed": "{actor} a retiré {subject}",
  "membership.left": "{subject} a quitté la conversation",
  "membership.preview.joined": "{subject} a rejoint",
  "membership.preview.removed": "{subject} a été retiré",
  "membership.preview.left": "{subject} est parti",
  "call.ended": "Appel · {duration}",
  "call.missed": "Appel manqué",
  "call.ringing": "{actor} a appelé",
  "call.preview.ended": "Appel · {duration}",
  "call.preview.missed": "Appel manqué",
  "expiry.set": "{actor} fait disparaître les messages après {delay}",
  "expiry.off": "{actor} a désactivé les messages éphémères",
  "expiry.preview.set": "Les messages disparaissent après {delay}",
  "expiry.preview.off": "Messages éphémères désactivés",
};

const CATALOGUES: Record<string, Partial<Catalogue>> = { en, fr };

/**
 * The language to speak, from the browser's list.
 *
 * Matched on the primary subtag alone: somebody asking for `fr-CA` is served `fr` rather than
 * English, which is the right answer even when the regional catalogue does not exist. The list is
 * read in order, so a reader who prefers Breton and accepts French gets French rather than the
 * fallback.
 *
 * Exported for the tests, which cannot ask a browser anything.
 */
export function pick(preferred: readonly string[]): string {
  for (const tag of preferred) {
    const primary = tag.toLowerCase().split("-")[0];
    if (primary in CATALOGUES) return primary;
  }
  return "en";
}

/**
 * A phrase, with its holes filled.
 *
 * A placeholder with no matching value is left as it stands. It means the catalogue and the call
 * site disagree, and showing `{subject}` in the interface is how that gets noticed and fixed —
 * whereas an empty space reads as a sentence somebody wrote badly.
 */
export function say(
  phrase: Phrase,
  values: Record<string, string> = {},
  preferred: readonly string[] = navigator.languages,
): string {
  const language = pick(preferred);
  const template = CATALOGUES[language]?.[phrase] ?? en[phrase];

  return template.replace(/\{(\w+)\}/g, (whole, name: string) => values[name] ?? whole);
}

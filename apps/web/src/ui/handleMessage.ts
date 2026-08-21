import type { HandleError } from "@/lib/handle";

/**
 * The display boundary for the handle format: one token in, one English sentence out.
 *
 * `lib/handle.ts` returns `"too-short"` rather than a phrase, deliberately — it is a pure module
 * and a pure module that returns prose has decided the product is English on behalf of every
 * caller. This file is where that decision is allowed to be made, and it is the file the i18n
 * work replaces with a lookup. Nothing else about the format lives here.
 *
 * It sits in `ui/` and not in `lib/` for the same reason `Field.tsx` does: it is words on a
 * screen. Both call sites — the onboarding form and the new-conversation form — go through it,
 * so the two never end up telling a user two different things about the same rule.
 */
export function handleMessage(problem: HandleError): string {
  switch (problem) {
    case "too-short":
      return "A handle needs at least 3 characters.";
    case "too-long":
      return "A handle cannot go past 32 characters.";
    // Naming the whole alphabet rather than the offending character: the character may be
    // invisible — a zero-width joiner, a bidi override — and pointing at something that does not
    // render is worse than saying what is allowed.
    case "bad-characters":
      return "Only lowercase letters, digits and underscores. No spaces, no accents, no capitals.";
  }
}

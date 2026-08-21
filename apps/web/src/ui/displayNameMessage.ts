import { MAX_CODE_POINTS, type DisplayNameError } from "@/lib/display-name";

/**
 * The display boundary for the display-name rules: one token in, one English sentence out.
 *
 * The twin of `handleMessage.ts`, and it exists for the same reason and now for a second one.
 * `lib/display-name.ts` returns `"too-long"` rather than a phrase because a pure module that
 * returns prose has decided the product is English on behalf of every caller. And there are two
 * screens asking for a name now — the settings panel and the first screen of the product — so
 * without one file between them, a rule broken in the same way is explained two different ways
 * depending on when it is broken.
 */
export function displayNameMessage(problem: DisplayNameError | null): string | undefined {
  switch (problem) {
    case "too-long":
      return `A display name is at most ${MAX_CODE_POINTS} characters.`;
    case "empty":
      return "A display name needs at least one visible character.";
    case null:
      return undefined;
  }
}

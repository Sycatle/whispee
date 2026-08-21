/**
 * Types for the one zxcvbn file `password.ts` reaches into by path.
 *
 * The English package ships its declarations for its entry point only, and its entry point drags
 * the four word lists — 1.2 MB — in with it. Only the feedback strings are wanted, so the file
 * holding them is imported directly, and it comes with no types of its own.
 *
 * Written here rather than silenced at the import: an `any` would let a later release change the
 * shape of those strings without anything noticing.
 */
declare module "@zxcvbn-ts/language-en/dist/translations.mjs" {
  import type { TranslationKeys } from "@zxcvbn-ts/core";

  const translations: TranslationKeys;
  export default translations;
}

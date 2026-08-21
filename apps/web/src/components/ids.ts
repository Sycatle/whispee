/**
 * Ids two components have to agree on, in a module that imports neither.
 *
 * `COMPOSER_ID` used to live in `Conversation.tsx`, which is where the field is. That was fine
 * while the shell's skip link was the only thing aiming at it — the shell imports the
 * conversation anyway. It stopped being fine when the thread needed it too: `Conversation`
 * renders `Messages`, so `Messages` importing back from it closes a cycle. ESM tolerates a cycle
 * over a string constant right up until somebody adds a second export to the same file and it
 * evaluates as `undefined`, with no error anywhere.
 */

/** The id the skip link aims at, so tabbing can jump the rail and the whole message list. */
export const COMPOSER_ID = "conversation-composer";
